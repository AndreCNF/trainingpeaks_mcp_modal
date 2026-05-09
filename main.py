"""TrainingPeaks MCP server hosted on Modal.

Mounts the upstream `tp_mcp` low-level `Server` (which already has all 58
tools registered via `@server.list_tools()` / `@server.call_tool()`) over
streamable HTTP, behind a static bearer token + OAuth 2.0 + PKCE wrapper
so it works from both Claude Desktop and Claude.ai (web/mobile).

Auth path: the long-lived `Production_tpAuth` cookie is sourced from a Modal
Volume (preferred) or a bootstrap env var. Upstream's `_ensure_access_token`
re-mints the 1h OAuth token in-memory on demand. A 50-min cron exercises the
same path so cookie expiry surfaces in Modal logs before a user hits it.
"""

from __future__ import annotations

import subprocess

import modal


def _git_info() -> tuple[str, str]:
    """Capture short HEAD sha and dirty flag at deploy time and bake them
    into the image as env vars (so the running container can log them)."""
    try:
        sha = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
        dirty = (
            "1"
            if subprocess.check_output(
                ["git", "status", "--porcelain"], text=True, stderr=subprocess.DEVNULL
            ).strip()
            else "0"
        )
        return sha, dirty
    except Exception:
        return "unknown", "0"


_git_sha, _git_dirty = _git_info()

VOLUME_PATH = "/data"
COOKIE_FILE = f"{VOLUME_PATH}/tp_auth_cookie.txt"

image = (
    modal.Image.debian_slim(python_version="3.13")
    .apt_install("git")
    .uv_pip_install(
        "tp-mcp@git+https://github.com/JamsusMaximus/trainingpeaks-mcp.git@06bdfe347759f458e577c59488455b6f52521b23"
    )
    .uv_pip_install(
        "fastapi>=0.115",
        "fastmcp>=2.14.0,<3",
        "mcp>=1.0.0",
        "modal>=1.4.2,<2",
    )
    .env({"GIT_COMMIT": _git_sha, "GIT_DIRTY": _git_dirty, "TP_COOKIE_FILE": COOKIE_FILE})
    .add_local_python_source("auth_shim", "oauth")
)

app = modal.App(
    name="trainingpeaks_mcp",
    image=image,
    secrets=[modal.Secret.from_name("tp-mcp-secrets")],
)

# Volume holding the long-lived `Production_tpAuth` cookie. `endpoint()` and
# the cron prefer it over the bootstrap `TP_AUTH_COOKIE` env var so cookie
# rotation via `/refresh-cookie` doesn't require a redeploy.
cookie_volume = modal.Volume.from_name("tp-cookie-vol", create_if_missing=True)


with image.imports():
    import contextlib
    import hmac
    import os

    from fastapi import FastAPI, HTTPException, Request  # ty:ignore[unresolved-import]
    from mcp.server.streamable_http_manager import (  # ty:ignore[unresolved-import]
        StreamableHTTPSessionManager,
    )

    from auth_shim import (
        install_cookie_shim,
        invalidate_token_cache,
        read_cookie,
        write_cookie_to_volume,
    )
    from oauth import mount_oauth_routes


@app.function(
    volumes={VOLUME_PATH: cookie_volume},
    min_containers=0,
    timeout=300,
)
@modal.asgi_app()
def endpoint():
    """ASGI web endpoint for the TrainingPeaks MCP server."""
    cookie_volume.reload()

    bearer_token = os.environ.get("MCP_BEARER_TOKEN")
    if not bearer_token:
        raise RuntimeError(
            "MCP_BEARER_TOKEN is not set. Run: "
            "modal secret create tp-mcp-secrets MCP_BEARER_TOKEN=<your-secret> ..."
        )

    if not read_cookie():
        raise RuntimeError(
            "No TrainingPeaks cookie available — neither the volume file nor "
            "TP_AUTH_COOKIE is set. Bootstrap with: "
            "modal secret create tp-mcp-secrets TP_AUTH_COOKIE=<Production_tpAuth value> ..."
        )

    # Patch upstream credential storage BEFORE importing tp_mcp.server so the
    # registered tool handlers see our cookie when they run.
    install_cookie_shim()
    from tp_mcp.server import server as tp_server  # noqa: PLC0415 — patch order matters

    cookie_source = "volume" if os.path.exists(COOKIE_FILE) else "env"
    print(
        f"[startup] commit={os.environ.get('GIT_COMMIT', '?')} "
        f"dirty={os.environ.get('GIT_DIRTY', '?')} "
        f"cookie={cookie_source}"
    )

    # Streamable HTTP transport over the upstream low-level Server. Stateless
    # so each request stands alone — fits Modal's container model.
    session_manager = StreamableHTTPSessionManager(
        app=tp_server,
        event_store=None,
        json_response=False,
        stateless=True,
    )

    base_url_holder: dict[str, str] = {}

    def _base_url() -> str:
        if "url" not in base_url_holder:
            base_url_holder["url"] = endpoint.get_web_url()
        return base_url_holder["url"]

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        async with session_manager.run():
            yield

    fastapi_app = FastAPI(lifespan=lifespan)

    # OAuth routes for Claude.ai's custom-connector UI. MUST be registered
    # before the /mcp mount below.
    mount_oauth_routes(fastapi_app, bearer_token=bearer_token, base_url=_base_url)

    @fastapi_app.post("/refresh-cookie")
    async def refresh_cookie(request: Request):
        """Rotate the TrainingPeaks cookie without a redeploy.

        Authenticated with the static MCP bearer token. The new cookie is
        written to the volume (which beats the env var on subsequent reads),
        committed, and the in-memory access-token cache is invalidated so
        the next tool call re-mints from the new cookie.
        """
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or not hmac.compare_digest(
            auth[7:], bearer_token
        ):
            raise HTTPException(status_code=401, detail="invalid bearer")
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="invalid json body")
        cookie = (body.get("cookie") or "").strip() if isinstance(body, dict) else ""
        if not cookie:
            raise HTTPException(status_code=400, detail="missing cookie")
        path = write_cookie_to_volume(cookie)
        cookie_volume.commit()
        invalidate_token_cache()
        print(f"[refresh-cookie] wrote new cookie to {path}, invalidated token cache")
        return {"ok": True}

    # Bearer-protected ASGI mount for the MCP transport. We intercept HTTP
    # requests at the ASGI layer (rather than via FastAPI middleware) so we
    # can return a clean 401 without touching the session manager.
    async def protected_mcp(scope, receive, send):
        if scope["type"] != "http":
            await session_manager.handle_request(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        provided = headers.get(b"authorization", b"").decode()
        if not provided.startswith("Bearer ") or not hmac.compare_digest(
            provided[7:], bearer_token
        ):
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"www-authenticate", b'Bearer realm="trainingpeaks-mcp"'),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": b'{"error":"unauthorized"}'})
            return
        await session_manager.handle_request(scope, receive, send)

    fastapi_app.mount("/mcp", protected_mcp)
    return fastapi_app


@app.function(
    volumes={VOLUME_PATH: cookie_volume},
    schedule=modal.Cron("*/30 * * * *"),
    timeout=120,
)
def refresh_token_health():
    """Defensive health-check: re-mint the OAuth token from the cookie every
    30 min so cookie expiry / TP API breakage shows up in Modal logs before
    a user hits it. Lazy in-memory refresh in `endpoint()` is the primary
    refresh path; this is a safety net. (30 min is the cleanest cron divisor
    for even spacing; the TP token TTL is ~60 min so this gives 2x coverage.)
    """
    cookie_volume.reload()

    if not read_cookie():
        raise RuntimeError(
            "[refresh_token_health] no cookie available — "
            "POST a fresh cookie to /refresh-cookie or update TP_AUTH_COOKIE."
        )

    install_cookie_shim()
    invalidate_token_cache()  # force a real mint, not a cache hit

    # Use upstream's auth validator — it exercises the full cookie → token
    # mint path and surfaces precise failure modes (expired cookie, network,
    # API change). validate_auth_sync takes the cookie value directly.
    from tp_mcp.auth import validate_auth_sync  # noqa: PLC0415

    cookie = read_cookie()
    assert cookie  # guarded above
    result = validate_auth_sync(cookie)
    print(f"[refresh_token_health] {result!r}")


@app.function(volumes={VOLUME_PATH: cookie_volume})
async def test_tool(tool_name: str = "tp_auth_status", arguments_json: str = ""):
    """Smoke-test the deployed MCP endpoint by calling one tool with the
    static bearer token. Useful after deploy to confirm the full stack works.

    Pass tool arguments as a JSON string (Modal CLI can't parse `dict | None`):
        modal run main.py::test_tool --tool-name tp_get_workouts \\
            --arguments-json '{"start":"2026-01-01","end":"2026-01-07"}'
    """
    import json  # noqa: PLC0415

    from fastmcp import Client  # noqa: PLC0415
    from fastmcp.client.transports import StreamableHttpTransport  # noqa: PLC0415

    bearer_token = os.environ["MCP_BEARER_TOKEN"]
    transport = StreamableHttpTransport(
        url=f"{endpoint.get_web_url()}/mcp/",
        headers={"Authorization": f"Bearer {bearer_token}"},
    )
    client = Client(transport)
    args = json.loads(arguments_json) if arguments_json else {}
    async with client:
        tools = await client.list_tools()
        names = [t.name for t in tools]
        print(f"[test_tool] {len(names)} tools available")
        if tool_name not in names:
            raise RuntimeError(f"tool {tool_name!r} not found; have: {names[:5]}…")
        result = await client.call_tool(tool_name, args)
        print(f"[test_tool] {tool_name}({args}) → {result.data!r}")
