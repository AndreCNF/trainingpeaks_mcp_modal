# trainingpeaks_mcp_modal

TrainingPeaks MCP server hosted on Modal. Wraps the upstream
[JamsusMaximus/trainingpeaks-mcp](https://github.com/JamsusMaximus/trainingpeaks-mcp)
(58 tools) so it's reachable from Claude Desktop and Claude.ai (web/mobile)
over HTTP with OAuth 2.0 + PKCE.

## How auth works

TrainingPeaks tokens are minted from a long-lived browser cookie
(`Production_tpAuth`, weeks-long) at
`GET https://tpapi.trainingpeaks.com/users/v3/token`. Upstream re-mints the
1h OAuth token in-memory on demand. We:

1. Bootstrap with the cookie via a Modal Secret on first deploy.
2. Persist subsequent rotations to a Modal Volume via an authenticated
   `/refresh-cookie` HTTP endpoint — no `modal` CLI needed for routine
   rotation.
3. Run a 50-min cron (`refresh_token_health`) that exercises the cookie →
   token mint path so cookie expiry surfaces in Modal logs.

## First-time setup

```bash
# Generate one long random secret — this serves as both the MCP transport
# bearer and the OAuth client_secret that Claude.ai's connector form expects.
python3 -c "import secrets; print(secrets.token_urlsafe(32))"   # MCP_BEARER_TOKEN

# Grab the Production_tpAuth cookie from your browser:
#   - Sign in to https://www.trainingpeaks.com
#   - DevTools → Application → Cookies → trainingpeaks.com → Production_tpAuth
#   - Copy the Value

modal secret create tp-mcp-secrets \
  MCP_BEARER_TOKEN=<paste-secret> \
  TP_AUTH_COOKIE=<paste-cookie>

uv run python deploy.py   # Volume is auto-created by create_if_missing=True
```

The Modal Volume `tp-cookie-vol` is created automatically on first deploy
(`Volume.from_name(..., create_if_missing=True)`); no `modal volume create`
step is needed.

## Rotating the cookie

Cookies last weeks. When yours expires, grab a fresh one from your browser
and `POST` it to the deployed server — no redeploy, no `modal` CLI:

```bash
curl -X POST \
  -H "Authorization: Bearer $MCP_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cookie":"<new Production_tpAuth value>"}' \
  https://<modal-username>--trainingpeaks-mcp-endpoint.modal.run/refresh-cookie
```

The server writes the new cookie to the Modal Volume (which beats the
bootstrap env var on subsequent reads) and invalidates the in-memory access
token so the next tool call re-mints from the new cookie.

## Connecting Claude

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or the equivalent on your platform:

```json
{
  "mcpServers": {
    "trainingpeaks": {
      "transport": {
        "type": "http",
        "url": "https://<modal-username>--trainingpeaks-mcp-endpoint.modal.run/mcp/"
      },
      "headers": {
        "Authorization": "Bearer <MCP_BEARER_TOKEN>"
      }
    }
  }
}
```

Restart Claude Desktop. The 58 tools should appear under the trainingpeaks
namespace.

### Claude.ai (web / mobile)

Add a custom connector:

1. Settings → Connectors → Add custom connector.
2. URL: `https://<modal-username>--trainingpeaks-mcp-endpoint.modal.run/mcp/`
3. Client secret: paste your `MCP_BEARER_TOKEN`. (The OAuth wrapper validates
   the form's `client_secret` against this value, then returns the same
   string as the `access_token` — one secret, two roles.)
4. Approve. Claude.ai walks the OAuth Authorization Code + PKCE flow against
   `/authorize` and `/token`.

## Verifying

```bash
# List tools (expect 58):
curl -H "Authorization: Bearer $MCP_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  https://<modal-username>--trainingpeaks-mcp-endpoint.modal.run/mcp/

# Smoke-test a single tool against the deployed server:
modal run main.py::test_tool --tool-name tp_auth_status

# Trigger the health-check cron manually:
modal run main.py::refresh_token_health
```

## File layout

| File | Purpose |
|---|---|
| `main.py` | Modal app, image, secrets, volume; FastAPI ASGI; mounts the upstream low-level MCP `Server` via `StreamableHTTPSessionManager`; `/refresh-cookie`; `refresh_token_health` cron. |
| `auth_shim.py` | Reads the cookie from volume → env; monkey-patches `tp_mcp.auth.storage.get_credential`; clears the in-memory token cache. |
| `oauth.py` | OAuth 2.0 + PKCE wrapper for Claude.ai's custom-connector UI (stateless HMAC-signed codes, no server-side session). |
| `pyproject.toml` | uv-managed deps; vendors `trainingpeaks-mcp` from Git. |
| `deploy.py` | Pre-flight git checks (clean tree, on `main`, up-to-date) before `modal deploy main.py`. |

## Architecture notes

- **No FastMCP wrapping of the 58 tools.** Upstream `tp_mcp` registers tools
  on a low-level `mcp.server.Server` with full JSON schemas. We mount that
  same `server` directly via `StreamableHTTPSessionManager`, so all 58 tools
  ship with their original schemas — no per-tool re-registration.
- **Patch order matters.** `install_cookie_shim()` runs before `tp_mcp.server`
  is imported, so registered handlers see our cookie when they invoke
  upstream's HTTP client.
- **Bearer auth at the ASGI layer.** A small wrapper around the MCP session
  manager checks `Authorization: Bearer ...` and returns 401 cleanly,
  without touching the session manager's lifespan.
- **Pin upstream once it's green.** `pyproject.toml` currently points at
  `main`; pin to a SHA after first successful deploy to insulate against
  upstream renames of `_TOOL_HANDLERS`, `TOOLS`, or `get_credential`.

## Cookie expiry diagnostics

If TP returns a 401 from `/users/v3/token`, the most common cause is an
expired `Production_tpAuth` cookie. The cron logs (`refresh_token_health`)
will show the failure within ≤50 min. To recover: extract a fresh cookie
from your browser and POST it to `/refresh-cookie` (above).
