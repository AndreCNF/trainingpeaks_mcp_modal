"""OAuth 2.0 Authorization Code + PKCE wrapper for Claude.ai's custom-connector UI.

Claude.ai only drives Authorization Code with PKCE, so we wrap the static
MCP_BEARER_TOKEN in that flow:
  /authorize  — auto-approves (the user's proof of authorization is the
                client_secret they pasted into the UI; nothing to ask them
                in a browser) and 302s back with a signed code.
  /token      — verifies client_secret + PKCE + code signature, then returns
                MCP_BEARER_TOKEN as the access token.

Codes are HMAC-signed (key = MCP_BEARER_TOKEN) and self-contained, so the
flow stays stateless across Modal containers — no shared store needed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Callable
from urllib.parse import urlencode

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse


CLAUDE_CALLBACKS = {
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
}
CODE_TTL_SECONDS = 300


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign_code(payload: dict, key: str) -> str:
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(key.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def _verify_code(code: str, key: str) -> dict | None:
    try:
        body, sig = code.rsplit(".", 1)
    except ValueError:
        return None
    expected = hmac.new(key.encode(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        payload = json.loads(_b64url_decode(body))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("exp", 0) < int(time.time()):
        return None
    return payload


def require_bearer(request: Request, bearer_token: str) -> None:
    """Raise 401 if the request lacks a valid Bearer token."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer")
    if not hmac.compare_digest(auth[7:], bearer_token):
        raise HTTPException(status_code=401, detail="invalid bearer")


def mount_oauth_routes(
    api: FastAPI,
    bearer_token: str,
    base_url: Callable[[], str],
    resource_path: str = "/mcp/",
) -> None:
    """Register /authorize, /token, and the two .well-known discovery endpoints.

    `base_url` is a zero-arg callable so the URL can be resolved lazily inside
    the request handler (Modal only knows the deployed URL at runtime).
    """

    @api.get("/.well-known/oauth-authorization-server")
    async def oauth_metadata():
        b = base_url()
        return JSONResponse(
            {
                "issuer": b,
                "authorization_endpoint": f"{b}/authorize",
                "token_endpoint": f"{b}/token",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["client_secret_post"],
            }
        )

    @api.get("/.well-known/oauth-protected-resource/mcp")
    async def resource_metadata():
        b = base_url()
        return JSONResponse(
            {
                "resource": f"{b}{resource_path}",
                "authorization_servers": [b],
                "bearer_methods_supported": ["header"],
            }
        )

    @api.get("/authorize")
    async def authorize(
        response_type: str,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str,
        state: str | None = None,
    ):
        if response_type != "code":
            return JSONResponse({"error": "unsupported_response_type"}, status_code=400)
        if redirect_uri not in CLAUDE_CALLBACKS:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "redirect_uri not allowed"},
                status_code=400,
            )
        if code_challenge_method != "S256":
            return JSONResponse(
                {"error": "invalid_request", "error_description": "S256 PKCE required"},
                status_code=400,
            )

        code = _sign_code(
            {
                "cid": client_id,
                "ru": redirect_uri,
                "cc": code_challenge,
                "exp": int(time.time()) + CODE_TTL_SECONDS,
                "n": secrets.token_hex(8),
            },
            key=bearer_token,
        )
        params = {"code": code}
        if state:
            params["state"] = state
        return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=302)

    @api.post("/token")
    async def token(request: Request):
        form = await request.form()
        if form.get("grant_type") != "authorization_code":
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

        client_secret = form.get("client_secret") or ""
        if not hmac.compare_digest(client_secret, bearer_token):
            return JSONResponse({"error": "invalid_client"}, status_code=401)

        payload = _verify_code(form.get("code") or "", key=bearer_token)
        if payload is None:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        if payload.get("cid") != form.get("client_id") or payload.get("ru") != form.get(
            "redirect_uri"
        ):
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        code_verifier = form.get("code_verifier") or ""
        challenge = _b64url(hashlib.sha256(code_verifier.encode()).digest())
        if not hmac.compare_digest(challenge, payload.get("cc", "")):
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        return JSONResponse(
            {
                "access_token": bearer_token,
                "token_type": "bearer",
                "expires_in": 3600,
            }
        )
