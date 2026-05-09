"""Inject the TrainingPeaks `Production_tpAuth` cookie into upstream `tp_mcp`.

`tp_mcp` reads the cookie from system keyring (via `tp_mcp.auth.storage`).
That doesn't exist in a Modal container, so we monkey-patch the storage
function to pull the cookie from a Modal Volume (preferred) or an env var
(bootstrap fallback).

Patch order matters: `install_cookie_shim()` MUST run before `tp_mcp.server`
or `tp_mcp.client.http` are imported, otherwise they will have already
captured a reference to the unpatched `get_credential`.
"""

from __future__ import annotations

import importlib
import os
from typing import Any


COOKIE_FILE_ENV = "TP_COOKIE_FILE"
COOKIE_BOOTSTRAP_ENV = "TP_AUTH_COOKIE"


def read_cookie() -> str | None:
    """Volume file first (writable, survives `/refresh-cookie`), env var as bootstrap."""
    path = os.environ.get(COOKIE_FILE_ENV)
    if path and os.path.exists(path):
        v = open(path).read().strip()
        if v:
            return v
    return os.environ.get(COOKIE_BOOTSTRAP_ENV) or None


def write_cookie_to_volume(cookie: str) -> str:
    """Persist a new cookie value to the volume file. Returns the path written."""
    path = os.environ[COOKIE_FILE_ENV]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(cookie.strip())
    return path


def install_cookie_shim() -> None:
    """Patch `tp_mcp.auth.storage.get_credential` (and its re-exports) before
    any other tp_mcp module captures a reference to it.

    Upstream's `get_credential()` returns a `CredentialResult` dataclass
    (`success`, `message`, `cookie`), not a raw string — the shim mirrors
    that contract so callers like `tp_auth_status` keep working.
    """
    from tp_mcp.auth.keyring import CredentialResult

    def _shim_get_credential() -> CredentialResult:
        cookie = read_cookie()
        if cookie:
            return CredentialResult(
                success=True,
                message="cookie loaded from modal volume/env",
                cookie=cookie,
            )
        return CredentialResult(
            success=False,
            message="no cookie available — POST one to /refresh-cookie",
            cookie=None,
        )

    # Patch the actual definition site first.
    storage = importlib.import_module("tp_mcp.auth.storage")
    storage.get_credential = _shim_get_credential  # type: ignore[attr-defined]

    # Patch the package re-export so `from tp_mcp.auth import get_credential`
    # also returns the shim. This handles modules that grab the symbol off
    # `tp_mcp.auth` directly rather than `tp_mcp.auth.storage`.
    auth_pkg = importlib.import_module("tp_mcp.auth")
    auth_pkg.get_credential = _shim_get_credential  # type: ignore[attr-defined]


def invalidate_token_cache() -> None:
    """Clear the in-memory OAuth access token so the next request re-mints
    using the current cookie. Tolerant to upstream attribute renames — clears
    every plausible cache attribute on `tp_mcp.client.http`.
    """
    try:
        http = importlib.import_module("tp_mcp.client.http")
    except ModuleNotFoundError:
        return
    for attr in (
        "_ACCESS_TOKEN",
        "_TOKEN_EXPIRES_AT",
        "_access_token",
        "_token_expires_at",
        "_cached_token",
        "_cached_token_expires_at",
    ):
        if hasattr(http, attr):
            setattr(http, attr, None)
    # Some clients keep state on a singleton client instance.
    for attr in ("_client", "_CLIENT", "client"):
        obj: Any = getattr(http, attr, None)
        if obj is None:
            continue
        for token_attr in ("access_token", "_access_token", "token", "_token"):
            if hasattr(obj, token_attr):
                try:
                    setattr(obj, token_attr, None)
                except AttributeError:
                    pass
