"""Toy OIDC provider for local QIIP testing.

Speaks just enough OpenID Connect for the qiip internal_oidc auth plugin:
discovery, authorization-code flow with a password login form, RS256-signed
ID tokens, JWKS, and a userinfo endpoint. Test-only: plaintext password file,
in-memory codes/tokens, and (by default) a self-signed TLS terminator in front
via nginx at https://your-qiip-host.localdomain/oidc.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

BASE = os.environ.get("OIDC_BASE_URL", "https://your-qiip-host.localdomain/oidc").rstrip("/")
PREFIX = os.environ.get("OIDC_BASE_PATH", "/oidc")
CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "my-qiip-client")
CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "change-me")
APP_REDIRECT_URI = os.environ.get(
    "OIDC_REDIRECT_URI", "https://your-qiip-host.localdomain/auth/callback"
)
USERS_FILE = Path(os.environ.get("OIDC_USERS_FILE", "/opt/qiip-oidc/users.txt"))
KEY_FILE = Path(os.environ.get("OIDC_KEY_FILE", "/opt/qiip-oidc/key.pem"))
DOMAIN = "localdomain"
TOKEN_TTL = 600

# ---------------------------------------------------------------------------
# RSA signing key (persisted; regenerated if the file is missing)
# ---------------------------------------------------------------------------

def _load_or_create_key() -> tuple[object, str]:
    if KEY_FILE.exists():
        key = serialization.load_pem_private_key(
            KEY_FILE.read_bytes(), password=None
        )
        return key, "local"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    KEY_FILE.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(KEY_FILE, 0o600)
    return key, "local"


_PRIVATE_KEY, KID = _load_or_create_key()


def _jwk() -> dict:
    pub = _PRIVATE_KEY.public_key()
    numbers = pub.public_numbers()
    def b64url(n: int) -> str:
        return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()

    return {
        "kty": "RSA",
        "kid": KID,
        "use": "sig",
        "alg": "RS256",
        "n": b64url(numbers.n),
        "e": b64url(numbers.e),
    }


def _sign_id_token(claims: dict) -> str:
    return jwt.encode(
        claims, _PRIVATE_KEY, algorithm="RS256", headers={"kid": KID}
    )


# ---------------------------------------------------------------------------
# User store: USERS_FILE, one "username:password" per line (# comments allowed)
# ---------------------------------------------------------------------------

def load_users() -> dict[str, str]:
    users: dict[str, str] = {}
    if not USERS_FILE.exists():
        return users
    for line in USERS_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, password = line.partition(":")
        name = name.strip().lower()
        if name:
            users[name] = password
    return users


def check_login(username: str, password: str) -> str | None:
    """Return the canonical username on success, else None."""
    users = load_users()
    name = username.strip().lower()
    if name not in users:
        return None
    if not hmac.compare_digest(users[name], password):
        return None
    return name


def user_email(name: str) -> str:
    return name if "@" in name else f"{name}@{DOMAIN}"


# In-memory state (single worker).
_codes: dict[str, dict] = {}       # code -> {username, client_id, redirect_uri, nonce, expires}
_tokens: dict[str, dict] = {}      # access_token -> {username, expires}

app = FastAPI(title="qiip toy oidc", openapi_url=None, docs_url=None, redoc_url=None)


@app.get(f"{PREFIX}/.well-known/openid-configuration")
def discovery() -> JSONResponse:
    return JSONResponse(
        {
            "issuer": BASE,
            "authorization_endpoint": f"{BASE}/authorize",
            "token_endpoint": f"{BASE}/token",
            "userinfo_endpoint": f"{BASE}/userinfo",
            "jwks_uri": f"{BASE}/jwks",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "scopes_supported": ["openid", "email", "profile"],
            "claims_supported": ["sub", "email", "email_verified", "name"],
            "code_challenge_methods_supported": [],
        }
    )


@app.get(f"{PREFIX}/jwks")
def jwks() -> JSONResponse:
    return JSONResponse({"keys": [_jwk()]})


_LOGIN_FORM = """<!doctype html>
<html><head><title>Local QIIP OIDC sign-in</title></head>
<body style="font-family: sans-serif; max-width: 26rem; margin: 3rem auto;">
<h2>Local QIIP OIDC sign-in</h2>
<p>Enter a test user (the @{domain} suffix is added automatically).</p>
{error}
<form method="post" action="{prefix}/login">
<input type="hidden" name="client_id" value="{client_id}">
<input type="hidden" name="redirect_uri" value="{redirect_uri}">
<input type="hidden" name="state" value="{state}">
<input type="hidden" name="scope" value="{scope}">
<input type="hidden" name="nonce" value="{nonce}">
<label>Username<br><input name="username" autofocus required></label><br><br>
<label>Password<br><input type="password" name="password" required></label><br><br>
<button type="submit">Sign in</button>
</form>
</body></html>"""


@app.get(f"{PREFIX}/authorize")
def authorize(
    response_type: str = "",
    client_id: str = "",
    redirect_uri: str = "",
    state: str = "",
    scope: str = "",
    nonce: str = "",
) -> Response:
    if response_type != "code":
        return RedirectResponse(_oidc_error(redirect_uri, state, "unsupported_response_type"), status_code=302)
    if client_id != CLIENT_ID:
        return RedirectResponse(_oidc_error(redirect_uri, state, "unauthorized_client"), status_code=302)
    if redirect_uri != APP_REDIRECT_URI:
        return RedirectResponse(_oidc_error(redirect_uri, state, "invalid_request") + "&error_description=bad_redirect_uri", status_code=302)
    # Plaintext redirect (no OAuth parameter leakage beyond code/state).
    html = _LOGIN_FORM.format(
        domain=DOMAIN, prefix=PREFIX, error="",
        client_id=client_id, redirect_uri=redirect_uri,
        state=state, scope=scope, nonce=nonce,
    )
    return HTMLResponse(html)


@app.post(f"{PREFIX}/login")
async def login(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    client_id: str = Form(""),
    redirect_uri: str = Form(""),
    state: str = Form(""),
    scope: str = Form(""),
    nonce: str = Form(""),
) -> Response:
    name = check_login(username, password)
    if name is None:
        html = _LOGIN_FORM.format(
            domain=DOMAIN, prefix=PREFIX,
            error="<p style=\"color: #a00;\">Invalid username or password.</p>",
            client_id=client_id, redirect_uri=redirect_uri,
            state=state, scope=scope, nonce=nonce,
        )
        return HTMLResponse(html, status_code=401)
    code = secrets.token_urlsafe(24)
    _codes[code] = {
        "username": name,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "nonce": nonce,
        "expires": time.time() + 300,
    }
    from urllib.parse import urlencode
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}{urlencode({'code': code, 'state': state})}", status_code=302)


@app.post(f"{PREFIX}/token")
async def token(request: Request) -> JSONResponse:
    form = dict(await request.form())
    auth = request.headers.get("authorization", "")
    client_id = form.get("client_id") or ""
    client_secret = form.get("client_secret") or ""
    if auth.lower().startswith("basic "):
        import base64 as b64
        try:
            decoded = b64.b64decode(auth.split(" ", 1)[1]).decode()
            client_id, _, client_secret = decoded.partition(":")
        except Exception:
            pass
    if client_id != CLIENT_ID or not hmac.compare_digest(client_secret, CLIENT_SECRET):
        return _token_error("invalid_client")
    grant_type = form.get("grant_type", "")
    code = form.get("code", "")
    if grant_type != "authorization_code" or code not in _codes:
        return _token_error("invalid_grant")
    entry = _codes.pop(code)
    if entry["expires"] < time.time():
        return _token_error("invalid_grant")
    if entry["client_id"] != client_id:
        return _token_error("invalid_grant")
    if form.get("redirect_uri") is not None and form.get("redirect_uri") != entry["redirect_uri"]:
        return _token_error("invalid_grant")

    username = entry["username"]
    email = user_email(username)
    now = int(time.time())
    id_token = _sign_id_token(
        {
            "iss": BASE,
            "sub": email,
            "aud": client_id,
            "iat": now,
            "exp": now + TOKEN_TTL,
            "email": email,
            "email_verified": True,
            "name": username,
            "nonce": entry["nonce"] or None,
        }
    )
    access_token = secrets.token_urlsafe(32)
    _tokens[access_token] = {"username": username, "email": email, "expires": now + TOKEN_TTL}
    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": TOKEN_TTL,
            "id_token": id_token,
        }
    )


@app.get(f"{PREFIX}/userinfo")
def userinfo(request: Request) -> JSONResponse:
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    entry = _tokens.get(token)
    if entry is None or entry["expires"] < time.time():
        return JSONResponse({"error": "invalid_token"}, status_code=401)
    email = entry["email"]
    return JSONResponse(
        {
            "sub": email,
            "email": email,
            "email_verified": True,
            "name": entry["username"],
        }
    )


def _token_error(code: str) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=400)


def _oidc_error(redirect_uri: str, state: str, code: str) -> str:
    from urllib.parse import urlencode
    sep = "&" if "?" in redirect_uri else "?"
    return f"{redirect_uri}{sep}{urlencode({'error': code, 'state': state})}"


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8081)
