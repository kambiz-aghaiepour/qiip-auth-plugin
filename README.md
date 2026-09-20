# qiip-auth-plugin

Replace Google OAuth on a [qiip](https://github.com/quadsproject/qiip)
inference-proxy with a **network-local OpenID Connect provider** ("toy OIDC"),
so sign-in can be tested or self-hosted on a lab network without `accounts.google.com`.

It consists of two pieces:

1. **`auth-plugin/internal_oidc.py`** — an *external* qiip auth plugin
   (`auth.internal_oidc`). Qiip's plugin manager discovers third-party plugins
   from a directory (`plugins.external_dir`), so **no qiip source code changes
   are required**.
2. **`oidc-provider/`** — a small FastAPI OpenID Connect provider with a
   username/password login form. Users are stored in a plaintext password file;
   the domain suffix (e.g. `@localdomain`) is appended automatically on login.

```
browser ──https──> nginx (qiip vhost)
                     ├── /         → uvicorn :5555  (qiip inference-proxy)
                     └── /oidc/*   → uvicorn :8081  (this OIDC provider)
```

The provider implements just enough OIDC for qiip's auth plugin:
`/.well-known/openid-configuration`, `/authorize` (password form), `/login`,
`/token`, `/jwks`, `/userinfo`, with RS256-signed ID tokens.

## Repository layout

| Path | Purpose |
|---|---|
| `auth-plugin/internal_oidc.py` | external qiip auth plugin (copy to the server) |
| `oidc-provider/app.py` | the toy OIDC provider (FastAPI) |
| `oidc-provider/users.txt.example` | example user store — copy and edit |
| `oidc-provider/qiip-oidc.service` | systemd unit for the provider |
| `deploy/plugins.yml.example` | `conf/plugins.yml` for the qiip checkout |
| `deploy/env.example` | `.env` additions for the qiip service |

## Deploying on an existing qiip server

Requirements: a qiip checkout with the plugin system (any recent branch — the
plugin manager loads external plugins), nginx in front of qiip, and root access.

### 1. Install the toy OIDC provider

```bash
sudo install -d -m 0755 -o root -g root /opt/qiip-oidc
sudo cp oidc-provider/app.py /opt/qiip-oidc/app.py          # root:root 0644
sudo python3 -m venv /opt/qiip-oidc/.venv
sudo /opt/qiip-oidc/.venv/bin/pip install fastapi uvicorn pyjwt cryptography python-multipart
```

Users (copy the example, edit, keep 0600/root):

```bash
sudo cp oidc-provider/users.txt.example /opt/qiip-oidc/users.txt
sudo chown root:root /opt/qiip-oidc/users.txt && sudo chmod 0600 /opt/qiip-oidc/users.txt
sudo vi /opt/qiip-oidc/users.txt      # one username:password per line, # comments allowed
```

Service:

```bash
sudo cp oidc-provider/qiip-oidc.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now qiip-oidc
```

Add/remove users later: edit `/opt/qiip-oidc/users.txt`, then
`sudo systemctl restart qiip-oidc`.

### 2. Configure the provider environment

Values default inside `app.py` to placeholders; override with environment
variables in `/opt/qiip-oidc/` (e.g. via systemd `Environment=` or a wrapper):

| Variable | Default | Meaning |
|---|---|---|
| `OIDC_BASE_URL` | `https://your-qiip-host.localdomain/oidc` | public issuer URL (must match `server_metadata_url` below) |
| `OIDC_BASE_PATH` | `/oidc` | path prefix nginx proxies to the provider |
| `OIDC_REDIRECT_URI` | `https://your-qiip-host.localdomain/auth/callback` | the qiip callback the provider may redirect to |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | `my-qiip-client` / `change-me` | shared with qiip's `.env` |
| `OIDC_USERS_FILE` / `OIDC_KEY_FILE` | `/opt/qiip-oidc/users.txt` / `key.pem` | user store, RSA signing key |

### 3. Install the auth plugin

```bash
sudo install -d -m 0755 -o root -g root /opt/qiip-plugins/auth
sudo cp auth-plugin/internal_oidc.py /opt/qiip-plugins/auth/   # root:root 0644
```

Note: the plugin directory/files must **not** be group/world-writable and must
not be symlinks — the plugin manager skips untrusted external plugins.

### 4. Configure qiip's plugin loading

In the qiip checkout, copy `deploy/plugins.yml.example` to `conf/plugins.yml`
(the live file is gitignored) and point the provider URL at your issuer:

```yaml
plugins:
  external_dir: /opt/qiip-plugins
  disabled: []
  config:
    auth.google:
      enabled: false
    auth.internal_oidc:
      enabled: true
      server_metadata_url: https://your-qiip-host.localdomain/oidc/.well-known/openid-configuration
```

Setting `auth.google.enabled: false` is important: qiip uses the first loaded
auth plugin.

### 5. Add the OAuth settings to qiip's `.env`

Add `deploy/env.example` values (all three `INFERENCE_PROXY_OAUTH__*` must be
set together), then restart qiip:

```bash
sudo systemctl restart inference-proxy
```

Startup log should show `auth plugin loaded plugin=internal_oidc` (not
`google auth plugin disabled`).

### 6. nginx: proxy `/oidc/` to the provider

Inside the qiip vhost's server block (before the generic `location /`):

```nginx
location /oidc/ {
    proxy_pass http://127.0.0.1:8081/oidc/;
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

If the qiip vhost uses TLS with a certificate the Python client does not trust
(typical self-signed lab cert), the server-side OIDC fetches need it trusted:

- add to `inference-proxy.service`: `Environment=SSL_CERT_FILE=/etc/pki/tls/certs/<host>.pem`
- and run uvicorn with `--proxy-headers` so the callback URL keeps the `https` scheme.

Then `sudo nginx -t && sudo systemctl reload nginx`.

## Verify

```bash
curl -k https://your-qiip-host.localdomain/oidc/.well-known/openid-configuration
# browser: https://your-qiip-host.localdomain/auth/login  → provider form → sign in
# → qiip /start page; the user row appears in data/qiip.db with email user1@localdomain
```

Note the browser must be able to resolve and trust the qiip vhost (for a
self-signed cert, accept the warning once).

## Notes and limitations

- **Test-only.** Plaintext password file, in-memory codes/tokens, no refresh
  tokens or PKCE. The provider redirect uses HTTP 302 (qiip's callback is
  GET-only; Starlette's default 307 would preserve the POST and fail with 405).
- The qiip callback creates local users keyed by the OIDC `sub` claim; the
  email domain (e.g. `localdomain`) can be constrained with
  `INFERENCE_PROXY_OAUTH__ALLOWED_DOMAINS`.
- To use it as the only login surface, keep `auth.google` disabled; to keep
  Google as an option you would need to extend the plugin manager selection
  (qiip picks the first `AuthPlugin`).
