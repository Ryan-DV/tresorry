# Tresorry

Like Tresorit, but it lives under your desk and apologises for nothing.

A self-hosted, passphrase-gated HTTPS file drop in one Docker container. Think
`python -m http.server`, but with uploads, a slick UI and a lock on the door.

- Browse, preview and download files from a folder on the host
- Upload by drag and drop, paste or file picker, with per-file progress
- Create folders, filter, sort; works on phones
- `curl` / `wget` / PowerShell friendly via HTTP Basic auth
- Self-signed TLS generated on first start

## Install

Requirements: Docker with the compose plugin (Docker Desktop on macOS/Windows, or Docker Engine on Linux).

```bash
git clone https://github.com/Ryan-DV/tresorry.git
cd tresorry
cp .env.example .env
```

Edit `.env`: set `SHARE_DIR` to the folder you want to share, and add the IP or hostname clients
will use to `CERT_SANS` (for example `CERT_SANS=localhost,127.0.0.1,192.168.1.50`).
On a Linux host, also set `TRESORRY_UID` and `TRESORRY_GID` to the output of `id -u` and `id -g`.

Generate a passphrase (printed once, only its scrypt hash is stored in `./secrets`):

```bash
./set-password.sh
```

Start it:

```bash
docker compose up -d --build
```

Open `https://<host-ip>/` and accept the self-signed certificate warning once per device.

### Without docker compose

```bash
docker build -t tresorry .
mkdir -p secrets certs data
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD/secrets:/out" --entrypoint python tresorry /app/setpw.py
docker run -d --name tresorry --restart unless-stopped -u "$(id -u):$(id -g)" \
  -p 0.0.0.0:443:8443 \
  -e CERT_SANS="localhost,127.0.0.1,<host-ip>" \
  -v "$PWD/data:/data" -v "$PWD/secrets:/secrets:ro" -v "$PWD/certs:/certs" \
  -e PASSWORD_HASH_FILE=/secrets/password_hash \
  --read-only --tmpfs /tmp:size=64m --cap-drop ALL \
  --security-opt no-new-privileges:true --pids-limit 256 \
  tresorry
```

## Everyday commands

```bash
docker compose logs -f                          # logins, uploads, access log
./set-password.sh                               # new random passphrase, live, revokes sessions
echo 'my own long phrase' | ./set-password.sh --stdin
rm -rf certs && docker compose restart          # new cert (e.g. after an IP change)
git pull && docker compose up -d --build        # update
docker compose down                             # stop
```

## Command line access

The username is ignored; use the passphrase as the password. `-k` because the cert is self-signed.

```bash
curl -k -u :'PASSPHRASE' https://HOST/browse/                      # list (tab separated)
curl -k -u :'PASSPHRASE' -OJ https://HOST/dl/path/to/file.zip      # download
curl -k -u :'PASSPHRASE' -F file=@./file.zip https://HOST/upload/  # upload into the root
wget --no-check-certificate --auth-no-challenge --user=x --password='PASSPHRASE' https://HOST/dl/file.zip
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SHARE_DIR` | `./data` | Host folder that is served and uploaded into |
| `TRESORRY_PORT` | `443` | Host port (HTTPS) |
| `CERT_SANS` | `localhost,127.0.0.1` | Names/IPs in the self-signed cert |
| `SESSION_HOURS` | `3` | Browser sessions end this long after login, activity does not extend it |
| `VISIBLE_DAYS` | `28` | Files older than this leave the panel and are no longer served (never deleted). `0` = off |
| `MAX_UPLOAD_GB` | `20` | Max size per upload request |
| `TRESORRY_UID` / `TRESORRY_GID` | `1000` | User the container runs as (Linux hosts) |

`SESSION_HOURS`, `VISIBLE_DAYS` and `MAX_UPLOAD_GB` are set in `docker-compose.yml`.

## Security model

- Every route except `/login` requires the passphrase (session cookie or HTTP Basic). Static assets,
  unknown paths and errors are behind the gate too, so nothing about the share leaks before login.
- Passphrase: four random words plus two digits (about 41 bits), stored as an scrypt hash.
- Login throttle: 10 failures per minute blocks that IP. Above 30 failures per minute across all IPs,
  every attempt is slowed by 2 s instead of locking real users out.
- Sessions are tracked server-side. Lock (logout) and a passphrase change revoke them at once.
  Cookies are `__Host-`, `Secure`, `HttpOnly`, `SameSite=Strict`, with a relative `Max-Age`.
- CSRF token plus Origin check on every state-changing request.
- Paths are resolved with `realpath` and must stay inside the share. Dotfiles, hidden folders and
  symlinks that leave the share or point into hidden folders are invisible and unreachable.
- Upload names are reduced to a bare filename; existing files are never overwritten (`name (1).ext`).
- User files are served with `nosniff` and a sandbox CSP. HTML and SVG are never rendered inline,
  text-like files are shown as plain text. Strict CSP on the app itself (`script-src 'self'`).
- Container runs as non-root, read-only root filesystem, all capabilities dropped.

File ages for `VISIBLE_DAYS` count from when a file arrived in the share (newest of mtime and ctime),
measured on the share's own filesystem clock, so a VM with a skewed clock still gets it right.
`touch` a file to bring it back. Uploads pass through `SHARE_DIR/.tresorry-spool`.

There is no delete in the UI and no folder upload (zip it first).
