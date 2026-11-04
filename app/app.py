"""Tresorry: a tiny self-hosted, passphrase-gated file drop.

Every route except /login requires a valid session cookie or HTTP Basic auth
(any username, the passphrase as password). Unknown paths redirect to /login
for anonymous clients, so nothing about the share leaks before auth.
"""
import hashlib
import hmac
import logging
import mimetypes
import os
import secrets
import shutil
import tempfile
import threading
import time
import unicodedata
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path

from flask import (Flask, Request, abort, g, jsonify, redirect, render_template,
                   request, send_file, session, url_for)
from flask.sessions import SecureCookieSessionInterface

ROOT = Path(os.path.realpath(os.environ.get("SHARE_ROOT", "/data")))
HASH_FILE = Path(os.environ.get("PASSWORD_HASH_FILE", "/secrets/password_hash"))
SPOOL = ROOT / ".tresorry-spool"
MAX_UPLOAD = int(float(os.environ.get("MAX_UPLOAD_GB", "20")) * 1024 ** 3)
SESSION_HOURS = float(os.environ.get("SESSION_HOURS", "3"))
# Files older than this vanish from the panel and are no longer served (never deleted).
VISIBLE_DAYS = float(os.environ.get("VISIBLE_DAYS", "28"))

# Login throttling (in-memory, single worker process).
WINDOW = 60
MAX_FAILS_PER_IP = 10
MAX_FAILS_GLOBAL = 30

log = logging.getLogger("tresorry")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

SPOOL.mkdir(exist_ok=True)
for leftover in SPOOL.iterdir():  # clean up interrupted uploads
    try:
        leftover.unlink()
    except OSError:
        pass


class SpoolRequest(Request):
    """Spool uploads onto the share volume so big files never fill the container."""

    def _get_file_stream(self, total_content_length, content_type, filename=None, content_length=None):
        return tempfile.NamedTemporaryFile("wb+", dir=SPOOL, prefix="up-")


class MaxAgeSessionInterface(SecureCookieSessionInterface):
    """Send Max-Age (relative) instead of Expires (absolute date). If this host's
    clock is skewed (common in VMs), an Expires date would be off in the browser."""

    def get_expiration_time(self, app, session):
        return None

    def save_session(self, app, session, response):
        super().save_session(app, session, response)
        exp = session.get("exp")
        if not exp:
            return
        name = self.get_cookie_name(app)
        cookies = [
            f"{h}; Max-Age={max(0, int(exp - time.time()))}"
            if h.startswith(name + "=") and "Max-Age" not in h else h
            for h in response.headers.getlist("Set-Cookie")
        ]
        response.headers.setlist("Set-Cookie", cookies)


app = Flask(__name__)
app.request_class = SpoolRequest
app.session_interface = MaxAgeSessionInterface()
app.config.update(
    SECRET_KEY=secrets.token_bytes(32),  # rotates on restart: everyone re-logs in
    SESSION_COOKIE_NAME="__Host-tresorry",
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=SESSION_HOURS),
    SESSION_REFRESH_EACH_REQUEST=False,  # absolute expiry: 3 h after login, activity does not extend it
    MAX_CONTENT_LENGTH=MAX_UPLOAD,
)

# --------------------------------------------------------------------------- #
# Passphrase verification
# --------------------------------------------------------------------------- #
_pw_lock = threading.Lock()
_pw_state = {"mtime": None, "params": None}
_basic_cache = {}  # HMAC(secret, password) -> expiry, avoids scrypt on every curl call


def _load_hash():
    st = HASH_FILE.stat()
    if _pw_state["mtime"] != st.st_mtime:
        algo, n, r, p, salt, dk = HASH_FILE.read_text().strip().split("$")
        if algo != "scrypt":
            raise RuntimeError("unsupported hash format")
        rotated = _pw_state["mtime"] is not None
        _pw_state.update(mtime=st.st_mtime, params=(int(n), int(r), int(p), bytes.fromhex(salt), bytes.fromhex(dk)))
        _basic_cache.clear()
        if rotated:  # new passphrase: every existing browser session dies
            with _sess_lock:
                _sessions.clear()
            log.info("passphrase changed, all sessions revoked")
    return _pw_state["params"]


# Server-side session registry so logout and passphrase rotation actually revoke
# a cookie (the signed cookie alone would stay valid until it expires).
_sess_lock = threading.Lock()
_sessions: dict = {}  # sid -> expiry


def session_create() -> str:
    sid = secrets.token_urlsafe(32)
    now = time.time()
    with _sess_lock:
        for k in [k for k, exp in _sessions.items() if exp < now]:
            del _sessions[k]
        _sessions[sid] = now + SESSION_HOURS * 3600
    return sid


def session_valid(sid) -> bool:
    if not sid:
        return False
    with _pw_lock:
        try:
            _load_hash()
        except OSError:
            return False
    with _sess_lock:
        return _sessions.get(sid, 0) > time.time()


def session_revoke(sid):
    with _sess_lock:
        _sessions.pop(sid, None)


def verify_password(pw: str) -> bool:
    if not pw or len(pw) > 256:
        return False
    with _pw_lock:
        n, r, p, salt, dk = _load_hash()
    cand = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, maxmem=128 * 1024 * 1024, dklen=len(dk))
    return hmac.compare_digest(cand, dk)


_th_lock = threading.Lock()
_fails_global: deque = deque()
_fails_ip: dict = {}


def _prune(q, now):
    while q and q[0] < now - WINDOW:
        q.popleft()


def throttled(ip: str) -> bool:
    """Hard-block an IP after too many failures. Global pressure only slows every
    attempt down (see below), so a few attacking IPs cannot lock out real users."""
    now = time.time()
    with _th_lock:
        _prune(_fails_global, now)
        q = _fails_ip.get(ip)
        if q is not None:
            _prune(q, now)
        under_attack = len(_fails_global) >= MAX_FAILS_GLOBAL
        blocked = q is not None and len(q) >= MAX_FAILS_PER_IP
    if under_attack and not blocked:
        time.sleep(2.0)
    return blocked


def record_fail(ip: str):
    now = time.time()
    with _th_lock:
        _fails_global.append(now)
        _fails_ip.setdefault(ip, deque()).append(now)
        if len(_fails_ip) > 5000:
            _fails_ip.clear()
    log.warning("auth failure from %s", ip)
    time.sleep(1.0)


def check_basic(pw: str, ip: str) -> bool:
    key = hmac.new(app.secret_key, pw.encode(), hashlib.sha256).digest()
    now = time.time()
    with _pw_lock:
        try:
            _load_hash()  # clears the cache if the passphrase was rotated
        except OSError:
            return False
        if _basic_cache.get(key, 0) > now:
            return True
    if verify_password(pw):
        _basic_cache[key] = now + 300
        return True
    record_fail(ip)
    return False


# --------------------------------------------------------------------------- #
# Gate: nothing but /login is reachable without auth
# --------------------------------------------------------------------------- #
def _authed_session() -> bool:
    return (bool(session.get("auth")) and session.get("exp", 0) > time.time()
            and session_valid(session.get("sid")))


@app.before_request
def gate():
    g.nonce = secrets.token_urlsafe(16)
    g.via = None

    # Reject cross-origin POSTs outright.
    if request.method not in ("GET", "HEAD"):
        origin = request.headers.get("Origin")
        if origin and origin.split("://", 1)[-1] != request.host:
            abort(403)

    if request.endpoint == "login":
        return None

    if _authed_session():
        g.via = "session"
        if request.method not in ("GET", "HEAD"):
            token = request.headers.get("X-CSRF-Token")
            if token is None and not (request.mimetype or "").startswith("multipart/"):
                token = request.form.get("csrf")
            if not token or not hmac.compare_digest(token, session.get("csrf", "")):
                abort(403)
        return None

    auth = request.authorization
    if auth is not None and auth.type == "basic" and auth.password:
        ip = request.remote_addr or "?"
        if throttled(ip):
            return "Too many attempts, wait a minute.\n", 429
        if check_basic(auth.password, ip):
            g.via = "basic"
            return None
        return "Unauthorized\n", 401

    if request.method == "GET" and request.endpoint in ("browse", "index"):
        return redirect(url_for("login", next=request.path))
    if request.method == "GET" and "text/html" in request.headers.get("Accept", ""):
        return redirect(url_for("login"))
    return "Unauthorized\n", 401


@app.after_request
def headers(resp):
    nonce = getattr(g, "nonce", "")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'none'; script-src 'self'; "
        f"style-src 'self' 'nonce-{nonce}'; img-src 'self' data:; media-src 'self'; "
        "font-src 'self'; connect-src 'self'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'",
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    # same-origin, not no-referrer: no-referrer makes browsers send "Origin: null" on POSTs
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers.setdefault("Cache-Control", "no-store")
    resp.headers["Server"] = "tresorry"
    return resp


# --------------------------------------------------------------------------- #
# Path handling
# --------------------------------------------------------------------------- #
def resolve(sub: str):
    """Map a URL sub-path to a real path that is guaranteed to sit inside ROOT."""
    parts = [p for p in (sub or "").split("/") if p not in ("", ".")]
    if any(p == ".." or p.startswith(".") or "\x00" in p for p in parts):
        abort(404)
    real = Path(os.path.realpath(ROOT.joinpath(*parts)))
    if not inside_share(real):
        abort(404)
    return real, "/".join(parts)


def inside_share(real: Path) -> bool:
    """True if a resolved path is ROOT or below it and not in a hidden (dot) entry,
    so symlinks cannot escape the share or reach hidden folders like the spool."""
    if real == ROOT:
        return True
    if ROOT not in real.parents:
        return False
    return not any(part.startswith(".") for part in real.relative_to(ROOT).parts)


_clock = {"offset": 0.0, "at": 0.0}


def share_now() -> float:
    """Current time according to the share's filesystem, not this host. When the
    share is a VM shared folder and the VM clock is skewed, file ages would be off,
    so ages are measured against the ctime of a freshly touched probe file.
    Re-probed every 10 minutes."""
    now = time.time()
    if now - _clock["at"] > 600:
        probe = SPOOL / "clock-probe"
        try:
            probe.write_bytes(b"")
            _clock["offset"] = os.stat(probe).st_ctime - time.time()
        except OSError:
            _clock["offset"] = 0.0
        _clock["at"] = now
    return now + _clock["offset"]


def added_at(st) -> float:
    """When a file arrived in the share. ctime catches files copied in with an old
    mtime (a copy gets a fresh ctime); mtime catches later edits."""
    return max(st.st_mtime, st.st_ctime)


def expired(st) -> bool:
    return VISIBLE_DAYS > 0 and share_now() - added_at(st) > VISIBLE_DAYS * 86400


def clean_name(raw: str) -> str:
    name = (raw or "").replace("\\", "/").split("/")[-1]
    name = unicodedata.normalize("NFC", name)
    name = "".join(ch for ch in name if ch.isprintable()).strip().lstrip(".").strip()
    if len(name.encode()) > 240:
        stem, ext = os.path.splitext(name)
        name = stem.encode()[: 240 - len(ext.encode())].decode(errors="ignore") + ext
    return name


def unique_target(folder: Path, name: str) -> Path:
    stem, ext = os.path.splitext(name)
    candidate, i = folder / name, 1
    while os.path.lexists(candidate):  # lexists: dangling symlinks count as taken
        candidate = folder / f"{stem} ({i}){ext}"
        i += 1
    return candidate


KINDS = {
    "image": {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".heic", ".ico", ".tif", ".tiff"},
    "video": {".mp4", ".mkv", ".mov", ".avi", ".webm", ".m4v"},
    "audio": {".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac"},
    "archive": {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".iso", ".dmg", ".cab"},
    "code": {".py", ".ps1", ".sh", ".js", ".ts", ".c", ".cpp", ".h", ".cs", ".go", ".rs", ".java", ".rb",
             ".php", ".html", ".css", ".json", ".xml", ".yml", ".yaml", ".toml", ".sql", ".bat", ".vbs", ".psm1"},
    "doc": {".pdf", ".doc", ".docx", ".txt", ".md", ".rtf", ".odt", ".xls", ".xlsx", ".csv", ".ppt", ".pptx", ".log"},
    "binary": {".exe", ".dll", ".bin", ".elf", ".so", ".msi", ".apk", ".jar", ".sys"},
}
TEXTISH = KINDS["code"] | {".txt", ".md", ".csv", ".log", ".ini", ".conf", ".cfg", ".nessus"}


def kind_of(name: str, is_dir: bool) -> str:
    if is_dir:
        return "folder"
    ext = os.path.splitext(name)[1].lower()
    for kind, exts in KINDS.items():
        if ext in exts:
            return kind
    return "file"


def human(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


app.jinja_env.filters["human"] = human


def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    nxt = request.values.get("next", "/")
    if (nxt != "/" and not nxt.startswith("/browse/")) or "\\" in nxt or "//" in nxt \
            or ".." in nxt.split("/") or any(ord(c) < 32 for c in nxt):
        nxt = "/"
    if request.method == "POST":
        ip = request.remote_addr or "?"
        if throttled(ip):
            error = "Too many attempts. Wait a minute and try again."
        elif verify_password(request.form.get("password", "")):
            session_revoke(session.get("sid"))
            session.clear()
            session.permanent = True
            session["sid"] = session_create()
            session["auth"] = True
            session["exp"] = time.time() + SESSION_HOURS * 3600
            session["csrf"] = secrets.token_urlsafe(32)
            log.info("login ok from %s", ip)
            return redirect(nxt)
        else:
            record_fail(ip)
            error = "That passphrase did not match."
    if _authed_session() and request.method == "GET":
        return redirect(nxt)
    tiles = [secrets.randbelow(9) for _ in range(96)]
    status = 429 if error and error.startswith("Too many") else (401 if error else 200)
    return render_template("login.html", error=error, next=nxt, tiles=tiles), status


@app.post("/logout")
def logout():
    session_revoke(session.get("sid"))
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def index():
    return redirect(url_for("browse", sub=""))


@app.get("/browse/", defaults={"sub": ""})
@app.get("/browse/<path:sub>")
def browse(sub):
    real, rel = resolve(sub)
    if real.is_file():
        return redirect(url_for("download", sub=rel))
    if not real.is_dir():
        abort(404)
    entries, total = [], 0
    with os.scandir(real) as it:
        for e in it:
            if e.name.startswith("."):
                continue
            try:
                target = os.path.realpath(e.path)
                if not inside_share(Path(target)):
                    continue  # symlink escaping the share or pointing at a hidden entry
                st = os.stat(target)
                is_dir = e.is_dir()
            except OSError:
                continue
            if not is_dir and expired(st):
                continue  # older than VISIBLE_DAYS: hidden from the panel
            size = 0 if is_dir else st.st_size
            total += size
            days_left = None if is_dir else (VISIBLE_DAYS * 86400 - (share_now() - added_at(st))) / 86400
            entries.append({
                "name": e.name,
                "rel": f"{rel}/{e.name}" if rel else e.name,
                "is_dir": is_dir,
                "size": size,
                "mtime": int(st.st_mtime),
                "date": datetime.fromtimestamp(st.st_mtime).strftime("%d %b %Y, %H:%M"),
                "kind": kind_of(e.name, is_dir),
                "viewable": (not is_dir) and viewable_mime(e.name) is not None,
                "days_left": days_left if VISIBLE_DAYS > 0 else None,
            })
    entries.sort(key=lambda x: (not x["is_dir"], x["name"].casefold()))
    crumbs, acc = [], []
    for part in rel.split("/") if rel else []:
        acc.append(part)
        crumbs.append({"name": part, "rel": "/".join(acc)})
    if g.via == "basic" and "text/html" not in request.headers.get("Accept", ""):
        return "".join(f"{e['rel']}{'/' if e['is_dir'] else ''}\t{e['size']}\n" for e in entries), 200, {
            "Content-Type": "text/plain; charset=utf-8"}
    return render_template(
        "browse.html", entries=entries, crumbs=crumbs, rel=rel, total=total,
        folder=crumbs[-1]["name"] if crumbs else "Home", csrf=csrf_token(),
        host=request.host, basic=g.via == "basic", visible_days=int(VISIBLE_DAYS),
    )


def viewable_mime(name: str):
    ext = os.path.splitext(name)[1].lower()
    mime = mimetypes.guess_type(name)[0] or ""
    if ext in (".svg", ".svgz") or "svg" in mime or "xml" in mime and mime.startswith("image/"):
        return None
    if mime.startswith(("image/", "video/", "audio/")) or mime == "application/pdf":
        return mime
    if ext in TEXTISH or mime.startswith("text/"):
        return "text/plain"  # Flask appends charset=utf-8
    return None


@app.get("/dl/<path:sub>")
def download(sub):
    real, _ = resolve(sub)
    if not real.is_file() or expired(real.stat()):
        abort(404)
    resp = send_file(real, as_attachment=True, download_name=real.name, conditional=True, max_age=0)
    resp.headers["Content-Security-Policy"] = "sandbox; default-src 'none'"
    return resp


@app.get("/view/<path:sub>")
def view(sub):
    real, rel = resolve(sub)
    if not real.is_file() or expired(real.stat()):
        abort(404)
    mime = viewable_mime(real.name)
    if mime is None:
        return redirect(url_for("download", sub=rel))
    resp = send_file(real, mimetype=mime, as_attachment=False, conditional=True, max_age=0)
    if mime == "application/pdf":
        resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    else:
        resp.headers["Content-Security-Policy"] = "sandbox; default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'"
    return resp


@app.post("/upload/", defaults={"sub": ""})
@app.post("/upload/<path:sub>")
def upload(sub):
    folder, rel = resolve(sub)
    if not folder.is_dir():
        abort(404)
    files = request.files.getlist("file") + request.files.getlist("files")
    if not files:
        return jsonify(error="no files in request (use form field 'file')"), 400
    saved = []
    for f in files:
        name = clean_name(f.filename)
        if not name:
            continue
        f.stream.flush()
        for _ in range(50):
            dest = unique_target(folder, name)
            try:
                os.link(f.stream.name, dest)  # instant, atomic, fails if dest exists
                break
            except FileExistsError:
                continue
            except OSError:
                try:
                    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                except FileExistsError:
                    continue
                with os.fdopen(fd, "wb") as out:
                    f.stream.seek(0)
                    shutil.copyfileobj(f.stream, out, 1024 * 1024)
                break
        else:
            return jsonify(error="could not pick a free filename"), 409
        f.close()
        try:
            os.chmod(dest, 0o644)  # temp files are 0600; make uploads readable like normal files
        except OSError:
            pass
        saved.append({"name": dest.name, "rel": f"{rel}/{dest.name}" if rel else dest.name, "size": dest.stat().st_size})
        log.info("upload %s (%s) via %s from %s", saved[-1]["rel"], human(saved[-1]["size"]), g.via, request.remote_addr)
    return jsonify(saved=saved)


@app.post("/mkdir/", defaults={"sub": ""})
@app.post("/mkdir/<path:sub>")
def mkdir(sub):
    folder, rel = resolve(sub)
    if not folder.is_dir():
        abort(404)
    data = request.get_json(silent=True) or {}
    name = clean_name(data.get("name") or request.form.get("name", ""))
    if not name:
        return jsonify(error="Folder name is empty"), 400
    target = folder / name
    try:
        target.mkdir()
    except FileExistsError:
        return jsonify(error="That folder already exists"), 409
    return jsonify(rel=f"{rel}/{name}" if rel else name)


@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, msg="Nothing here. It may have been moved or never existed."), 404


@app.errorhandler(413)
def too_big(_):
    return jsonify(error=f"File too large (limit {human(MAX_UPLOAD)})"), 413


@app.errorhandler(403)
def forbidden(_):
    return jsonify(error="Forbidden"), 403
