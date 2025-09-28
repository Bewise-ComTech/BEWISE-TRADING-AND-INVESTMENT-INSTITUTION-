# app.py
import os
import secrets
import logging
import mimetypes
import shutil
import subprocess
import hmac
import hashlib
import base64
import time
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from flask import (
    Flask, request, jsonify, render_template, send_from_directory,
    make_response, abort, Response, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from jinja2 import TemplateNotFound

# --------------- Configuration ---------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
CHUNK_FOLDER = os.path.join(UPLOAD_FOLDER, "chunks")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CHUNK_FOLDER, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)

# Env-configurable (default admin PIN set to 811335 as requested)
ADMIN_PIN = os.environ.get("ADMIN_PIN", "811335")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", ADMIN_PIN)
ALLOWED_DEVICE_HASH = os.environ.get("ALLOWED_DEVICE_HASH")   # optional lock-to-device
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_urlsafe(24))
MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 200 * 1024 * 1024))
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") == "1"

# Render/Postgres DB you gave (or override with DATABASE_URL env var)
POSTGRES_URL = os.environ.get("DATABASE_URL") or (
    "postgresql://crypto_trading_ef73_user:ExqngrM4GrJX6FmefoA1g3BRPu2kF0tk@"
    "dpg-d37inupr0fns739ha5r0-a.oregon-postgres.render.com/crypto_trading_ef73"
)

# Optional frontend origin for CORS when streaming video cross-origin
FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN")  # e.g. "https://your-frontend.example.com"

# --------------- App setup ---------------
app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)
app.config["SQLALCHEMY_DATABASE_URI"] = POSTGRES_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.secret_key = SECRET_KEY

# Keep CORS for APIs; streaming/HLS endpoints will add CORS headers dynamically as needed.
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("crypto_training")

db = SQLAlchemy(app)

# --------------- Models ---------------
class Pin(db.Model):
    __tablename__ = "pins"
    id = db.Column(db.Integer, primary_key=True)
    pin = db.Column(db.String(6), unique=True, nullable=False)
    note = db.Column(db.String(256))
    device_id = db.Column(db.String(512))
    ip = db.Column(db.String(64))
    revoked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_at = db.Column(db.DateTime, nullable=True)

class Video(db.Model):
    __tablename__ = "videos"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(512))
    filename = db.Column(db.String(1024))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class File(db.Model):
    __tablename__ = "files"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(512))
    filename = db.Column(db.String(1024))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Payment(db.Model):
    __tablename__ = "payments"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    email = db.Column(db.String(200))
    course_title = db.Column(db.String(300))
    proof_filename = db.Column(db.String(1024))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Session(db.Model):
    __tablename__ = "sessions"
    token = db.Column(db.String(128), primary_key=True)
    pin_id = db.Column(db.Integer, db.ForeignKey("pins.id"))
    device_id = db.Column(db.String(512))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)

# --------------- Utilities --------------
def now():
    return datetime.utcnow()

def generate_pin():
    for _ in range(30):
        candidate = "{:06d}".format(secrets.randbelow(900000) + 100000)
        if not Pin.query.filter_by(pin=candidate).first():
            return candidate
    raise RuntimeError("Unable to generate unique PIN")

def create_session(pin_id, device_id, hours=24):
    token = secrets.token_urlsafe(40)
    s = Session(token=token, pin_id=pin_id, device_id=device_id,
                created_at=now(), expires_at=now() + timedelta(hours=hours))
    db.session.add(s); db.session.commit()
    return token

def validate_session(token):
    if not token:
        return None
    s = Session.query.filter_by(token=token).first()
    if not s:
        return None
    if s.expires_at < now():
        try:
            db.session.delete(s); db.session.commit()
        except Exception:
            pass
        return None
    p = Pin.query.get(s.pin_id)
    if not p:
        try:
            db.session.delete(s); db.session.commit()
        except Exception:
            pass
        return None
    if p.revoked and p.pin != ADMIN_PIN:
        try:
            db.session.delete(s); db.session.commit()
        except Exception:
            pass
        return None
    return s

def admin_auth_ok(req):
    # Header-based admin shortcut
    header = req.headers.get("X-ADMIN-PW")
    if header and header == ADMIN_PASSWORD:
        return True
    token = req.cookies.get("session_token")
    s = validate_session(token)
    if s:
        p = Pin.query.get(s.pin_id)
        if p and p.pin == ADMIN_PIN:
            return True
    return False

def set_session_cookie(resp, token):
    samesite_val = "None" if COOKIE_SECURE else "Lax"
    resp.set_cookie("session_token", token, httponly=True, samesite=samesite_val, secure=COOKIE_SECURE, path="/")
    return resp

# -------------- Init DB & ensure admin PIN exists & non-revocable by default -----------------
with app.app_context():
    db.create_all()
    admin_obj = Pin.query.filter_by(pin=ADMIN_PIN).first()
    if not admin_obj:
        admin_obj = Pin(pin=ADMIN_PIN, note="admin-pin", created_at=now(), revoked=False)
        db.session.add(admin_obj); db.session.commit()
        logger.info("Admin pin created: %s", ADMIN_PIN)
    else:
        if admin_obj.revoked:
            admin_obj.revoked = False
            db.session.add(admin_obj); db.session.commit()
            logger.info("Admin pin was revoked, reset to active: %s", ADMIN_PIN)

# -------------- Error Handling -----------
@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({"success": False, "error": "file_too_large"}), 413

@app.errorhandler(Exception)
def handle_exception(e):
    logger.exception("Unhandled exception: %s", e)
    if request.path.startswith("/api/"):
        return jsonify({"error": "internal_server_error", "message": str(e), "success": False}), 500
    try:
        return render_template("error.html", message=str(e)), 500
    except TemplateNotFound:
        body = f"<h1>Internal Server Error</h1><pre>{str(e)}</pre>"
        resp = make_response(body, 500)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        return resp

# -------------- Page Routes & safe rendering --------------
def safe_render(name):
    candidates = [f"{name}.html"]
    if name == "authentication":
        candidates.append("index.html")
    for tpl in candidates:
        try:
            return render_template(tpl)
        except TemplateNotFound:
            path = os.path.join(app.template_folder or TEMPLATES_DIR, tpl)
            if os.path.exists(path):
                return send_from_directory(app.template_folder, tpl)
    abort(404, description=f"Template not found: {name}.html")

@app.route("/", methods=["GET"])
def root():
    return safe_render("authentication")

@app.route("/authentication.html", methods=["GET"])
def authentication_page():
    return safe_render("authentication")

@app.route("/admin", methods=["GET"])
def admin_page():
    return safe_render("admin")

@app.route("/dashboard", methods=["GET"])
def dashboard_page():
    return safe_render("dashboard")

@app.route("/course", methods=["GET"])
def course_page():
    return safe_render("course")

@app.route("/payment", methods=["GET"])
def payment_page():
    return safe_render("payment")

@app.route("/files", methods=["GET"])
def files_page():
    return safe_render("files")

@app.route("/logo.png")
def logo():
    path = os.path.join(app.static_folder or STATIC_DIR, "logo.png")
    if os.path.exists(path):
        return send_from_directory(app.static_folder, "logo.png")
    svg = ("<svg xmlns='http://www.w3.org/2000/svg' width='200' height='60'>"
           "<rect width='100%' height='100%' fill='#444'/>"
           "<text x='50%' y='50%' dominant-baseline='middle' text-anchor='middle' fill='#fff' font-size='18'>LOGO</text></svg>")
    resp = make_response(svg)
    resp.headers['Content-Type'] = 'image/svg+xml'
    return resp

# -------------- API: Auth ----------------
@app.route("/api/login", methods=["POST"])
def api_login():
    data = (request.get_json() or {})
    pin = (data.get("pin") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    ip = request.remote_addr

    if not pin or len(pin) != 6 or not pin.isdigit():
        return jsonify({"success": False, "error": "invalid_pin_format"}), 400

    if ALLOWED_DEVICE_HASH and device_id and device_id != ALLOWED_DEVICE_HASH:
        return jsonify({"success": False, "error": "device_not_allowed", "message": "Installation locked to a specific device."}), 403

    p = Pin.query.filter_by(pin=pin).first()
    if not p:
        return jsonify({"success": False, "error": "pin_not_found"}), 404

    # Only treat revoked as blocking for non-admin PINs
    if p.revoked and p.pin != ADMIN_PIN:
        return jsonify({"success": False, "error": "pin_revoked"}), 403

    # assign on first use
    if not p.device_id:
        p.device_id = device_id
        p.ip = ip
        p.assigned_at = now()
        db.session.add(p); db.session.commit()
        token = create_session(p.id, device_id)
        resp = jsonify({"success": True, "message": "logged_in", "role": ("admin" if p.pin == ADMIN_PIN else "user")})
        set_session_cookie(resp, token)
        return resp

    # if device matches -> issue session
    if p.device_id == device_id:
        token = create_session(p.id, device_id)
        resp = jsonify({"success": True, "message": "logged_in", "role": ("admin" if p.pin == ADMIN_PIN else "user")})
        set_session_cookie(resp, token)
        return resp

    # different device:
    # If admin PIN -> do NOT revoke automatically. Update assigned device (admin non-revocable by default).
    if p.pin == ADMIN_PIN:
        p.device_id = device_id
        p.ip = ip
        p.assigned_at = now()
        db.session.add(p); db.session.commit()
        token = create_session(p.id, device_id)
        resp = jsonify({"success": True, "message": "logged_in", "role": "admin"})
        set_session_cookie(resp, token)
        return resp

    # otherwise revoke the pin for security
    p.revoked = True
    db.session.add(p); db.session.commit()
    return jsonify({"success": False, "error": "revoked_due_to_multiple_devices", "message": "PIN revoked because it was used on another device."}), 403

@app.route("/api/check_session")
def api_check_session():
    token = request.cookies.get("session_token")
    s = validate_session(token)
    if not s:
        return jsonify({"logged_in": False})
    p = Pin.query.get(s.pin_id)
    return jsonify({"logged_in": True, "pin_id": s.pin_id, "device_id": s.device_id, "is_admin": (p.pin == ADMIN_PIN if p else False)})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    token = request.cookies.get("session_token")
    if token:
        s = Session.query.get(token)
        if s:
            db.session.delete(s); db.session.commit()
    resp = jsonify({"success": True})
    resp.delete_cookie("session_token", path="/")
    return resp

# -------------- API: Videos -------------
@app.route("/api/videos")
def api_videos():
    rows = Video.query.order_by(Video.uploaded_at.desc()).all()
    return jsonify([{"id": r.id, "title": r.title, "uploaded_at": r.uploaded_at.isoformat()} for r in rows])

# -------------- Range-capable streaming helper -------------
def make_range_response(path, request, download_name=None):
    """
    Returns a Response that supports HTTP Range requests for large files.
    """
    file_size = os.path.getsize(path)
    range_header = request.headers.get('Range', None)
    if range_header:
        # parse "bytes=start-end"
        try:
            ranges = range_header.strip().split('=')[1]
            if ',' in ranges:
                # multiple ranges not supported; return full for simplicity
                start = 0
                end = file_size - 1
            else:
                if ranges.startswith('-'):
                    # suffix: last N bytes
                    length = int(ranges[1:])
                    start = max(file_size - length, 0)
                    end = file_size - 1
                elif ranges.endswith('-'):
                    start = int(ranges[:-1])
                    end = file_size - 1
                else:
                    start_s, end_s = ranges.split('-')
                    start = int(start_s) if start_s else 0
                    end = int(end_s) if end_s else file_size - 1
                # clamp
                start = max(0, min(start, file_size - 1))
                end = max(0, min(end, file_size - 1))
        except Exception as e:
            logger.exception("Invalid Range header: %s", e)
            start = 0
            end = file_size - 1
    else:
        start = 0
        end = file_size - 1

    length = end - start + 1
    content_type = mimetypes.guess_type(path)[0] or 'application/octet-stream'

    def generate():
        with open(path, 'rb') as f:
            f.seek(start)
            remaining = length
            chunk_size = 64 * 1024
            while remaining > 0:
                read_sz = min(chunk_size, remaining)
                data = f.read(read_sz)
                if not data:
                    break
                remaining -= len(data)
                yield data

    status = 206 if (range_header and (start != 0 or end != file_size - 1)) else 200
    headers = {
        'Content-Type': content_type,
        'Accept-Ranges': 'bytes',
        'Content-Length': str(length),
        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
        'Content-Range': f'bytes {start}-{end}/{file_size}' if status == 206 else f'bytes 0-{file_size-1}/{file_size}',
    }
    # CORS for streaming to another origin if FRONTEND_ORIGIN is set and matches request origin
    origin = request.headers.get('Origin')
    if FRONTEND_ORIGIN:
        if origin and origin == FRONTEND_ORIGIN:
            headers['Access-Control-Allow-Origin'] = origin
            headers['Access-Control-Allow-Credentials'] = 'true'
    else:
        # if no FRONTEND_ORIGIN specified, echo Origin when present (helps cross-origin access)
        if origin:
            headers['Access-Control-Allow-Origin'] = origin
            headers['Access-Control-Allow-Credentials'] = 'true'

    rv = Response(generate(), status=status, headers=headers)
    # add Content-Disposition when download_name provided
    if download_name:
        rv.headers['Content-Disposition'] = f'inline; filename="{download_name}"'
    return rv

@app.route("/stream/<int:video_id>", methods=["GET"])
def stream_video(video_id):
    # check session before streaming
    token = request.cookies.get("session_token")
    s = validate_session(token)
    if not s:
        # return 401 so frontend will handle re-login
        return ("Unauthorized", 401)
    v = Video.query.get(video_id)
    if not v:
        return ("Not found", 404)
    path = os.path.join(app.config["UPLOAD_FOLDER"], v.filename)
    if not os.path.exists(path):
        return ("File missing", 404)
    try:
        return make_range_response(path, request, download_name=v.filename)
    except Exception as exc:
        logger.exception("Streaming failed for %s: %s", path, exc)
        return ("Streaming error", 500)

# -------------- HLS generation & serving -------------
def create_hls_for_file(src_path, dest_dir, segment_time=6):
    """
    Create HLS (m3u8 + .ts segments) from src_path into dest_dir using ffmpeg.
    Requires ffmpeg installed on the host.
    Returns True on success, False otherwise.
    """
    os.makedirs(dest_dir, exist_ok=True)
    playlist = os.path.join(dest_dir, "index.m3u8")
    # FFmpeg command to produce VOD HLS
    cmd = [
        "ffmpeg", "-y", "-i", src_path,
        "-preset", "veryfast",
        "-g", "48", "-sc_threshold", "0",
        "-keyint_min", "48",
        "-hls_time", str(segment_time),
        "-hls_playlist_type", "vod",
        "-hls_segment_filename", os.path.join(dest_dir, "segment_%05d.ts"),
        "-hls_flags", "independent_segments",
        "-hls_allow_cache", "0",
        "-hls_base_url", "./",
        playlist
    ]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        logger.info("HLS created for %s -> %s", src_path, dest_dir)
        return True
    except Exception as exc:
        logger.exception("ffmpeg HLS creation failed for %s: %s", src_path, exc)
        try:
            if os.path.exists(playlist):
                os.remove(playlist)
        except Exception:
            pass
        return False

@app.route("/hls/<int:video_id>/<path:fname>", methods=["GET", "OPTIONS"])
def serve_hls(video_id, fname):
    # OPTIONS preflight
    if request.method == "OPTIONS":
        origin = request.headers.get('Origin')
        resp = make_response('', 204)
        if origin:
            resp.headers['Access-Control-Allow-Origin'] = origin
            resp.headers['Access-Control-Allow-Credentials'] = 'true'
            resp.headers['Access-Control-Allow-Headers'] = 'Range,Origin,Accept,Content-Type,Authorization'
            resp.headers['Access-Control-Expose-Headers'] = 'Content-Range,Accept-Ranges,Content-Length,Content-Type'
        return resp

    hls_dir = os.path.join(app.config["UPLOAD_FOLDER"], f"hls_{video_id}")
    # secure filename usage
    safe_fname = secure_filename(fname)
    target = os.path.join(hls_dir, safe_fname)
    if not os.path.exists(target):
        return ("Not found", 404)
    origin = request.headers.get('Origin')
    resp = make_response(send_file(target))
    if origin:
        resp.headers['Access-Control-Allow-Origin'] = origin
        resp.headers['Access-Control-Allow-Credentials'] = 'true'
        resp.headers['Access-Control-Expose-Headers'] = 'Content-Range,Accept-Ranges,Content-Length,Content-Type'
    if target.endswith('.m3u8'):
        resp.headers['Content-Type'] = 'application/vnd.apple.mpegurl'
    elif target.endswith('.ts'):
        resp.headers['Content-Type'] = 'video/mp2t'
    return resp


# -------------- Signed URL helpers (new) -------------
def make_signed_token(video_id, expires_seconds=3600):
    """
    Create a URL-safe base64 token encoding "video_id:expiry:signature"
    signature = HMAC_SHA256(app.secret_key, f"{video_id}:{expiry}")
    """
    expiry = int(time.time()) + int(expires_seconds)
    msg = f"{video_id}:{expiry}"
    sig = hmac.new(app.secret_key.encode(), msg.encode(), hashlib.sha256).hexdigest()
    payload = f"{msg}:{sig}".encode()
    token = base64.urlsafe_b64encode(payload).decode()
    return token

def verify_signed_token(token):
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        parts = raw.split(':')
        if len(parts) < 3:
            return False, None
        video_id = int(parts[0])
        expiry = int(parts[1])
        sig = parts[2]
        # Recompute
        msg = f"{video_id}:{expiry}"
        expected = hmac.new(app.secret_key.encode(), msg.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return False, None
        if time.time() > expiry:
            return False, None
        return True, video_id
    except Exception as exc:
        logger.exception("verify_signed_token failed: %s", exc)
        return False, None

@app.route("/api/video_token/<int:video_id>")
def api_video_token(video_id):
    # Requires a valid session (so only logged-in users can request tokens)
    token_cookie = request.cookies.get("session_token")
    s = validate_session(token_cookie)
    if not s:
        return jsonify({"success": False, "error": "auth_required"}), 401
    v = Video.query.get(video_id)
    if not v:
        return jsonify({"success": False, "error": "video_not_found"}), 404
    token = make_signed_token(video_id, expires_seconds=60*60)  # 1 hour by default
    signed_url = f"/signed_stream/{video_id}?t={token}"
    return jsonify({"success": True, "token": token, "url": signed_url})

@app.route("/signed_stream/<int:video_id>")
def signed_stream(video_id):
    token = request.args.get("t", "")
    ok, vid = verify_signed_token(token)
    if not ok or vid != video_id:
        return ("Unauthorized", 401)
    v = Video.query.get(video_id)
    if not v:
        return ("Not found", 404)
    path = os.path.join(app.config["UPLOAD_FOLDER"], v.filename)
    if not os.path.exists(path):
        return ("File missing", 404)
    try:
        # stream without requiring session cookie (token-based)
        return make_range_response(path, request, download_name=v.filename)
    except Exception as exc:
        logger.exception("Signed streaming failed for %s: %s", path, exc)
        return ("Streaming error", 500)

# -------------- API: Admin -------------
@app.route("/api/admin/upload_video", methods=["POST"])
def api_admin_upload_video():
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    title = request.form.get("title", "").strip()
    f = request.files.get("video")
    if not f or not title:
        return jsonify({"success": False, "error": "missing_title_or_file"}), 400
    safe_name = secrets.token_hex(8) + "_" + secure_filename(f.filename)
    path = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
    try:
        f.save(path)
        v = Video(title=title, filename=safe_name, uploaded_at=now())
        db.session.add(v); db.session.commit()
        # Attempt to create HLS (requires ffmpeg)
        hls_dir = os.path.join(app.config["UPLOAD_FOLDER"], f"hls_{v.id}")
        ok = create_hls_for_file(path, hls_dir, segment_time=6)
        if not ok:
            logger.warning("HLS creation failed for video id %s; continuing without HLS", v.id)
            return jsonify({"success": True, "video_id": v.id, "warning": "hls_creation_failed"})
        return jsonify({"success": True, "video_id": v.id, "hls": True})
    except Exception as exc:
        logger.exception("upload_video failed: %s", exc)
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass
        return jsonify({"success": False, "error": "upload_failed", "message": str(exc)}), 500

@app.route("/api/admin/generate_pin", methods=["POST"])
def api_admin_generate_pin():
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    note = (request.get_json() or {}).get("note", "")[:200]
    pin = generate_pin()
    p = Pin(pin=pin, note=note, created_at=now(), revoked=False)
    db.session.add(p); db.session.commit()
    return jsonify({"success": True, "pin": pin})

@app.route("/api/admin/pins")
def api_admin_pins():
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    rows = Pin.query.order_by(Pin.created_at.desc()).all()
    data = []
    for r in rows:
        data.append({
            "id": r.id, "pin": r.pin, "note": r.note, "device_id": r.device_id,
            "ip": r.ip, "revoked": r.revoked, "created_at": (r.created_at.isoformat() if r.created_at else None),
            "assigned_at": (r.assigned_at.isoformat() if r.assigned_at else None)
        })
    return jsonify(data)

@app.route("/api/admin/revoke_pin", methods=["POST"])
def api_admin_revoke_pin():
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    data = request.get_json() or {}
    pin_id = data.get("pin_id")
    force = bool(data.get("force", False))
    if not pin_id:
        return jsonify({"success": False, "error": "missing_pin_id"}), 400
    p = Pin.query.get(pin_id)
    if not p:
        return jsonify({"success": False, "error": "pin_not_found"}), 404
    # If this is the protected ADMIN_PIN, require explicit confirmation (force:true)
    if p.pin == ADMIN_PIN:
        if not force:
            return jsonify({"success": False, "error": "confirm_admin_action_required", "message": "To revoke the admin PIN, include {\"force\": true} in the request body."}), 409
    p.revoked = True
    db.session.add(p); db.session.commit()
    return jsonify({"success": True})

@app.route("/api/admin/delete_pin", methods=["POST"])
def api_admin_delete_pin():
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    data = request.get_json() or {}
    pin_id = data.get("pin_id")
    if not pin_id:
        return jsonify({"success": False, "error": "missing_pin_id"}), 400
    p = Pin.query.get(pin_id)
    if not p:
        return jsonify({"success": False, "error": "pin_not_found"}), 404
    # PROTECT admin PIN from deletion completely
    if p.pin == ADMIN_PIN:
        return jsonify({"success": False, "error": "admin_pin_protected", "message": "Admin PIN cannot be deleted."}), 409

    try:
        # Remove sessions referencing this pin to avoid FK constraint issues
        try:
            Session.query.filter_by(pin_id=p.id).delete(synchronize_session=False)
            db.session.commit()
        except Exception:
            db.session.rollback()
            logger.exception("Failed to delete sessions for pin %s", p.id)
            return jsonify({"success": False, "error": "delete_failed", "message": "Failed to remove sessions for pin."}), 500

        db.session.delete(p)
        db.session.commit()
        return jsonify({"success": True})
    except Exception as exc:
        logger.exception("Failed to delete pin %s: %s", pin_id, exc)
        db.session.rollback()
        return jsonify({"success": False, "error": "delete_failed", "message": str(exc)}), 500

@app.route("/api/admin/delete_video", methods=["POST"])
def api_admin_delete_video():
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    data = request.get_json() or {}
    video_id = data.get("video_id")
    if not video_id:
        return jsonify({"success": False, "error": "missing_video_id"}), 400
    v = Video.query.get(video_id)
    if not v:
        return jsonify({"success": False, "error": "video_not_found"}), 404
    filename = v.filename
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    # also remove HLS directory if present
    hls_dir = os.path.join(app.config["UPLOAD_FOLDER"], f"hls_{v.id}")
    try:
        db.session.delete(v)
        db.session.commit()
    except Exception as exc:
        logger.exception("DB delete failed for video %s: %s", video_id, exc)
        db.session.rollback()
        return jsonify({"success": False, "error": "delete_failed", "message": str(exc)}), 500
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception as exc:
        logger.exception("Failed to remove video file %s: %s", path, exc)
    try:
        if os.path.isdir(hls_dir):
            shutil.rmtree(hls_dir)
    except Exception as exc:
        logger.exception("Failed to remove HLS dir %s: %s", hls_dir, exc)
    return jsonify({"success": True})

# Admin file endpoints (upload/list/delete)
@app.route("/api/admin/upload_file", methods=["POST"])
def api_admin_upload_file():
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    title = request.form.get("title", "").strip()
    f = request.files.get("file")
    if not f or not title:
        return jsonify({"success": False, "error": "missing_title_or_file"}), 400
    safe_name = secrets.token_hex(8) + "_" + secure_filename(f.filename)
    path = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
    try:
        f.save(path)
        file_row = File(title=title, filename=safe_name, uploaded_at=now())
        db.session.add(file_row)
        db.session.commit()
        return jsonify({"success": True, "file_id": file_row.id})
    except Exception as exc:
        logger.exception("upload_file failed: %s", exc)
        db.session.rollback()
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass
        return jsonify({"success": False, "error": "upload_failed", "message": str(exc)}), 500

@app.route("/api/files")
def api_files():
    rows = File.query.order_by(File.uploaded_at.desc()).all()
    data = [{"id": r.id, "title": r.title, "filename": r.filename, "uploaded_at": (r.uploaded_at.isoformat() if r.uploaded_at else None)} for r in rows]
    return jsonify(data)

@app.route("/view/file/<int:file_id>")
def view_file(file_id):
    frow = File.query.get(file_id)
    if not frow:
        return "Not found", 404
    filename = frow.filename
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if not os.path.exists(file_path):
        return "File missing", 404
    resp = make_response(send_from_directory(app.config["UPLOAD_FOLDER"], filename))
    resp.headers["Content-Disposition"] = f'inline; filename="{filename}"'
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp

# -------------- Chunked upload endpoints -------------
@app.route("/api/admin/upload_video_chunk", methods=["POST"])
def api_admin_upload_video_chunk():
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403

    upload_id = request.form.get("upload_id") or request.values.get("upload_id")
    filename = request.form.get("filename") or request.values.get("filename")
    chunk_index = request.form.get("chunk_index")
    total_chunks = request.form.get("total_chunks")
    chunk_file = request.files.get("chunk")

    if not upload_id or not filename or chunk_index is None or total_chunks is None or not chunk_file:
        return jsonify({"success": False, "error": "missing_chunk_fields"}), 400

    try:
        chunk_index_i = int(chunk_index)
        total_chunks_i = int(total_chunks)
    except Exception:
        return jsonify({"success": False, "error": "invalid_chunk_index_or_total"}), 400

    safe_upload_dir = os.path.join(CHUNK_FOLDER, secure_filename(upload_id))
    os.makedirs(safe_upload_dir, exist_ok=True)
    chunk_path = os.path.join(safe_upload_dir, f"part_{chunk_index_i:06d}.chunk")
    try:
        chunk_file.save(chunk_path)
        return jsonify({"success": True, "saved": True, "chunk_index": chunk_index_i, "total_chunks": total_chunks_i})
    except Exception as exc:
        logger.exception("Failed to save chunk %s: %s", chunk_path, exc)
        return jsonify({"success": False, "error": "chunk_save_failed", "message": str(exc)}), 500

@app.route("/api/admin/finish_video_upload", methods=["POST"])
def api_admin_finish_video_upload():
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403

    data = request.get_json() or {}
    upload_id = data.get("upload_id")
    filename = data.get("filename")
    title = data.get("title", "")[:512]

    if not upload_id or not filename or not title:
        return jsonify({"success": False, "error": "missing_finish_fields"}), 400

    safe_upload_dir = os.path.join(CHUNK_FOLDER, secure_filename(upload_id))
    if not os.path.isdir(safe_upload_dir):
        return jsonify({"success": False, "error": "upload_not_found"}), 404

    parts = sorted([p for p in os.listdir(safe_upload_dir) if p.startswith("part_")])
    if not parts:
        return jsonify({"success": False, "error": "no_chunks_found"}), 400

    safe_name = secrets.token_hex(8) + "_" + secure_filename(filename)
    out_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
    try:
        with open(out_path, "wb") as out_f:
            for part in parts:
                part_path = os.path.join(safe_upload_dir, part)
                with open(part_path, "rb") as pf:
                    shutil.copyfileobj(pf, out_f)
        v = Video(title=title, filename=safe_name, uploaded_at=now())
        db.session.add(v); db.session.commit()
        # remove chunk dir
        try:
            shutil.rmtree(safe_upload_dir)
        except Exception:
            logger.exception("Failed to remove chunk directory %s", safe_upload_dir)

        # Attempt to create HLS for the assembled file
        hls_dir = os.path.join(app.config["UPLOAD_FOLDER"], f"hls_{v.id}")
        ok = create_hls_for_file(out_path, hls_dir, segment_time=6)
        if not ok:
            logger.warning("HLS creation failed for assembled upload %s (video id %s)", out_path, v.id)
            return jsonify({"success": True, "video_id": v.id, "warning": "hls_creation_failed"})
        return jsonify({"success": True, "video_id": v.id, "hls": True})
    except Exception as exc:
        logger.exception("Failed to assemble chunks for upload_id %s: %s", upload_id, exc)
        try:
            if os.path.exists(out_path):
                os.remove(out_path)
        except Exception:
            pass
        return jsonify({"success": False, "error": "assemble_failed", "message": str(exc)}), 500

# -------------- API: Payment (keep record but do not attempt SMTP sending) ------------
@app.route("/api/payment/proof", methods=["POST"])
def api_payment_proof():
    name = request.form.get("name", "")
    email = request.form.get("email", "")
    course_title = request.form.get("course_title", "")
    f = request.files.get("proof")
    if not name or not f:
        return jsonify({"success": False, "error": "missing_fields"}), 400

    # Save to uploads folder (same place as other content)
    safe_name = secrets.token_hex(8) + "_" + secure_filename(f.filename)
    path = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
    try:
        f.save(path)
    except Exception as exc:
        logger.exception("Failed to save proof file: %s", exc)
        return jsonify({"success": False, "error": "save_failed", "message": str(exc)}), 500

    # store payment record
    try:
        pay = Payment(name=name, email=email, course_title=course_title, proof_filename=safe_name, created_at=now())
        db.session.add(pay)
        db.session.commit()
    except Exception as exc:
        logger.exception("Failed to save payment record: %s", exc)
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass
        return jsonify({"success": False, "error": "db_failed", "message": str(exc)}), 500

    return jsonify({"success": True})

# -------------- Health -------------------
@app.route("/api/health")
def health():
    try:
        db.session.execute("SELECT 1")
        return jsonify({"ok": True})
    except Exception as e:
        logger.exception("Health check failed")
        return jsonify({"ok": False, "error": str(e)}), 500

# --------------- Run ---------------------
if __name__ == "__main__":
    debug_flag = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_flag, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

