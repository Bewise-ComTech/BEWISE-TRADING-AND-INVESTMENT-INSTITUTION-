# app.py
import os
import secrets
import logging
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from flask import (
    Flask, request, jsonify, render_template, send_from_directory,
    make_response, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from jinja2 import TemplateNotFound

# --------------- Configuration ---------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(BASE_DIR, "data.db")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Ensure folders exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)

# Env-configurable
ADMIN_PIN = os.environ.get("ADMIN_PIN", "891959")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", ADMIN_PIN)
ALLOWED_DEVICE_HASH = os.environ.get("ALLOWED_DEVICE_HASH")   # optional lock-to-device
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_urlsafe(24))
MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 200 * 1024 * 1024))
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") == "1"  # set to "0" for local http testing

RENDER_HOST = os.environ.get("RENDER_HOST", "bewise-trading-and-investment-institution.onrender.com")

# --------------- App setup ---------------
app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)

# ---------- DATABASE CONFIGURATION ----------
# Prefer explicit DATABASE_URL env var; fallback to the provided Render Postgres URL.
# This replaces the default SQLite URI so the app uses your Render Postgres instance.
DB_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://crypto_trading_ef73_user:ExqngrM4GrJX6FmefoA1g3BRPu2kF0tk@dpg-d37inupr0fns739ha5r0-a.oregon-postgres.render.com/crypto_trading_ef73"
)
app.config["SQLALCHEMY_DATABASE_URI"] = DB_URL
# --------------------------------------------

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.secret_key = SECRET_KEY

# Allow CORS for API endpoints and support credentials (cookies)
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# logging
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
    """Generic non-video file uploads (documents, zips, images, etc)."""
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
    """Generate a unique 6-digit PIN (tries up to a few times)."""
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
    if not p or p.revoked:
        try:
            db.session.delete(s); db.session.commit()
        except Exception:
            pass
        return None
    return s

def admin_auth_ok(req):
    """Admin authorized if header matches ADMIN_PASSWORD OR session belongs to admin pin."""
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
    """Set httponly session cookie (path included)."""
    samesite_val = "None" if COOKIE_SECURE else "Lax"
    # include path="/" to ensure cookie is sent for all routes
    resp.set_cookie("session_token", token, httponly=True, samesite=samesite_val, secure=COOKIE_SECURE, path="/")
    return resp

# -------------- Init DB -----------------
with app.app_context():
    db.create_all()
    # Ensure admin PIN exists
    if not Pin.query.filter_by(pin=ADMIN_PIN).first():
        p = Pin(pin=ADMIN_PIN, note="admin-pin", created_at=now(), revoked=False)
        db.session.add(p); db.session.commit()
        logger.info("Admin pin created: %s", ADMIN_PIN)

# -------------- Error Handling -----------
@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({"success": False, "error": "file_too_large"}), 413

@app.errorhandler(Exception)
def handle_exception(e):
    # Log full exception server-side
    logger.exception("Unhandled exception: %s", e)

    # For API endpoints return JSON
    if request.path.startswith("/api/"):
        return jsonify({"error": "internal_server_error", "message": str(e), "success": False}), 500

    # For non-API (HTML) requests return friendly HTML if possible
    try:
        return render_template("error.html", message=str(e)), 500
    except TemplateNotFound:
        body = f"<h1>Internal Server Error</h1><pre>{str(e)}</pre>"
        resp = make_response(body, 500)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        return resp

# -------------- Page Routes & safe rendering --------------
def safe_render(name):
    """Render template name.html from templates or fallback to an alternate if needed.

    For the authentication page we also accept index.html (to support renamed file).
    """
    candidates = [f"{name}.html"]
    if name == "authentication":
        # support projects that renamed the auth template to index.html (GitHub or static hosting)
        candidates.append("index.html")
    for tpl in candidates:
        try:
            return render_template(tpl)
        except TemplateNotFound:
            path = os.path.join(app.template_folder or TEMPLATES_DIR, tpl)
            if os.path.exists(path):
                return send_from_directory(app.template_folder, tpl)
    # if nothing found -> 404
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

@app.route("/admin.html", methods=["GET"])
def admin_html():
    return safe_render("admin")

@app.route("/dashboard", methods=["GET"])
def dashboard_page():
    return safe_render("dashboard")

@app.route("/dashboard.html", methods=["GET"])
def dashboard_html():
    return safe_render("dashboard")

@app.route("/course", methods=["GET"])
def course_page():
    return safe_render("course")

@app.route("/course.html", methods=["GET"])
def course_html():
    return safe_render("course")

@app.route("/payment", methods=["GET"])
def payment_page():
    return safe_render("payment")

@app.route("/payment.html", methods=["GET"])
def payment_html():
    return safe_render("payment")

@app.route("/files", methods=["GET"])
def files_page():
    return safe_render("files")
@app.route("/files.html", methods=["GET"])
def files_html():
    return safe_render("files")

# Serve logo or fallback svg
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

    # optional server-side device lock
    if ALLOWED_DEVICE_HASH and device_id and device_id != ALLOWED_DEVICE_HASH:
        return jsonify({"success": False, "error": "device_not_allowed", "message": "Installation locked to a specific device."}), 403

    p = Pin.query.filter_by(pin=pin).first()
    if not p:
        return jsonify({"success": False, "error": "pin_not_found"}), 404
    if p.revoked:
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

    # different device -> revoke
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

@app.route("/stream/<int:video_id>")
def stream_video(video_id):
    token = request.cookies.get("session_token")
    s = validate_session(token)
    if not s:
        return "Unauthorized", 401
    v = Video.query.get(video_id)
    if not v:
        return "Not found", 404
    path = os.path.join(app.config["UPLOAD_FOLDER"], v.filename)
    if not os.path.exists(path):
        return "File missing", 404
    resp = make_response(send_from_directory(app.config["UPLOAD_FOLDER"], v.filename))
    resp.headers["Content-Disposition"] = f'inline; filename="{v.filename}"'
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp

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
    f.save(path)
    v = Video(title=title, filename=safe_name, uploaded_at=now())
    db.session.add(v); db.session.commit()
    return jsonify({"success": True, "video_id": v.id})

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
    if not pin_id:
        return jsonify({"success": False, "error": "missing_pin_id"}), 400
    p = Pin.query.get(pin_id)
    if not p:
        return jsonify({"success": False, "error": "pin_not_found"}), 404
    p.revoked = True
    db.session.add(p); db.session.commit()
    return jsonify({"success": True})

# ---------------- New Admin endpoints -----------------
@app.route("/api/admin/delete_pin", methods=["POST"])
def api_admin_delete_pin():
    """Permanently delete a PIN record (admin only)."""
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    data = request.get_json() or {}
    pin_id = data.get("pin_id")
    if not pin_id:
        return jsonify({"success": False, "error": "missing_pin_id"}), 400
    p = Pin.query.get(pin_id)
    if not p:
        return jsonify({"success": False, "error": "pin_not_found"}), 404
    try:
        db.session.delete(p)
        db.session.commit()
        return jsonify({"success": True})
    except Exception as exc:
        logger.exception("Failed to delete pin %s: %s", pin_id, exc)
        db.session.rollback()
        return jsonify({"success": False, "error": "delete_failed", "message": str(exc)}), 500

@app.route("/api/admin/delete_video", methods=["POST"])
def api_admin_delete_video():
    """Delete a video record and remove its file from uploads (admin only)."""
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    data = request.get_json() or {}
    video_id = data.get("video_id")
    if not video_id:
        return jsonify({"success": False, "error": "missing_video_id"}), 400
    v = Video.query.get(video_id)
    if not v:
        return jsonify({"success": False, "error": "video_not_found"}), 404

    # Build safe path (filename stored in DB already, so use it)
    filename = v.filename
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    try:
        # remove DB record first, then file
        db.session.delete(v)
        db.session.commit()
    except Exception as exc:
        logger.exception("DB delete failed for video %s: %s", video_id, exc)
        db.session.rollback()
        return jsonify({"success": False, "error": "delete_failed", "message": str(exc)}), 500

    # Try to remove file (best-effort). If file missing, it's okay.
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception as exc:
        # Log but return success because DB record is removed.
        logger.exception("Failed to remove video file %s: %s", path, exc)
        return jsonify({"success": True, "warning": "db_deleted_but_file_remove_failed", "message": str(exc)})
    return jsonify({"success": True})

# -------------- API: Files (NEW & admin) -------------
@app.route("/api/admin/upload_file", methods=["POST"])
def api_admin_upload_file():
    """Generic file upload (any file) — admin only. Saves to uploads/ and creates File record."""
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
@app.route("/api/admin/files")
def api_admin_files():
    """List uploaded non-video files (admin only)."""
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    rows = File.query.order_by(File.uploaded_at.desc()).all()
    data = [{"id": r.id, "title": r.title, "filename": r.filename, "uploaded_at": (r.uploaded_at.isoformat() if r.uploaded_at else None)} for r in rows]
    return jsonify(data)

@app.route("/api/admin/delete_file", methods=["POST"])
def api_admin_delete_file():
    """Delete a file record and remove its file from uploads (admin only)."""
    if not admin_auth_ok(request):
        return jsonify({"success": False, "error": "admin_auth_required"}), 403
    data = request.get_json() or {}
    file_id = data.get("file_id")
    if not file_id:
        return jsonify({"success": False, "error": "missing_file_id"}), 400
    frow = File.query.get(file_id)
    if not frow:
        return jsonify({"success": False, "error": "file_not_found"}), 404
    filename = frow.filename
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    try:
        db.session.delete(frow)
        db.session.commit()
    except Exception as exc:
        logger.exception("DB delete failed for file %s: %s", file_id, exc)
        db.session.rollback()
        return jsonify({"success": False, "error": "delete_failed", "message": str(exc)}), 500

    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception as exc:
        logger.exception("Failed to remove file %s: %s", path, exc)
        return jsonify({"success": True, "warning": "db_deleted_but_file_remove_failed", "message": str(exc)})
    return jsonify({"success": True})

@app.route("/api/files")
def api_files():
    """List uploaded files available to all users."""
    rows = File.query.order_by(File.uploaded_at.desc()).all()
    data = [{"id": r.id, "title": r.title, "filename": r.filename, "uploaded_at": (r.uploaded_at.isoformat() if r.uploaded_at else None)} for r in rows]
    return jsonify(data)

# ----- NEW: public file view route (serves inline for preview; no attachment header) -----
@app.route("/view/file/<int:file_id>")
def view_file(file_id):
    """Serve file inline so browser can preview (PDFs/images) but do not force-download.
       This is intentionally view-only; frontend should not show a download button.
    """
    frow = File.query.get(file_id)
    if not frow:
        return "Not found", 404
    filename = frow.filename
    # secure join to avoid path traversal
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if not os.path.exists(file_path):
        return "File missing", 404
    # send file inline; let send_from_directory set content-type
    resp = make_response(send_from_directory(app.config["UPLOAD_FOLDER"], filename))
    # prefer inline so browser opens the file if it can (pdf/images)
    resp.headers["Content-Disposition"] = f'inline; filename="{filename}"'
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp

# -------------- API: Payment ------------
@app.route("/api/payment/proof", methods=["POST"])
def api_payment_proof():
    name = request.form.get("name", "")
    email = request.form.get("email", "")
    course_title = request.form.get("course_title", "")
    f = request.files.get("proof")
    if not name or not f:
        return jsonify({"success": False, "error": "missing_fields"}), 400
    safe_name = secrets.token_hex(8) + "_" + secure_filename(f.filename)
    path = os.path.join(app.static_folder, safe_name)
    f.save(path)
    pay = Payment(name=name, email=email, course_title=course_title, proof_filename=safe_name, created_at=now())
    db.session.add(pay); db.session.commit()
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
