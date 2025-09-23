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
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(TEMPLATES_DIR, exist_ok=True)

# Env-configurable (default admin PIN set to 811335 as requested)
ADMIN_PIN = os.environ.get("ADMIN_PIN", "811335")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", ADMIN_PIN)
ALLOWED_DEVICE_HASH = os.environ.get("ALLOWED_DEVICE_HASH")   # optional lock-to-device
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_urlsafe(24))
MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 200 * 1024 * 1024))
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") == "1"

# Render/Postgres DB you gave
# (You can also set DATABASE_URL as env variable and use that instead)
POSTGRES_URL = (
    "postgresql://crypto_trading_ef73_user:ExqngrM4GrJX6FmefoA1g3BRPu2kF0tk@"
    "dpg-d37inupr0fns739ha5r0-a.oregon-postgres.render.com/crypto_trading_ef73"
)

# --------------- App setup ---------------
app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", POSTGRES_URL)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.secret_key = SECRET_KEY

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
    # if pin revoked and not admin -> kill session
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
    # Only mark cookie secure / SameSite=None when the current request is secure.
    # This avoids cookies being dropped when running over plain HTTP (local dev).
    samesite_val = "None" if COOKIE_SECURE and request.is_secure else "Lax"
    secure_flag = bool(COOKIE_SECURE and request.is_secure)
    resp.set_cookie("session_token", token, httponly=True, samesite=samesite_val, secure=secure_flag, path="/")
    return resp

# -------------- Init DB & ensure admin PIN exists & non-revocable -----------------
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
    # If admin PIN -> do NOT revoke. Update assigned device (admin non-revocable).
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
    # Prevent admin PIN from being revoked
    if p.pin == ADMIN_PIN:
        return jsonify({"success": False, "error": "cannot_revoke_admin_pin", "message": "Admin PIN cannot be revoked."}), 403
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
    # Warning: allow deleting admin pin only if explicitly desired - here we prevent delete of admin pin
    if p.pin == ADMIN_PIN:
        return jsonify({"success": False, "error": "cannot_delete_admin_pin", "message": "Admin PIN cannot be deleted."}), 403

    # Remove any sessions referencing this pin first (prevents FK constraint errors)
    try:
        Session.query.filter_by(pin_id=p.id).delete()
        db.session.commit()
    except Exception:
        db.session.rollback()

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
        return jsonify({"success": True, "warning": "db_deleted_but_file_remove_failed", "message": str(exc)})
    return jsonify({"success": True})
