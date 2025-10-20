import os
import datetime
import threading
import time
import uuid
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, Response, abort, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis
import requests
from stem import Signal
from stem.control import Controller
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
import mimetypes
import io
from zoneinfo import ZoneInfo
from PIL import Image
import bleach

# ===============================================================
# ---- Flask app configuration ----
# ===============================================================
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "phasma_secret_change_me")
app.config["DEBUG"] = True
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/phasma"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# NOTE: flask.session is NOT used — no persistent cookies are set

# ===============================================================
# ---- Upload configuration ----
# ===============================================================
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png"}
ALLOWED_MIMETYPES = {"image/jpeg", "image/png"}
ALLOWED_IMAGE_FORMATS = {"PNG", "JPEG"}  # Pillow Image.format values
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# ---- Image resolution limits ----
MAX_IMAGE_WIDTH = 1920
MAX_IMAGE_HEIGHT = 1080
MAX_PIXELS = MAX_IMAGE_WIDTH * MAX_IMAGE_HEIGHT

# ---- MIME type mapping ----
SAFE_MIME_MAPPING = {
    "PNG": "image/png",
    "JPEG": "image/jpeg"
}

# ---- Authentication Token TTL ----
AUTH_TOKEN_TTL = 3600  # seconds = 1 hour

# --- TIME ---
TIMEZONE = ZoneInfo("Europe/Prague")

# ===============================================================
# ---- Database and Redis ----
# ===============================================================
db = SQLAlchemy(app)
r = redis.StrictRedis(host="127.0.0.1", port=6379, db=0, decode_responses=False)

# ===============================================================
# ---- Argon2 Hasher (secure password hashing) ----
# ===============================================================
argon2Hasher = PasswordHasher(
    time_cost=4,
    memory_cost=64 * 1024,  # 64 MB
    parallelism=1,
    hash_len=32,
    salt_len=16
)

# ===============================================================
# ---- Database Models ----
# ===============================================================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def format_time(self):
        utc_time = self.created_at.replace(tzinfo=ZoneInfo("UTC"))
        formated_time = utc_time.astimezone(TIMEZONE)
        return formated_time.strftime('%d.%m.%Y %H:%M:%S')

class Message(db.Model):
    id = db.Column(db.BigInteger, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)  # Encrypted message content
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)

    def get_plain(self):
        return decrypt_message(self.content)

    def format_time(self):
        utc_time = self.created_at.replace(tzinfo=ZoneInfo("UTC"))
        formated_time = utc_time.astimezone(TIMEZONE)
        return formated_time.strftime('%H:%M:%S')

    def as_text(self):
        ts = self.format_time()
        return f"[{ts}] {self.username}: {self.get_plain()}"

class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    filename = db.Column(db.String(256), unique=True, nullable=False, index=True)  # UUID-based filename
    original_filename = db.Column(db.String(256), nullable=False)
    filesize = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(50), nullable=False)  # Trusted MIME from Pillow validation
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)

    def format_time(self):
        utc_time = self.created_at.replace(tzinfo=ZoneInfo("UTC"))
        formated_time = utc_time.astimezone(TIMEZONE)
        return formated_time.strftime('%d.%m.%Y %H:%M:%S')

class Secret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=False)  # Encrypted with master key
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def format_time(self):
        utc_time = self.created_at.replace(tzinfo=ZoneInfo("UTC"))
        formated_time = utc_time.astimezone(TIMEZONE)
        return formated_time.strftime('%d.%m.%Y %H:%M:%S')

# ===============================================================
# ---- Master key management (FERNET_MASTER_KEY) ----
# ===============================================================
def load_master_fernet():
    key = os.environ.get("FERNET_MASTER_KEY")
    if not key:
        tmp = Fernet.generate_key().decode()
        print("[WARN] FERNET_MASTER_KEY not set. Generated TEMPORARY master key (local only).")
        key = tmp
    return Fernet(key.encode())

def set_secret_encrypted(name: str, plaintext: str):
    enc = master_fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")
    s = Secret.query.filter_by(name=name).first()
    if s:
        s.value = enc
    else:
        s = Secret(name=name, value=enc)
        db.session.add(s)
    db.session.commit()
    return s

def get_secret_decrypted(name: str):
    s = Secret.query.filter_by(name=name).first()
    if not s:
        return None
    try:
        return master_fernet.decrypt(s.value.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        print(f"[ERROR] Could not decrypt Secret {name} with current master key.")
        return None

# ===============================================================
# ---- Initialize database, master key, and data key ----
# ===============================================================
with app.app_context():
    db.create_all()
    print("[OK] Database tables created (if missing)")
    master_fernet = load_master_fernet()

    # Import tor_pass.txt if needed
    if Secret.query.filter_by(name="TOR_PASS_ENC").first() is None:
        if os.path.exists("tor_pass.txt"):
            with open("tor_pass.txt", "r", encoding="utf-8") as f:
                torpass = f.read().strip()
            if torpass:
                set_secret_encrypted("TOR_PASS_ENC", torpass)
                print("[INFO] Imported tor_pass.txt into DB (encrypted).")

    # Generate or load DATA_KEY
    data_key = get_secret_decrypted("DATA_KEY_ENC")
    if not data_key:
        new_key = Fernet.generate_key().decode()
        set_secret_encrypted("DATA_KEY_ENC", new_key)
        data_key = new_key
        print("[INFO] Generated new DATA_KEY and stored encrypted in DB.")
    data_fernet = Fernet(data_key.encode("utf-8"))

# ===============================================================
# ---- Upload folder initialization ----
# ===============================================================
def init_upload_folder():
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
        print(f"[OK] Created upload folder: {UPLOAD_FOLDER}")
    else:
        print(f"[OK] Upload folder exists: {UPLOAD_FOLDER}")

init_upload_folder()

# ===============================================================
# ---- Encryption helpers ----
# ===============================================================
def encrypt_message(plaintext: str) -> str:
    return data_fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

def decrypt_message(ciphertext: str) -> str:
    try:
        return data_fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return "[UNDECRYPTABLE MESSAGE]"

def encrypt_file(file_data: bytes) -> bytes:
    return data_fernet.encrypt(file_data)

def decrypt_file(encrypted_data: bytes) -> bytes:
    try:
        return data_fernet.decrypt(encrypted_data)
    except InvalidToken:
        return None

def get_tor_password():
    return get_secret_decrypted("TOR_PASS_ENC")

# ===============================================================
# --- TEXT sanitization ---
# ===============================================================
def sanitize_text(text: str) -> str:
    if not text:
        return ""
    #REMOVE all Html tags (keep text)
    sanitized = bleach.clean(
        text,
        tags= [],
        attributes= {},
        strip= True
        )
    return sanitized.strip()

# ===============================================================
# ---- Authentication token helpers ----
# ===============================================================
def generate_auth_token(username: str) -> tuple:
    """Generate ephemeral auth token. One session per user. Returns (token, old_token)."""
    old_token_bytes = r.get(f"user_session:{username}")
    old_token = old_token_bytes.decode("utf-8") if old_token_bytes else None
    
    # Revoke old token if exists
    if old_token:
        r.delete(f"auth_token:{old_token}")
    
    token = str(uuid.uuid4())
    r.setex(f"auth_token:{token}", AUTH_TOKEN_TTL, username.encode("utf-8"))
    r.setex(f"user_session:{username}", AUTH_TOKEN_TTL, token.encode("utf-8"))
    print(f"[OK] Auth token generated for {username}")
    return token, old_token

def verify_token(token: str) -> str or None:
    """Verify token and return username, or None if invalid/expired."""
    if not token:
        return None
    username_bytes = r.get(f"auth_token:{token}")
    if not username_bytes:
        return None
    return username_bytes.decode("utf-8")

def revoke_token(token: str):
    """Revoke token immediately (active logout)."""
    username_bytes = r.get(f"auth_token:{token}")
    if username_bytes:
        username = username_bytes.decode("utf-8")
        r.delete(f"user_session:{username}")
    r.delete(f"auth_token:{token}")
    print(f"[OK] Auth token revoked")

def extract_token_from_request() -> str or None:
    """Extract Bearer token from Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    return auth_header[7:]  # Remove "Bearer " prefix

# ===============================================================
# ---- Rate Limiter ----
# ===============================================================
def get_username_key():
    token = extract_token_from_request()
    username = verify_token(token)
    if username:
        return f"user:{username}"
    username_form = request.form.get("user", "").strip()
    if username_form:
        return f"form:{username_form}"
    return get_remote_address()

limiter = Limiter(
    app=app,
    key_func=get_username_key,
    storage_uri="redis://127.0.0.1:6379",
    default_limits=[]
)

# ===============================================================
# ---- Photo helpers ----
# ===============================================================
def validate_and_get_mime_type(file_data: bytes, original_filename: str) -> str or None:
    try:
        # Check file size
        if len(file_data) > MAX_FILE_SIZE:
            print(f"[WARN] File size exceeds MAX_FILE_SIZE")
            return None
        
        # Check extension (quick filter)
        if not original_filename or '.' not in original_filename:
            print(f"[WARN] Invalid filename format")
            return None
        
        ext = original_filename.rsplit('.', 1)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            print(f"[WARN] File extension '{ext}' not in ALLOWED_EXTENSIONS")
            return None
        
        # Open image with Pillow - validates bytes and structure
        img = Image.open(io.BytesIO(file_data))
        
        # Check image resulution BEFORE further processing
        if img.width > MAX_IMAGE_WIDTH or img.height > MAX_IMAGE_HEIGHT:
            print(f"[WARN] Image resulution {img.width}x{img.height} exceed maximum {MAX_IMAGE_WIDTH}x{MAX_IMAGE_HEIGHT}")
            return None
        
        # Check total px count 
        if img.width * img.height > MAX_PIXELS:
            print(f"[WARN] Total pixels {img.width * img.height} exceeds maximum {MAX_PIXELS}")
            return None
        
        # Get REAL image format from Pillow
        image_format = img.format
        if image_format not in ALLOWED_IMAGE_FORMATS:
            print(f"[WARN] Image format '{image_format}' not in ALLOWED_IMAGE_FORMATS")
            return None
        
        # Get trusted MIME type from mapping (NOT FROM CLIENT)
        mime_type = SAFE_MIME_MAPPING.get(image_format)
        if not mime_type:
            print(f"[ERROR] No MIME mapping for format '{image_format}'")
            return None
        
        print(f"[OK] Image validated: {img.width}x{img.height}, format={image_format}, mime={mime_type}")
        return mime_type
    
    except Exception as e:
        print(f"[WARN] Image validation failed: {e}")
        return None

def save_photo(username: str, file_obj) -> Photo or None:
    """Save encrypted photo to disk and create DB entry."""
    try:
        # Read file data
        file_data = file_obj.read()
        
        # Validate image: magic bytes, format, and get trusted MIME type
        mime_type = validate_and_get_mime_type(file_data, file_obj.filename)
        if not mime_type:
            return None
        
        # Generate unique filename (UUID)
        unique_filename = f"{uuid.uuid4()}.bin"
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        
        # Encrypt file data
        encrypted_data = encrypt_file(file_data)
        
        # Save encrypted file to disk
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Create database entry (with trusted MIME type)
        original_name = secure_filename(file_obj.filename)
        photo = Photo(
            username=username,
            filename=unique_filename,
            original_filename=original_name,
            filesize=len(file_data),
            mime_type=mime_type  # Trusted MIME from Pillow validation
        )
        db.session.add(photo)
        db.session.commit()
        
        print(f"[OK] Photo saved: {unique_filename} by {username}")
        return photo
    except Exception as e:
        print(f"[ERROR] Failed to save photo: {e}")
        return None

def load_photo(photo_id: int) -> tuple or None:
    """Load and decrypt photo from disk."""
    try:
        photo = Photo.query.filter_by(id=photo_id).first()
        if not photo:
            return None
        
        file_path = os.path.join(UPLOAD_FOLDER, photo.filename)
        if not os.path.exists(file_path):
            print(f"[ERROR] Photo file not found: {file_path}")
            return None
        
        # Read encrypted file
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt file data
        decrypted_data = decrypt_file(encrypted_data)
        if decrypted_data is None:
            print(f"[ERROR] Could not decrypt photo: {photo.filename}")
            return None
        
        return (decrypted_data, photo.mime_type, photo.original_filename)
    except Exception as e:
        print(f"[ERROR] Failed to load photo: {e}")
        return None

# ===============================================================
# ---- Tor SOCKS5 and ControlPort ----
# ===============================================================
SOCKS5_ADDR = "127.0.0.1:9050"
TOR_CONTROL_PORT = 9051
tor_session = None

def create_tor_session():
    s = requests.Session()
    s.proxies.update({
        "http": f"socks5h://{SOCKS5_ADDR}",
        "https": f"socks5h://{SOCKS5_ADDR}",
    })
    return s

def tor_control_available():
    import socket
    try:
        with socket.create_connection(("127.0.0.1", TOR_CONTROL_PORT), timeout=1):
            return True
    except Exception:
        return False

def rotate_tor_identity():
    """Rotate Tor identity via ControlPort."""
    global tor_session
    if not tor_control_available():
        print("[WARN] Tor ControlPort unavailable")
        return
    try:
        with Controller.from_port(port=TOR_CONTROL_PORT) as c:
            with app.app_context():
                torpass = get_tor_password()
            if not torpass:
                print("[WARN] TOR password not found in DB.")
                return
            c.authenticate(password=torpass)
            c.signal(Signal.NEWNYM)
            print("[INFO] -> Tor identity rotated")
            time.sleep(5)
            tor_session = create_tor_session()
    except Exception as e:
        print("[ERROR] Tor rotation failed:", e)

def fetch_via_tor(url, **kwargs):
    global tor_session
    if tor_session is None:
        tor_session = create_tor_session()
    return tor_session.get(url, timeout=15, **kwargs)

# ---- Background Tor rotation thread ----
def auto_rotate_tor(interval=10):
    while True:
        rotate_tor_identity()
        time.sleep(interval)

threading.Thread(target=auto_rotate_tor, args=(10,), daemon=True).start()

# ===============================================================
# ---- Message helpers ----
# ===============================================================
def save_message(username, content):
    #Sanitize message before encrypt...
    sanitized_content = sanitize_text(content)

    #skip empty message after sanitization
    if not sanitized_content:
        return None

    ciphertext = encrypt_message(sanitized_content)
    msg = Message(username=username, content=ciphertext)
    db.session.add(msg)
    db.session.commit()
    r.publish("chat", msg.as_text().encode("utf-8"))
    return msg

def _log_tor_ip_background():
    """Check and log Tor exit IP."""
    try:
        resp = fetch_via_tor("https://ifconfig.co/json")
        if resp.ok:
            print("[INFO] Outgoing request via Tor. Exit IP:", resp.json().get("ip"))
        else:
            print("[WARN] Tor fetch failed, status:", resp.status_code)
    except Exception as e:
        print("[ERROR] Tor request failed:", e)

def event_stream():
    """Stream chat messages via Server-Sent Events."""
    with app.app_context():
        last = Message.query.order_by(Message.created_at.desc()).limit(200).all()
        for m in reversed(last):
            yield f"data: {m.as_text()}\n\n"
    pubsub = r.pubsub(ignore_subscribe_messages=True)
    pubsub.subscribe("chat")
    for message in pubsub.listen():
        data = message.get("data")
        if isinstance(data, bytes):
            try:
                data = data.decode("utf-8")
            except Exception:
                data = str(data)
        yield f"data: {data}\n\n"

# ===============================================================
# ---- Auth Routes ----
# ===============================================================
@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per 15 minutes")
def register():
    """User registration route."""
    if request.method == "POST":
        username = request.form.get("user", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            return "Enter your username and password", 400

        if User.query.filter_by(username=username).first():
            return "A user with this name already EXISTS.", 400

        password_hash = argon2Hasher.hash(password)
        db.session.add(User(username=username, password_hash=password_hash))
        db.session.commit()
        return redirect("/login")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per 15 minutes")
def login():
    """User login route."""
    if request.method == "POST":
        username = request.form.get("user", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            return "Enter your username and password", 400

        user = User.query.filter_by(username=username).first()
        if not user:
            return "INCORRECT username or password", 400

        try:
            argon2Hasher.verify(user.password_hash, password)
            # Generate ephemeral auth token (one session per user)
            auth_token, old_token = generate_auth_token(username)
            old_token_exists = old_token is not None
            # Return token to client (store in memory, not cookies)
            return render_template("index.html", auth_token=auth_token, user=username, old_session=old_token_exists)
        except VerifyMismatchError:
            return "INCORRECT password", 400

    return render_template("login.html")

# ===============================================================
# ---- Chat message routes ----
# ===============================================================
@app.route("/post", methods=["POST"])
@limiter.limit("30 per minute")
def post():
    # Extract and verify token from Authorization header
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return abort(401)
    
    text = request.form.get("message", "").strip()
    if not text:
        return ("", 204)
    
    msg = save_message(username, text)
    if not msg:  # Message was empty after sanitization
        return ("", 204)

    def tor_rotate_and_log():
        rotate_tor_identity()
        _log_tor_ip_background()

    threading.Thread(target=tor_rotate_and_log, daemon=True).start()
    return ("", 204)

@app.route("/stream")
@limiter.limit("100 per minute")
def stream():
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return abort(401)
    
    return Response(event_stream(), mimetype="text/event-stream")

# ===============================================================
# ---- Photo upload and download routes ----
# ===============================================================
@app.route("/upload", methods=["POST"])
@limiter.limit("5 per hour")
def upload():
    """Upload photo route."""
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return abort(401)
    
    if "file" not in request.files:
        return "No file part", 400
    
    file = request.files["file"]
    if file.filename == "":
        return "No selected file", 400
    
    photo = save_photo(username, file)
    if not photo:
        return "Invalid file or file too large", 400
    
    # Notify chat with photo marker
    notification = f"[PHOTO_ID:{photo.id}]"
    save_message(username, notification)
    
    def tor_rotate_and_log():
        rotate_tor_identity()
        _log_tor_ip_background()
    
    threading.Thread(target=tor_rotate_and_log, daemon=True).start()
    return {"photo_id": photo.id}, 200

@app.route("/photo/<int:photo_id>")
def get_photo(photo_id: int):
    """Download decrypted photo (inline display, safe MIME type)."""
    result = load_photo(photo_id)
    if not result:
        return abort(404)
    
    decrypted_data, mime_type, original_filename = result
    
    # Create response with decrypted image data
    response = send_file(
        io.BytesIO(decrypted_data),
        mimetype=mime_type,
        as_attachment=False,  # Inline display for <img> tag
        download_name=original_filename
    )
    
    # Add strict CSP header to prevent XSS execution
    response.headers['Content-Security-Policy'] = "default-src 'none'; img-src 'self'"
    
    # Add additional safety headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    
    return response

@app.route("/logout", methods=["POST"])
def logout():
    """Logout route - revoke token immediately."""
    token = extract_token_from_request()
    if token:
        revoke_token(token)
    return "", 204

@app.route("/verify-session", methods=["GET"])
@limiter.limit("100 per minute")
def verify_session():
    """Verify if current session is still valid."""
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return jsonify({"valid": False}), 401
    return jsonify({"valid": True}), 200

@app.route("/")
def root():
    """Redirect root to login page."""
    return redirect("/login")

# ===============================================================
# ---- Startup ----
# ===============================================================
if __name__ == "__main__":
    print(f"[INFO] Starting Flask app on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
