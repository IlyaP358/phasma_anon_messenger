import os
import datetime
import threading
import time
import uuid
import re
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, Response, abort, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
load_dotenv()
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
# ---- PRODUCTION vs DEVELOPMENT MODE ----
# ===============================================================
# Set FLASK_ENV=production for production deployment
# In development mode (default), security requirements are OPTIONAL:
# - FLASK_SECRET, REDIS_PASSWORD, FERNET_MASTER_KEY are optional
# - Temporary keys are generated with warnings
# 
# In production mode, ALL security variables are REQUIRED
# ===============================================================

# ===============================================================
# ---- Flask app configuration ----
# ===============================================================
app = Flask(__name__)

# SECRET_KEY configuration
secret_key = os.environ.get("FLASK_SECRET")
is_production = os.environ.get("FLASK_ENV") == "production"

if not secret_key:
    if is_production:
        raise RuntimeError("[CRITICAL] FLASK_SECRET must be set in production mode!")
    else:
        print("[WARN] FLASK_SECRET not set. Using temporary key (development only!)")
        secret_key = "dev_secret_key_change_in_production"

app.secret_key = secret_key

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

# ---- Username/Password validation ----
USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 32
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')

# ---- Message limit for event stream ----
MESSAGE_HISTORY_LIMIT = 50

# ---- Tor rotation settings ----
TOR_ROTATION_INTERVAL = 300  # 5 minutes
TOR_ROTATION_MESSAGE_THRESHOLD = 30  # Rotate after N messages

# --- TIME ---
TIMEZONE = ZoneInfo("Europe/Prague")

# ===============================================================
# ---- Database and Redis (with authentication) ----
# ===============================================================
db = SQLAlchemy(app)

# Redis password (optional for development, required for production)
redis_password = os.environ.get("REDIS_PASSWORD")

# Determine if we're in production mode
is_production = os.environ.get("FLASK_ENV") == "production"

if is_production and not redis_password:
    raise RuntimeError("[CRITICAL] REDIS_PASSWORD must be set in production mode!")

# Create Redis connection with / without password
if redis_password:
    r = redis.StrictRedis(
        host="127.0.0.1",
        port=6379,
        db=0,
        password=redis_password,
        decode_responses=False
    )
else:
    print("[WARN] Running Redis WITHOUT password (development mode only!)")
    r = redis.StrictRedis(
        host="127.0.0.1",
        port=6379,
        db=0,
        decode_responses=False
    )

# Test Redis connection
try:
    r.ping()
    if redis_password:
        print("[OK] Redis connection established with authentication")
    else:
        print("[OK] Redis connection established (NO PASSWORD - dev mode)")
except redis.ConnectionError as e:
    raise RuntimeError(f"[CRITICAL] Redis connection failed: {e}")

# ===============================================================
# ---- Argon2 Hasher (strengthened parameters) ----
# ===============================================================
argon2Hasher = PasswordHasher(
    time_cost=4,
    memory_cost=256 * 1024,  # 256 MB
    parallelism=2,
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
    username = db.Column(db.String(100), nullable=False, index=True)  # Added index
    content = db.Column(db.Text, nullable=False)  # Encrypted message content
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)

    # Composite index for username + created_at queries
    __table_args__ = (
        db.Index('ix_message_username_created', 'username', 'created_at'),
    )

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
    username = db.Column(db.String(100), nullable=False, index=True)  # Added index
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
        if is_production:
            raise RuntimeError("[CRITICAL] FERNET_MASTER_KEY must be set in production mode!")
        else:
            # Generate temporary key for development
            tmp = Fernet.generate_key().decode()
            print("[WARN] FERNET_MASTER_KEY not set. Generated TEMPORARY key (development only).")
            print(f"[WARN] To persist data, add to .env: FERNET_MASTER_KEY={tmp}")
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

    # Import Tor password from environment variable (NOT from file)
    if Secret.query.filter_by(name="TOR_PASS_ENC").first() is None:
        tor_pass_env = os.environ.get("TOR_CONTROL_PASSWORD")
        if tor_pass_env:
            set_secret_encrypted("TOR_PASS_ENC", tor_pass_env)
            print("[INFO] Imported TOR_CONTROL_PASSWORD from environment (encrypted).")
        else:
            print("[WARN] TOR_CONTROL_PASSWORD not set. Tor rotation will be disabled.")

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
# ---- Validation helpers ----
# ===============================================================
def validate_username(username: str) -> tuple[bool, str]:
    """Validate username format and length. Returns (is_valid, error_message)."""
    if not username:
        return False, "Username cannot be empty"
    
    if len(username) < USERNAME_MIN_LENGTH:
        return False, f"Username must be at least {USERNAME_MIN_LENGTH} characters"
    
    if len(username) > USERNAME_MAX_LENGTH:
        return False, f"Username must not exceed {USERNAME_MAX_LENGTH} characters"
    
    if not USERNAME_PATTERN.match(username):
        return False, "Username can only contain letters, numbers, underscores, and hyphens"
    
    return True, ""

def validate_password(password: str) -> tuple[bool, str]:
    """Validate password length. Returns (is_valid, error_message)."""
    if not password:
        return False, "Password cannot be empty"
    
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters"
    
    if len(password) > PASSWORD_MAX_LENGTH:
        return False, f"Password must not exceed {PASSWORD_MAX_LENGTH} characters"
    
    return True, ""

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
    # REMOVE all HTML tags (keep text)
    sanitized = bleach.clean(
        text,
        tags=[],
        attributes={},
        strip=True
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
    """Extract Bearer token from Authorization header or POST body."""
    # Try Authorization header first
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]  # Remove "Bearer " prefix
    
    # Fallback to POST body
    if request.method == "POST":
        token = request.form.get("token", "").strip()
        if token:
            return token
    
    return None

# ===============================================================
# ---- Rate Limiter ----
# ===============================================================
def get_username_key():
    """Get rate limit key based on authenticated user or IP address."""
    token = extract_token_from_request()
    username = verify_token(token)
    if username:
        return f"user:{username}"
    return f"ip:{get_remote_address()}"

# Build storage URI based on whether Redis has password
if redis_password:
    storage_uri = f"redis://:{redis_password}@127.0.0.1:6379"
else:
    storage_uri = "redis://127.0.0.1:6379"

limiter = Limiter(
    app=app,
    key_func=get_username_key,
    storage_uri=storage_uri,
    default_limits=[]
)

# ===============================================================
# ---- Rate Limit Error Handler ----
# ===============================================================
@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded errors."""
    return jsonify({
        "error": "Rate limit exceeded",
        "message": "[ERROR 429] You are sending requests too quickly. Please try again later."
    }), 429

# ===============================================================
# ---- Security Headers ----
# ===============================================================
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    # Skip if CSP already set (e.g., for /photo endpoint)
    if 'Content-Security-Policy' not in response.headers:
        # CSP for HTML pages
        if response.mimetype == 'text/html' or request.path in ['/', '/login', '/register']:
            response.headers['Content-Security-Policy'] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self'; "
                "connect-src 'self';"
            )
    
    # Security headers for all responses
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    
    return response

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
        
        # Check image resolution BEFORE further processing
        if img.width > MAX_IMAGE_WIDTH or img.height > MAX_IMAGE_HEIGHT:
            print(f"[WARN] Image resolution {img.width}x{img.height} exceeds maximum {MAX_IMAGE_WIDTH}x{MAX_IMAGE_HEIGHT}")
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
# ---- Tor SOCKS5 and ControlPort (Thread-Safe) ----
# ===============================================================
SOCKS5_ADDR = "127.0.0.1:9050"
TOR_CONTROL_PORT = 9051

# Thread-local storage for Tor sessions
thread_local = threading.local()

def create_tor_session():
    """Create a new Tor session with SOCKS5 proxy."""
    s = requests.Session()
    s.proxies.update({
        "http": f"socks5h://{SOCKS5_ADDR}",
        "https": f"socks5h://{SOCKS5_ADDR}",
    })
    return s

def get_tor_session():
    """Get thread-local Tor session."""
    if not hasattr(thread_local, 'session'):
        thread_local.session = create_tor_session()
    return thread_local.session

def tor_control_available():
    """Check if Tor ControlPort is available."""
    import socket
    try:
        with socket.create_connection(("127.0.0.1", TOR_CONTROL_PORT), timeout=1):
            return True
    except Exception:
        return False

def rotate_tor_identity():
    """Rotate Tor identity via ControlPort."""
    if not tor_control_available():
        print("[WARN] Tor ControlPort unavailable")
        return
    try:
        with Controller.from_port(port=TOR_CONTROL_PORT) as c:
            with app.app_context():
                torpass = get_tor_password()
            if not torpass:
                print("[WARN] TOR password not found in DB. Rotation disabled.")
                return
            c.authenticate(password=torpass)
            c.signal(Signal.NEWNYM)
            print("[INFO] -> Tor identity rotated")
            time.sleep(5)
            
            # Clear thread-local session to force recreation
            if hasattr(thread_local, 'session'):
                delattr(thread_local, 'session')
    except Exception as e:
        print("[ERROR] Tor rotation failed:", e)

def fetch_via_tor(url, **kwargs):
    """Fetch URL via Tor using thread-local session."""
    session = get_tor_session()
    return session.get(url, timeout=15, **kwargs)

def increment_message_count():
    """Increment message counter for Tor rotation."""
    try:
        count = r.incr("tor:message_count")
        if count >= TOR_ROTATION_MESSAGE_THRESHOLD:
            print(f"[INFO] Message threshold reached ({count} messages). Rotating Tor...")
            threading.Thread(target=rotate_tor_identity, daemon=True).start()
            r.set("tor:message_count", 0)
    except Exception as e:
        print(f"[ERROR] Failed to increment message count: {e}")

# ---- Background Tor rotation thread ----
def auto_rotate_tor(interval=TOR_ROTATION_INTERVAL):
    """Background thread for periodic Tor rotation."""
    while True:
        time.sleep(interval)
        rotate_tor_identity()
        r.set("tor:message_count", 0)  # Reset counter after time-based rotation

threading.Thread(target=auto_rotate_tor, daemon=True).start()

# ===============================================================
# ---- Message helpers ----
# ===============================================================
def save_message(username, content):
    """Save message to database (sanitized and encrypted)."""
    # Sanitize message before encrypt
    sanitized_content = sanitize_text(content)

    # Skip empty message after sanitization
    if not sanitized_content:
        return None

    ciphertext = encrypt_message(sanitized_content)
    msg = Message(username=username, content=ciphertext)
    db.session.add(msg)
    db.session.commit()
    r.publish("chat", msg.as_text().encode("utf-8"))
    
    # Increment message count for Tor rotation
    increment_message_count()
    
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
        # Load last N messages
        last = Message.query.order_by(Message.created_at.desc()).limit(MESSAGE_HISTORY_LIMIT).all()
        for m in reversed(last):
            yield f"data: {m.as_text()}\n\n"
    
    # Subscribe to Redis pubsub for new messages
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

        # Validate username
        valid_username, username_error = validate_username(username)
        if not valid_username:
            return username_error, 400

        # Validate password
        valid_password, password_error = validate_password(password)
        if not valid_password:
            return password_error, 400

        # Check if user exists
        if User.query.filter_by(username=username).first():
            return "A user with this name already EXISTS.", 400

        # Hash password and create user
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

        # Validate username format
        valid_username, username_error = validate_username(username)
        if not valid_username:
            return "INCORRECT username or password", 400

        # Validate password format
        valid_password, password_error = validate_password(password)
        if not valid_password:
            return "INCORRECT username or password", 400

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
            return "INCORRECT username or password", 400

    return render_template("login.html")

# ===============================================================
# ---- Chat message routes ----
# ===============================================================
@app.route("/post", methods=["POST"])
@limiter.limit("30 per minute")
def post():
    """Post message to chat."""
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

    return ("", 204)

@app.route("/stream")
@limiter.limit("100 per minute")
def stream():
    """Server-Sent Events stream for chat messages."""
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
        return "[ERROR] invalid file or file too large \n max photo resolution is 1920x1080", 400
    
    # Notify chat with photo marker
    notification = f"[PHOTO_ID:{photo.id}]"
    save_message(username, notification)
    
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
# Debug mode is OFF by default (only enabled via environment variable)
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "0") == "1"

if __name__ == "__main__":
    print(f"[INFO] Starting Flask app on http://127.0.0.1:5000")
    print(f"[INFO] Debug mode: {app.config['DEBUG']}")
    app.run(host="127.0.0.1", port=5000, debug=app.config["DEBUG"])
