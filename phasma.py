import os
import datetime
import threading
import time
import uuid
import re
import secrets
import logging
import json
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, Response, abort, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
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
import hmac
import hashlib

# ===============================================================
# ---- PRODUCTION vs DEVELOPMENT MODE ----
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

# ===============================================================
# ---- Disable Flask/Werkzeug logging ----
# ===============================================================
if is_production:
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    log.disabled = True
else:
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.WARNING)

# ===============================================================
# ---- CORS Configuration ----
# ===============================================================
if is_production:
    CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "https://yourdomain.com").split(",")
    CORS(app, origins=CORS_ORIGINS, supports_credentials=True)
    print(f"[OK] CORS enabled for origins: {CORS_ORIGINS}")
else:
    CORS(app, origins=["http://localhost:5000", "http://127.0.0.1:5000"], supports_credentials=True)
    print("[OK] CORS enabled for localhost (development mode)")

# ===============================================================
# ---- Upload configuration ----
# ===============================================================
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png"}
ALLOWED_MIMETYPES = {"image/jpeg", "image/png"}
ALLOWED_IMAGE_FORMATS = {"PNG", "JPEG"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MIN_FILE_SIZE = 1024 # 1 KB minimum

MAX_IMAGE_WIDTH = 2560
MAX_IMAGE_HEIGHT = 2560
MAX_PIXELS = MAX_IMAGE_WIDTH * MAX_IMAGE_HEIGHT

SAFE_MIME_MAPPING = {
    "PNG": "image/png",
    "JPEG": "image/jpeg"
}

AUTH_TOKEN_TTL = 3600  # seconds = 1 hour

USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 32
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')

MESSAGE_HISTORY_LIMIT = 50
MAX_MESSAGE_LENGTH = 5000

PHOTO_URL_TTL = 86400  # 24 hours
SIGNED_URL_SECRET = None

TOR_ROTATION_INTERVAL = 300  # 5 minutes
TOR_ROTATION_MESSAGE_THRESHOLD = 30

TIMEZONE = ZoneInfo("Europe/Prague")

# ===============================================================
# ---- Database and Redis ----
# ===============================================================
db = SQLAlchemy(app)

redis_password = os.environ.get("REDIS_PASSWORD")

if is_production and not redis_password:
    raise RuntimeError("[CRITICAL] REDIS_PASSWORD must be set in production mode!")

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

try:
    r.ping()
    if redis_password:
        print("[OK] Redis connection established with authentication")
    else:
        print("[OK] Redis connection established (NO PASSWORD - dev mode)")
except redis.ConnectionError as e:
    raise RuntimeError(f"[CRITICAL] Redis connection failed: {e}")

# ===============================================================
# ---- Argon2 Hasher ----
# ===============================================================
argon2Hasher = PasswordHasher(
    time_cost=4,
    memory_cost=256 * 1024,
    parallelism=2,
    hash_len=32,
    salt_len=16
)

DUMMY_HASH = argon2Hasher.hash("dummy_password_for_timing_attack_prevention")

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
    username = db.Column(db.String(100), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), nullable=False, default='text', index=True)  # 'text' or 'photo'
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)

    __table_args__ = (
        db.Index('ix_message_username_created', 'username', 'created_at'),
    )

    def get_plain(self):
        try:
            decrypted = data_fernet.decrypt(self.content.encode("utf-8")).decode("utf-8")
            
            if self.message_type == 'photo':
                # Для фото content - это JSON с photo_id
                return json.loads(decrypted)
            else:
                # Для текста - просто текст
                return decrypted
        except (InvalidToken, json.JSONDecodeError) as e:
            print(f"[ERROR] Failed to decrypt/parse message {self.id}: {e}")
            return "[UNDECRYPTABLE MESSAGE]"

    def format_time(self):
        utc_time = self.created_at.replace(tzinfo=ZoneInfo("UTC"))
        formated_time = utc_time.astimezone(TIMEZONE)
        return formated_time.strftime('%H:%M:%S')

    def as_text(self):
        ts = self.format_time()
        plain = self.get_plain()
        
        if self.message_type == 'photo':
            if isinstance(plain, dict):
                return f"[{ts}] {self.username}: [PHOTO:{plain.get('photo_id')}]"
            return f"[{ts}] {self.username}: [PHOTO]"
        else:
            return f"[{ts}] {self.username}: {plain}"

class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, index=True)
    filename = db.Column(db.String(256), unique=True, nullable=False, index=True)
    photo_token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    filesize = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)

    def format_time(self):
        utc_time = self.created_at.replace(tzinfo=ZoneInfo("UTC"))
        formated_time = utc_time.astimezone(TIMEZONE)
        return formated_time.strftime('%d.%m.%Y %H:%M:%S')

class Secret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def format_time(self):
        utc_time = self.created_at.replace(tzinfo=ZoneInfo("UTC"))
        formated_time = utc_time.astimezone(TIMEZONE)
        return formated_time.strftime('%d.%m.%Y %H:%M:%S')

# ===============================================================
# ---- Master key management ----
# ===============================================================
def load_master_fernet():
    key = os.environ.get("FERNET_MASTER_KEY")
    if not key:
        if is_production:
            raise RuntimeError("[CRITICAL] FERNET_MASTER_KEY must be set in production mode!")
        else:
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
# ---- Initialize database ----
# ===============================================================
with app.app_context():
    db.create_all()
    print("[OK] Database tables created (if missing)")
    master_fernet = load_master_fernet()

    if Secret.query.filter_by(name="TOR_PASS_ENC").first() is None:
        tor_pass_env = os.environ.get("TOR_CONTROL_PASSWORD")
        if tor_pass_env:
            set_secret_encrypted("TOR_PASS_ENC", tor_pass_env)
            print("[INFO] Imported TOR_CONTROL_PASSWORD from environment (encrypted).")
        else:
            print("[WARN] TOR_CONTROL_PASSWORD not set. Tor rotation will be disabled.")

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
# ---- Text sanitization ----
# ===============================================================
def sanitize_text(text: str) -> str:
    if not text:
        return ""
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
def get_client_ip_subnet() -> str:
    ip = get_remote_address()
    if not ip:
        return "0.0.0"
    if '.' in ip:
        octets = ip.split('.')
        return '.'.join(octets[:3])
    if ':' in ip:
        segments = ip.split(':')
        return ':'.join(segments[:3])
    return "0.0.0"

def generate_auth_token(username: str) -> tuple:
    old_token_bytes = r.get(f"user_session:{username}")
    old_token = old_token_bytes.decode("utf-8") if old_token_bytes else None
    
    token = str(uuid.uuid4())
    ip_subnet = get_client_ip_subnet()
    token_data = f"{username}|{ip_subnet}"
    
    pipe = r.pipeline()
    pipe.multi()
    
    if old_token:
        pipe.delete(f"auth_token:{old_token}")
    
    pipe.setex(f"auth_token:{token}", AUTH_TOKEN_TTL, token_data.encode("utf-8"))
    pipe.setex(f"user_session:{username}", AUTH_TOKEN_TTL, token.encode("utf-8"))
    pipe.execute()
    
    print(f"[OK] Auth token generated for {username} from subnet {ip_subnet}")
    return token, old_token

def verify_token(token: str) -> str or None:
    if not token:
        return None
    
    token_data_bytes = r.get(f"auth_token:{token}")
    if not token_data_bytes:
        return None
    
    token_data = token_data_bytes.decode("utf-8")
    
    if '|' not in token_data:
        return token_data
    
    username, stored_subnet = token_data.split('|', 1)
    current_subnet = get_client_ip_subnet()
    
    if stored_subnet != current_subnet:
        print(f"[SECURITY] IP subnet mismatch for {username}: stored={stored_subnet}, current={current_subnet}")
        revoke_token(token)
        return None
    
    return username

def revoke_token(token: str):
    username_bytes = r.get(f"auth_token:{token}")
    if username_bytes:
        username = username_bytes.decode("utf-8")
        r.delete(f"user_session:{username}")
    r.delete(f"auth_token:{token}")
    print(f"[OK] Auth token revoked")

def extract_token_from_request() -> str or None:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    
    if request.method == "POST":
        token = request.form.get("token", "").strip()
        if token:
            return token
    
    return None

# ===============================================================
# ---- Nonce generation for CSP ----
# ===============================================================
def generate_nonce():
    return secrets.token_urlsafe(16)

# ===============================================================
# ---- Rate Limiter ----
# ===============================================================
def get_username_key():
    token = extract_token_from_request()
    username = verify_token(token)
    if username:
        return f"user:{username}"
    return f"ip:{get_remote_address()}"

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
    return jsonify({
        "error": "Rate limit exceeded",
        "message": "[ERROR 429] You are sending requests too quickly. Please try again later."
    }), 429

# ===============================================================
# ---- HTTPS Enforcement ----
# ===============================================================
@app.before_request
def enforce_https():
    http_allow = os.environ.get("HTTP_ALLOW", "0") == "1"
    
    if is_production and not request.is_secure and not http_allow:
        return jsonify({"error": "HTTPS required"}), 403
    
    if is_production and http_allow and not request.is_secure:
        if not hasattr(enforce_https, '_warning_shown'):
            print("[WARN] HTTP_ALLOW is enabled in production mode! This is insecure for public deployment.")
            enforce_https._warning_shown = True

# ===============================================================
# ---- Security Headers ----
# ===============================================================
@app.after_request
def add_security_headers(response):
    nonce = getattr(request, '_csp_nonce', None)
    
    if 'Content-Security-Policy' not in response.headers:
        if response.mimetype == 'text/html' or request.path in ['/', '/login', '/register']:
            if nonce:
                response.headers['Content-Security-Policy'] = (
                    f"default-src 'self'; "
                    f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
                    f"style-src 'self' 'unsafe-inline'; "
                    f"img-src 'self'; "
                    f"connect-src 'self';"
                )
            else:
                response.headers['Content-Security-Policy'] = (
                    "default-src 'self'; "
                    "script-src 'self' https://cdn.jsdelivr.net; "
                    "style-src 'self' 'unsafe-inline'; "
                    "img-src 'self'; "
                    "connect-src 'self';"
                )
    
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    
    if is_production:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# ===============================================================
# ---- Photo helpers ----
# ===============================================================
def validate_and_get_mime_type(file_data: bytes, original_filename: str) -> str or None:
    try:
        if len(file_data) > MAX_FILE_SIZE:
            print(f"[WARN] File size exceeds MAX_FILE_SIZE")
            return None

        if len(file_data) < MIN_FILE_SIZE:
            print(f"[WARN] File size too small: {len(file_data)} bytes")
            return None        
        
        if not original_filename or '.' not in original_filename:
            print(f"[WARN] Invalid filename format")
            return None
        
        ext = original_filename.rsplit('.', 1)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            print(f"[WARN] File extension '{ext}' not in ALLOWED_EXTENSIONS")
            return None
        
        img = Image.open(io.BytesIO(file_data))
        
        if img.width > MAX_IMAGE_WIDTH or img.height > MAX_IMAGE_HEIGHT:
            print(f"[WARN] Image resolution {img.width}x{img.height} exceeds maximum")
            return None
        
        if img.width * img.height > MAX_PIXELS:
            print(f"[WARN] Total pixels exceeds maximum")
            return None
        
        image_format = img.format
        if image_format not in ALLOWED_IMAGE_FORMATS:
            print(f"[WARN] Image format '{image_format}' not allowed")
            return None
        
        mime_type = SAFE_MIME_MAPPING.get(image_format)
        if not mime_type:
            print(f"[ERROR] No MIME mapping for format '{image_format}'")
            return None
        
        print(f"[OK] Image validated: {img.width}x{img.height}, format={image_format}")
        return mime_type
    
    except Exception as e:
        print(f"[WARN] Image validation failed: {e}")
        return None

# ===============================================================
# ---- Photo Signed URL helpers ----
# ===============================================================
def get_or_create_signed_url_secret():
    global SIGNED_URL_SECRET
    if SIGNED_URL_SECRET:
        return SIGNED_URL_SECRET
    
    with app.app_context():
        secret = get_secret_decrypted("SIGNED_URL_SECRET")
        if not secret:
            secret = secrets.token_urlsafe(32)
            set_secret_encrypted("SIGNED_URL_SECRET", secret)
            print("[INFO] Generated new SIGNED_URL_SECRET")
        SIGNED_URL_SECRET = secret
        return secret

def generate_signed_photo_url(photo_token: str) -> dict:
    secret = get_or_create_signed_url_secret()
    expiration = int(time.time()) + PHOTO_URL_TTL
    
    message = f"{photo_token}:{expiration}"
    signature = hmac.new(
        secret.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return {
        "token": photo_token,
        "signature": signature,
        "expires": expiration
    }

def verify_signed_photo_url(photo_token: str, signature: str, expiration: str) -> bool:
    try:
        secret = get_or_create_signed_url_secret()
        exp_timestamp = int(expiration)
        
        if time.time() > exp_timestamp:
            print(f"[WARN] Signed URL expired: {photo_token}")
            return False
        
        message = f"{photo_token}:{exp_timestamp}"
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            print(f"[WARN] Invalid signature for photo: {photo_token}")
            return False
        
        return True
    except Exception as e:
        print(f"[ERROR] Signature verification failed: {e}")
        return False

def save_photo(username: str, file_obj) -> tuple or None:
    try:
        file_data = file_obj.read()
        
        mime_type = validate_and_get_mime_type(file_data, file_obj.filename)
        if not mime_type:
            return None
        
        unique_filename = f"{secrets.token_urlsafe(32)}.bin"
        photo_token = secrets.token_urlsafe(24)
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        
        encrypted_data = encrypt_file(file_data)
        
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Создаем запись Photo
        photo = Photo(
            username=username,
            filename=unique_filename,
            photo_token=photo_token,
            filesize=len(file_data),
            mime_type=mime_type
        )
        db.session.add(photo)
        db.session.flush()  # Получаем photo.id
        
        # Создаем запись Message с типом 'photo'
        photo_data = json.dumps({
            "photo_id": photo.id,
            "photo_token": photo_token
        })
        encrypted_content = encrypt_message(photo_data)
        
        message = Message(
            username=username,
            content=encrypted_content,
            message_type='photo',
            created_at=photo.created_at  # Синхронизируем время
        )
        db.session.add(message)
        db.session.commit()
        
        print(f"[OK] Photo saved: {unique_filename} by {username}, Message ID: {message.id}")
        return (photo, message)
        
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Failed to save photo: {e}")
        return None

def load_photo_by_token(photo_token: str) -> tuple or None:
    try:
        photo = Photo.query.filter_by(photo_token=photo_token).first()
        if not photo:
            return None
        
        file_path = os.path.join(UPLOAD_FOLDER, photo.filename)
        if not os.path.exists(file_path):
            print(f"[ERROR] Photo file not found: {file_path}")
            return None
        
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = decrypt_file(encrypted_data)
        if decrypted_data is None:
            print(f"[ERROR] Could not decrypt photo: {photo.filename}")
            return None
        
        return (decrypted_data, photo.mime_type)
    except Exception as e:
        print(f"[ERROR] Failed to load photo: {e}")
        return None

# ===============================================================
# ---- Tor helpers ----
# ===============================================================
SOCKS5_ADDR = "127.0.0.1:9050"
TOR_CONTROL_PORT = 9051

thread_local = threading.local()

def create_tor_session():
    s = requests.Session()
    s.proxies.update({
        "http": f"socks5h://{SOCKS5_ADDR}",
        "https": f"socks5h://{SOCKS5_ADDR}",
    })
    return s

def get_tor_session():
    if not hasattr(thread_local, 'session'):
        thread_local.session = create_tor_session()
    return thread_local.session

def tor_control_available():
    import socket
    try:
        with socket.create_connection(("127.0.0.1", TOR_CONTROL_PORT), timeout=1):
            return True
    except Exception:
        return False

def rotate_tor_identity():
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
            
            if hasattr(thread_local, 'session'):
                delattr(thread_local, 'session')
    except Exception as e:
        print("[ERROR] Tor rotation failed:", e)

def fetch_via_tor(url, **kwargs):
    session = get_tor_session()
    return session.get(url, timeout=15, **kwargs)

def increment_message_count():
    try:
        count = r.incr("tor:message_count")
        if count >= TOR_ROTATION_MESSAGE_THRESHOLD:
            print(f"[INFO] Message threshold reached ({count} messages). Rotating Tor...")
            threading.Thread(target=rotate_tor_identity, daemon=True).start()
            r.set("tor:message_count", 0)
    except Exception as e:
        print(f"[ERROR] Failed to increment message count: {e}")

def auto_rotate_tor(interval=TOR_ROTATION_INTERVAL):
    while True:
        time.sleep(interval)
        rotate_tor_identity()
        r.set("tor:message_count", 0)

threading.Thread(target=auto_rotate_tor, daemon=True).start()

# ===============================================================
# ---- Message helpers ----
# ===============================================================
def save_message(username, content):
    """Сохраняет текстовое сообщение"""
    sanitized_content = sanitize_text(content)

    if not sanitized_content:
        return None
    
    if len(sanitized_content) > MAX_MESSAGE_LENGTH:
        return None

    ciphertext = encrypt_message(sanitized_content)
    msg = Message(
        username=username, 
        content=ciphertext,
        message_type='text'
    )
    db.session.add(msg)
    db.session.commit()
    
    # Публикуем в Redis
    ts = msg.format_time()
    message_text = f"[{ts}] {username}: {sanitized_content}"
    r.publish("chat", message_text.encode("utf-8"))
    
    increment_message_count()
    
    return msg

def format_message_for_sse(msg: Message) -> str:
    """Форматирует сообщение для SSE с подписанными URL для фото"""
    ts = msg.format_time()
    
    if msg.message_type == 'photo':
        plain = msg.get_plain()
        if isinstance(plain, dict) and 'photo_id' in plain:
            photo_id = plain['photo_id']
            photo = Photo.query.filter_by(id=photo_id).first()
            
            if photo:
                signed_data = generate_signed_photo_url(photo.photo_token)
                photo_url = f"/photo/{signed_data['token']}?sig={signed_data['signature']}&exp={signed_data['expires']}"
                return f"[{ts}] {msg.username}: [PHOTO:{photo_id}:{photo_url}]"
            else:
                return f"[{ts}] {msg.username}: [PHOTO:{photo_id}]"
        return f"[{ts}] {msg.username}: [PHOTO]"
    else:
        # Текстовое сообщение
        plain = msg.get_plain()
        return f"[{ts}] {msg.username}: {plain}"

def event_stream():
    """SSE stream - только новые сообщения в реальном времени.
    История загружается через /history endpoint!"""
    
    # Подписываемся на Redis pub/sub для новых сообщений
    pubsub = r.pubsub(ignore_subscribe_messages=True)
    pubsub.subscribe("chat")
    
    # Слушаем только новые сообщения
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
@limiter.limit("5 per 15 minutes", methods=["POST"])
def register():
    if request.method == "POST":
        username = request.form.get("user", "").strip()
        password = request.form.get("password", "").strip()

        valid_username, username_error = validate_username(username)
        if not valid_username:
            try:
                argon2Hasher.verify(DUMMY_HASH, password)
            except:
                pass
            return username_error, 400

        valid_password, password_error = validate_password(password)
        if not valid_password:
            try:
                argon2Hasher.verify(DUMMY_HASH, password)
            except:
                pass
            return password_error, 400

        password_hash = argon2Hasher.hash(password)
        
        if User.query.filter_by(username=username).first():
            return "A user with this name already EXISTS.", 400

        db.session.add(User(username=username, password_hash=password_hash))
        db.session.commit()
        return redirect("/login")

    nonce = generate_nonce()
    request._csp_nonce = nonce
    return render_template("register.html", nonce=nonce)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("30 per 15 minutes", methods=["POST"])
def login():
    if request.method == "POST":
        username = request.form.get("user", "").strip()
        password = request.form.get("password", "").strip()

        valid_username, username_error = validate_username(username)
        if not valid_username:
            try:
                argon2Hasher.verify(DUMMY_HASH, password)
            except:
                pass
            return "INCORRECT username or password", 400

        valid_password, password_error = validate_password(password)
        if not valid_password:
            try:
                argon2Hasher.verify(DUMMY_HASH, password)
            except:
                pass
            return "INCORRECT username or password", 400

        user = User.query.filter_by(username=username).first()
        if not user:
            try:
                argon2Hasher.verify(DUMMY_HASH, password)
            except:
                pass
            return "INCORRECT username or password", 400

        try:
            argon2Hasher.verify(user.password_hash, password)
            auth_token, old_token = generate_auth_token(username)
            old_token_exists = old_token is not None
            
            nonce = generate_nonce()
            request._csp_nonce = nonce
            return render_template("index.html", auth_token=auth_token, user=username, old_session=old_token_exists, nonce=nonce)
        except VerifyMismatchError:
            return "INCORRECT username or password", 400

    nonce = generate_nonce()
    request._csp_nonce = nonce
    return render_template("login.html", nonce=nonce)

# ===============================================================
# ---- Chat message routes ----
# ===============================================================
@app.route("/post", methods=["POST"])
@limiter.limit("30 per minute")
def post():
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return abort(401)
    
    text = request.form.get("message", "").strip()
    if not text:
        return ("", 204)
    
    if len(text) > MAX_MESSAGE_LENGTH:
        return jsonify({"error": "Message too long", "max_length": MAX_MESSAGE_LENGTH}), 400
    
    msg = save_message(username, text)
    if not msg:
        return ("", 204)

    return ("", 204)

@app.route("/stream")
@limiter.limit("100 per minute")
def stream():
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return abort(401)
    
    return Response(event_stream(), mimetype="text/event-stream")

@app.route("/history")
@limiter.limit("30 per minute")
def history():
    """Load message history with pagination."""
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return abort(401)
    
    before_id = request.args.get('before_id', type=int)
    limit = request.args.get('limit', default=50, type=int)
    
    if limit > 100:
        limit = 100
    
    # Запрашиваем все типы сообщений (текст и фото)
    query = Message.query.order_by(Message.created_at.desc())
    
    if before_id:
        before_msg = Message.query.filter_by(id=before_id).first()
        if before_msg:
            query = query.filter(Message.created_at < before_msg.created_at)
    
    messages = query.limit(limit).all()
    
    # Собираем ID фото для предзагрузки
    photo_ids = []
    for msg in messages:
        if msg.message_type == 'photo':
            plain = msg.get_plain()
            if isinstance(plain, dict) and 'photo_id' in plain:
                photo_ids.append(plain['photo_id'])
    
    # Предзагружаем подписанные URL для всех фото
    photo_urls = {}
    if photo_ids:
        photos = Photo.query.filter(Photo.id.in_(photo_ids)).all()
        for photo in photos:
            signed_data = generate_signed_photo_url(photo.photo_token)
            photo_urls[photo.id] = f"/photo/{signed_data['token']}?sig={signed_data['signature']}&exp={signed_data['expires']}"
    
    # Формируем результат
    result = []
    for msg in reversed(messages):
        ts = msg.format_time()
        
        if msg.message_type == 'photo':
            plain = msg.get_plain()
            if isinstance(plain, dict) and 'photo_id' in plain:
                photo_id = plain['photo_id']
                if photo_id in photo_urls:
                    message_text = f"[{ts}] {msg.username}: [PHOTO:{photo_id}:{photo_urls[photo_id]}]"
                else:
                    message_text = f"[{ts}] {msg.username}: [PHOTO:{photo_id}]"
            else:
                message_text = f"[{ts}] {msg.username}: [PHOTO]"
        else:
            # Текстовое сообщение
            plain = msg.get_plain()
            message_text = f"[{ts}] {msg.username}: {plain}"
        
        result.append({
            "id": msg.id,
            "text": message_text
        })
    
    return jsonify({
        "messages": result,
        "has_more": len(messages) == limit
    }), 200

# ===============================================================
# ---- Photo upload and download routes ----
# ===============================================================
@app.route("/upload", methods=["POST"])
@limiter.limit("15 per minute; 300 per day")
def upload():
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return abort(401)
    
    if "file" not in request.files:
        return "No file part", 400
    
    file = request.files["file"]
    if file.filename == "":
        return "No selected file", 400
    
    result = save_photo(username, file)
    if not result:
        return "[ERROR] invalid file or file too large \n max photo resolution is 2560x2560", 400
    
    photo, message = result
    
    # Публикуем сообщение о фото в Redis для SSE
    message_text = format_message_for_sse(message)
    r.publish("chat", message_text.encode("utf-8"))
    
    increment_message_count()
    
    return {"photo_id": photo.id, "message_id": message.id}, 200

@app.route("/photo/sign/<int:photo_id>", methods=["GET"])
@limiter.limit("20 per minute")
def sign_photo_url(photo_id: int):
    """Generate signed URL for photo access."""
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return abort(401)
    
    photo = Photo.query.filter_by(id=photo_id).first()
    if not photo:
        return abort(404)
    
    signed_data = generate_signed_photo_url(photo.photo_token)
    
    return jsonify({
        "url": f"/photo/{signed_data['token']}?sig={signed_data['signature']}&exp={signed_data['expires']}"
    }), 200

@app.route("/photo/<photo_token>")
@limiter.limit("60 per minute")
def get_photo(photo_token: str):
    """Download decrypted photo by signed URL."""
    signature = request.args.get('sig', '')
    expiration = request.args.get('exp', '')
    
    if not verify_signed_photo_url(photo_token, signature, expiration):
        return abort(403)
    
    result = load_photo_by_token(photo_token)
    if not result:
        return abort(404)
    
    decrypted_data, mime_type = result
    
    response = send_file(
        io.BytesIO(decrypted_data),
        mimetype=mime_type,
        as_attachment=False
    )
    
    response.headers['Content-Security-Policy'] = "default-src 'none'; img-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    
    return response

@app.route("/logout", methods=["POST"])
def logout():
    token = extract_token_from_request()
    if token:
        revoke_token(token)
    return "", 204

@app.route("/verify-session", methods=["GET"])
@limiter.limit("10 per minute")
def verify_session():
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return jsonify({"valid": False}), 401
    return jsonify({"valid": True}), 200

@app.route("/")
def root():
    return redirect("/login")

# ===============================================================
# ---- Startup ----
# ===============================================================
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "0") == "1"

if __name__ == "__main__":
    print(f"[INFO] Starting Flask app on http://127.0.0.1:5000")
    print(f"[INFO] Debug mode: {app.config['DEBUG']}")
    print(f"[INFO] Production mode: {is_production}")
    app.run(host="127.0.0.1", port=5000, debug=app.config["DEBUG"])
