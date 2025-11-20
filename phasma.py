import os
import datetime
import threading
import time
import uuid
import re
import secrets
import logging
import json
import subprocess
import tempfile
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, Response, abort, send_file, jsonify, make_response
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
from mutagen import File as MutagenFile
from mutagen.id3 import ID3NoHeaderError
from pikepdf import Pdf
from user_agents import parse as parse_user_agent

# ===============================================================
# ---- PRODUCTION vs DEVELOPMENT MODE ----
# ===============================================================
app = Flask(__name__)

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
TEMP_FOLDER = "temp_processing" # Добавлено из old_script

# File categories and their allowed formats
FILE_CATEGORIES = {
    'photo': {
        'extensions': {'jpg', 'jpeg', 'png', 'gif', 'webp'},
        'mimetypes': {'image/jpeg', 'image/png', 'image/gif', 'image/webp'},
        'max_size': 10 * 1024 * 1024,  # 10 MB
        'display': 'inline'
    },
    'video': {
        'extensions': {'mp4', 'mov', 'webm'},
        'mimetypes': {'video/mp4', 'video/quicktime', 'video/webm'},
        'max_size': 100 * 1024 * 1024,  # 100 MB
        'display': 'download'
    },
    'audio': {
        'extensions': {'mp3', 'm4a', 'ogg', 'wav'},
        'mimetypes': {'audio/mpeg', 'audio/mp4', 'audio/ogg', 'audio/wav', 'audio/x-wav'},
        'max_size': 50 * 1024 * 1024,  # 50 MB
        'display': 'download'
    },
    'document': {
        'extensions': {'pdf', 'txt'},
        'mimetypes': {'application/pdf', 'text/plain'},
        'max_size': 25 * 1024 * 1024,  # 25 MB
        'display': 'download'
    }
}

# Build combined extension and mimetype sets
ALLOWED_EXTENSIONS = set()
ALLOWED_MIMETYPES = set()
for category in FILE_CATEGORIES.values():
    ALLOWED_EXTENSIONS.update(category['extensions'])
    ALLOWED_MIMETYPES.update(category['mimetypes'])

MIN_FILE_SIZE = 100  # 100 bytes minimum

# Image-specific settings (for photos only)
MAX_IMAGE_WIDTH = 16_384
MAX_IMAGE_HEIGHT = 16_384
MAX_PIXELS = MAX_IMAGE_WIDTH * MAX_IMAGE_HEIGHT
IMAGE_QUALITY = 90  # Добавлено из old_script (JPEG quality after metadata removal)

# PIL format to MIME mapping (for images)
SAFE_MIME_MAPPING = {
    "PNG": "image/png",
    "JPEG": "image/jpeg",
    "GIF": "image/gif",
    "WEBP": "image/webp"
}

# Extension to MIME mapping (for non-images)
EXT_TO_MIME = {
    'mp4': 'video/mp4',
    'mov': 'video/quicktime',
    'webm': 'video/webm',
    'mp3': 'audio/mpeg',
    'm4a': 'audio/mp4',
    'ogg': 'audio/ogg',
    'wav': 'audio/wav',
    'pdf': 'application/pdf',
    'txt': 'text/plain'
}

AUTH_TOKEN_TTL = 3600  # seconds = 1 hour
SESSION_METADATA_TTL = 3600

USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 32
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')

MESSAGE_HISTORY_LIMIT = 50
MAX_MESSAGE_LENGTH = 5000

FILE_URL_TTL = 86400  # 24 hours
SIGNED_URL_SECRET = None

TOR_ROTATION_INTERVAL = 300  # 5 minutes
TOR_ROTATION_MESSAGE_THRESHOLD = 30

TIMEZONE = ZoneInfo("Europe/Prague")

# FFmpeg configuration
FFMPEG_PATH = "ffmpeg"  # Добавлено из old_script

# ===============================================================
# ---- ADD THIS CONFIGURATION after FFmpeg section ----
# ===============================================================

# URL Preview configuration
URL_PREVIEW_CACHE_TTL = 7 * 24 * 3600  # 7 days
URL_PREVIEW_REQUEST_TIMEOUT = 5  # seconds
URL_PREVIEW_MAX_TITLE_LENGTH = 256
URL_PREVIEW_MAX_DESCRIPTION_LENGTH = 500
MAX_URLS_PER_MESSAGE = 10
URL_PARSE_RATE_LIMIT = 10  # URLs per minute per user

MAX_PREVIEW_SIZE = 10 * 1024 * 1024  # 10 MB

YOUTUBE_PATTERN = r'(?:https?://)?(?:www\.)?(?:youtube\.com|youtu\.be)/'
YOUTUBE_ID_PATTERN = r'(?:youtube\.com/watch\?v=|youtu\.be/|youtube\.com/embed/|youtube\.com/shorts/|youtube\.com/live/)([a-zA-Z0-9_-]{11})'

VIMEO_PATTERN = r'(?:https?://)?(?:www\.)?vimeo\.com/(\d+)'
INSTAGRAM_PATTERN = r'(?:https?://)?(?:www\.)?instagram\.com/'
TIKTOK_PATTERN = r'(?:https?://)?(?:www\.)?(?:tiktok\.com|vm\.tiktok\.com)/'

IMAGE_PATTERN = r'(?:https?://[^\s]+\.(?:jpg|jpeg|png|gif|webp)(?:[\?\#]|$)|https?://[^\s]*(?:/images?/|/img/|/photo/|/thumb|gstatic\.com/|imgur\.com/|cloudinary\.com/)[^\s]*)'
# ===============================================================


# URL regex pattern (basic)
URL_PATTERN = re.compile(
    r'https?://[^\s\[\]<>"\'\)\}]+',
    re.IGNORECASE
)


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
        # Убедиться что created_at в UTC и вернуть корректный Unix timestamp
        if self.created_at.tzinfo is None:
            # Если naive datetime, предполагаем UTC
            utc_time = self.created_at.replace(tzinfo=datetime.timezone.utc)
        else:
            utc_time = self.created_at.astimezone(datetime.timezone.utc)
        
        return int(utc_time.timestamp())

    def format_time_iso(self):
        # Возвращаем ISO 8601 строку в UTC
        if self.created_at.tzinfo is None:
            utc_time = self.created_at.replace(tzinfo=datetime.timezone.utc)
        else:
            utc_time = self.created_at.astimezone(datetime.timezone.utc)
        
        return utc_time.isoformat() + 'Z'

class Message(db.Model):
    id = db.Column(db.BigInteger, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True, index=True)  # ДОБАВЛЕНО
    username = db.Column(db.String(100), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.String(20), nullable=False, default='text', index=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)

    __table_args__ = (
        db.Index('ix_message_group_created', 'group_id', 'created_at'),  # ДОБАВЛЕНО
        db.Index('ix_message_username_created', 'username', 'created_at'),
    )

    def format_time(self):
        if self.created_at.tzinfo is None:
            utc_time = self.created_at.replace(tzinfo=datetime.timezone.utc)
        else:
            utc_time = self.created_at.astimezone(datetime.timezone.utc)
        return int(utc_time.timestamp())

    def format_time_iso(self):
        if self.created_at.tzinfo is None:
            utc_time = self.created_at.replace(tzinfo=datetime.timezone.utc)
        else:
            utc_time = self.created_at.astimezone(datetime.timezone.utc)
        return utc_time.isoformat() + 'Z'

    def get_plain(self):
        try:
            decrypted = data_fernet.decrypt(self.content.encode("utf-8")).decode("utf-8")
            
            if self.message_type in ('photo', 'file', 'text'):
                return json.loads(decrypted)
            else:
                return decrypted
        except json.JSONDecodeError:
            if self.message_type == 'text':
                try:
                    decrypted_again = data_fernet.decrypt(self.content.encode("utf-8")).decode("utf-8")
                    return {'text': decrypted_again, 'urls': {}}
                except (InvalidToken, Exception):
                    return "[UNDECRYPTABLE MESSAGE]"
            else:
                return "[UNDECRYPTABLE MESSAGE]"
        except (InvalidToken, Exception) as e:
            print(f"[ERROR] Failed to decrypt/parse message {self.id}: {e}")
            return "[UNDECRYPTABLE MESSAGE]"

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, index=True)
    filename = db.Column(db.String(256), unique=True, nullable=False, index=True)
    file_token = db.Column(db.String(128), unique=True, nullable=False, index=True)
    original_filename = db.Column(db.String(256), nullable=False)
    file_category = db.Column(db.String(20), nullable=False, index=True)  # photo/video/audio/document
    filesize = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)

    def format_time(self):
        # Убедиться что created_at в UTC и вернуть корректный Unix timestamp
        if self.created_at.tzinfo is None:
            utc_time = self.created_at.replace(tzinfo=datetime.timezone.utc)
        else:
            utc_time = self.created_at.astimezone(datetime.timezone.utc)
        
        return int(utc_time.timestamp())

    def format_time_iso(self):
        # Возвращаем ISO 8601 строку в UTC
        if self.created_at.tzinfo is None:
            utc_time = self.created_at.replace(tzinfo=datetime.timezone.utc)
        else:
            utc_time = self.created_at.astimezone(datetime.timezone.utc)
        
        return utc_time.isoformat() + 'Z'

class Secret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def format_time(self):
        # Убедиться что created_at в UTC и вернуть корректный Unix timestamp
        if self.created_at.tzinfo is None:
            utc_time = self.created_at.replace(tzinfo=datetime.timezone.utc)
        else:
            utc_time = self.created_at.astimezone(datetime.timezone.utc)
        
        return int(utc_time.timestamp())

    def format_time_iso(self):
        # Возвращаем ISO 8601 строку в UTC
        if self.created_at.tzinfo is None:
            utc_time = self.created_at.replace(tzinfo=datetime.timezone.utc)
        else:
            utc_time = self.created_at.astimezone(datetime.timezone.utc)
        
        return utc_time.isoformat() + 'Z'

class URLPreview(db.Model):
    """Cache for URL previews (links in messages)"""
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(512), unique=True, nullable=False, index=True)
    service_type = db.Column(db.String(50), nullable=False)  # youtube, vimeo, instagram, tiktok, image, unknown
    title = db.Column(db.String(256), nullable=True)
    thumbnail_url = db.Column(db.String(512), nullable=True)
    description = db.Column(db.Text, nullable=True)
    cached_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)
    ttl = db.Column(db.DateTime, nullable=True)  # When cache expires

    def is_expired(self):
        if self.ttl is None:
            return False
        return datetime.datetime.utcnow() > self.ttl

    def format_time(self):
        # Убедиться что cached_at в UTC и вернуть корректный Unix timestamp
        if self.cached_at.tzinfo is None:
            utc_time = self.cached_at.replace(tzinfo=datetime.timezone.utc)
        else:
            utc_time = self.cached_at.astimezone(datetime.timezone.utc)
        
        return int(utc_time.timestamp())

    def format_time_iso(self):
        # Возвращаем ISO 8601 строку в UTC
        if self.cached_at.tzinfo is None:
            utc_time = self.cached_at.replace(tzinfo=datetime.timezone.utc)
        else:
            utc_time = self.cached_at.astimezone(datetime.timezone.utc)
        
        return utc_time.isoformat() + 'Z'

class Group(db.Model):
    """Модель группы (чата)"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # Название группы
    group_code = db.Column(db.String(8), unique=True, nullable=False, index=True)  # Уникальный 8-значный код
    creator = db.Column(db.String(100), nullable=False, index=True)  # Username создателя
    password_hash = db.Column(db.String(256), nullable=False)  # Хеш пароля входа
    root_password_hash = db.Column(db.String(256), nullable=False)  # Хеш рут-пароля
    max_members = db.Column(db.Integer, default=100)  # Максимум участников
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)
    
    def format_time(self):
        if self.created_at.tzinfo is None:
            utc_time = self.created_at.replace(tzinfo=datetime.timezone.utc)
        else:
            utc_time = self.created_at.astimezone(datetime.timezone.utc)
        return int(utc_time.timestamp())

    def format_time_iso(self):
        if self.created_at.tzinfo is None:
            utc_time = self.created_at.replace(tzinfo=datetime.timezone.utc)
        else:
            utc_time = self.created_at.astimezone(datetime.timezone.utc)
        return utc_time.isoformat() + 'Z'


class GroupMember(db.Model):
    """Модель членства пользователя в группе"""
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False, index=True)
    username = db.Column(db.String(100), nullable=False, index=True)
    role = db.Column(db.String(20), default='member', nullable=False)  # creator, member
    joined_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)
    
    __table_args__ = (
        db.UniqueConstraint('group_id', 'username', name='unique_group_member'),
        db.Index('ix_groupmember_group_username', 'group_id', 'username'),
    )
    
    def format_time(self):
        if self.joined_at.tzinfo is None:
            utc_time = self.joined_at.replace(tzinfo=datetime.timezone.utc)
        else:
            utc_time = self.joined_at.astimezone(datetime.timezone.utc)
        return int(utc_time.timestamp())

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

    if not os.path.exists(TEMP_FOLDER):
        os.makedirs(TEMP_FOLDER)
        print(f"[OK] Created temp folder: {TEMP_FOLDER}")
    else:
        print(f"[OK] Temp folder exists: {TEMP_FOLDER}")

init_upload_folder()

# ===============================================================
# ---- FFmpeg availability check----
# ===============================================================
def check_ffmpeg():
    try:
        result = subprocess.run(
            [FFMPEG_PATH, '-version'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        if result.returncode == 0:
            print("[OK] FFmpeg is available")
            return True
        else:
            print("[WARN] FFmpeg not working properly")
            return False
    except Exception as e:
        print(f"[WARN] FFmpeg not found: {e}")
        print("[WARN] Video metadata removal will be disabled")
        return False

FFMPEG_AVAILABLE = check_ffmpeg()

# ===============================================================
# ---- METADATA REMOVAL FUNCTIONS----
# ===============================================================

def strip_image_metadata(file_data: bytes, image_format: str) -> bytes or None:
    """
    Remove metadata from images without re-encoding (preserves animation perfectly).
    Uses binary-level manipulation to strip EXIF/metadata while keeping image data intact.
    """
    try:
        if image_format in ("GIF", "WEBP"):
            print(f"[INFO] {image_format} format - minimal metadata present, returning optimized copy")
            try:
                img = Image.open(io.BytesIO(file_data))
                output = io.BytesIO()
                
                if image_format == "GIF":
                    img.save(output, format="GIF", save_all=True, duration=img.info.get('duration', 100), loop=img.info.get('loop', 0))
                else:  # WEBP
                    img.save(output, format="WEBP", save_all=True, duration=img.info.get('duration', 100), loop=img.info.get('loop', 0))
                
                clean_data = output.getvalue()
                print(f"[OK] {image_format} repackaged: {len(file_data)} -> {len(clean_data)} bytes")
                return clean_data
            except Exception as e:
                print(f"[WARN] Failed to repackage {image_format}, returning original: {e}")
                return file_data
        
        elif image_format == "PNG":
            print("[INFO] Processing PNG - stripping EXIF and ancillary chunks")
            try:
                img = Image.open(io.BytesIO(file_data))
                output = io.BytesIO()
                
                data = {"optimize": True}
                img.save(output, format="PNG", **data)
                
                clean_data = output.getvalue()
                print(f"[OK] PNG metadata stripped: {len(file_data)} -> {len(clean_data)} bytes")
                return clean_data
            except Exception as e:
                print(f"[WARN] PNG strip failed: {e}")
                return file_data
        
        # Для JPEG — удаляем EXIF на бинарном уровне
        elif image_format == "JPEG":
            print("[INFO] Processing JPEG - stripping EXIF data")
            try:
                img = Image.open(io.BytesIO(file_data))
                output = io.BytesIO()
                
                # Конвертируем RGBA в RGB если нужно
                if img.mode in ("RGBA", "LA", "P"):
                    background = Image.new("RGB", img.size, (255, 255, 255))
                    if img.mode == "P":
                        img = img.convert("RGBA")
                    background.paste(img, mask=img.split()[-1] if img.mode in ("RGBA", "LA") else None)
                    img = background
                
                # Сохраняем БЕЗ exif data
                img.save(output, format="JPEG", quality=IMAGE_QUALITY, progressive=True)
                
                clean_data = output.getvalue()
                print(f"[OK] JPEG metadata stripped: {len(file_data)} -> {len(clean_data)} bytes")
                return clean_data
            except Exception as e:
                print(f"[WARN] JPEG strip failed: {e}")
                return file_data
        
        else:
            print(f"[WARN] Unknown image format: {image_format}")
            return file_data
    
    except Exception as e:
        print(f"[ERROR] Failed to strip image metadata: {e}")
        return None

def strip_video_metadata(file_data: bytes, ext: str) -> bytes or None:
    """
    Remove metadata from video files using FFmpeg (stream copy - FAST!)
    """
    if not FFMPEG_AVAILABLE:
        print("[WARN] FFmpeg not available, skipping video metadata removal")
        return file_data
    
    temp_input = None
    temp_output = None
    
    try:
        # Create temp files
        with tempfile.NamedTemporaryFile(mode='wb', suffix=f'.{ext}', delete=False, dir=TEMP_FOLDER) as f:
            temp_input = f.name
            f.write(file_data)
        
        temp_output = tempfile.NamedTemporaryFile(mode='wb', suffix=f'.{ext}', delete=False, dir=TEMP_FOLDER).name
        
        # FFmpeg command: stream copy without re-encoding (FAST!)
        cmd = [
            FFMPEG_PATH,
            '-i', temp_input,
            '-map_metadata', '-1',  # Remove all metadata
            '-map_chapters', '-1',  # Remove chapters
            '-c', 'copy',  # Stream copy (no re-encoding!)
            '-fflags', '+bitexact',  # Reproducible output
            '-y',  # Overwrite output
            temp_output
        ]
        
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60
        )
        
        if result.returncode != 0:
            print(f"[ERROR] FFmpeg failed: {result.stderr.decode('utf-8', errors='ignore')}")
            return None
        
        # Read cleaned file
        with open(temp_output, 'rb') as f:
            clean_data = f.read()
        
        print(f"[OK] Video metadata stripped: {len(file_data)} -> {len(clean_data)} bytes")
        return clean_data
        
    except subprocess.TimeoutExpired:
        print("[ERROR] FFmpeg timeout")
        return None
    except Exception as e:
        print(f"[ERROR] Failed to strip video metadata: {e}")
        return None
    finally:
        # Cleanup temp files
        if temp_input and os.path.exists(temp_input):
            try:
                os.remove(temp_input)
            except:
                pass
        if temp_output and os.path.exists(temp_output):
            try:
                os.remove(temp_output)
            except:
                pass


def strip_audio_metadata(file_data: bytes, ext: str) -> bytes or None:
    """
    Remove metadata from audio files using mutagen
    """
    
    temp_file = None
    
    try:
        # Create temp file
        with tempfile.NamedTemporaryFile(mode='wb', suffix=f'.{ext}', delete=False, dir=TEMP_FOLDER) as f:
            temp_file = f.name
            f.write(file_data)
        
        # Load audio file with mutagen
        try:
            audio = MutagenFile(temp_file, easy=False)
            
            if audio is None:
                print(f"[WARN] Mutagen couldn't process audio file, returning original")
                return file_data
            
            # Delete all tags
            if hasattr(audio, 'tags') and audio.tags:
                audio.delete()
                audio.save()
            
            # Read cleaned file
            with open(temp_file, 'rb') as f:
                clean_data = f.read()
            
            print(f"[OK] Audio metadata stripped: {len(file_data)} -> {len(clean_data)} bytes")
            return clean_data
            
        except ID3NoHeaderError:
            # File has no ID3 tags (already clean)
            print("[OK] Audio file has no metadata")
            return file_data
            
    except Exception as e:
        print(f"[ERROR] Failed to strip audio metadata: {e}")
        return None
    finally:
        # Cleanup temp file
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except:
                pass


def strip_pdf_metadata(file_data: bytes) -> bytes or None:
    """
    Remove metadata from PDF files using pikepdf
    """
    temp_input = None
    temp_output = None
    
    try:
        # Create temp files
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.pdf', delete=False, dir=TEMP_FOLDER) as f:
            temp_input = f.name
            f.write(file_data)
        
        temp_output = tempfile.NamedTemporaryFile(mode='wb', suffix='.pdf', delete=False, dir=TEMP_FOLDER).name
        
        # Open PDF and remove metadata
        with Pdf.open(temp_input) as pdf:
            # Remove document info
            with pdf.open_metadata() as meta:
                meta.clear()
            
            # Save without metadata
            pdf.save(temp_output)
        
        # Read cleaned file
        with open(temp_output, 'rb') as f:
            clean_data = f.read()
        
        print(f"[OK] PDF metadata stripped: {len(file_data)} -> {len(clean_data)} bytes")
        return clean_data
        
    except Exception as e:
        print(f"[ERROR] Failed to strip PDF metadata: {e}")
        return None
    finally:
        # Cleanup temp files
        if temp_input and os.path.exists(temp_input):
            try:
                os.remove(temp_input)
            except:
                pass
        if temp_output and os.path.exists(temp_output):
            try:
                os.remove(temp_output)
            except:
                pass


def strip_file_metadata(file_data: bytes, category: str, ext: str, image_format: str = None) -> bytes or None:
    """
    Main function to strip metadata based on file category
    """
    print(f"[INFO] Stripping metadata for {category} file...")
    
    if category == 'photo':
         return strip_image_metadata(file_data, image_format)
    
    elif category == 'video':
        return strip_video_metadata(file_data, ext)
    
    elif category == 'audio':
        return strip_audio_metadata(file_data, ext)
    
    elif category == 'document':
        if ext.lower() == 'pdf':
            return strip_pdf_metadata(file_data)
        else:
            # TXT files don't have metadata
            print("[OK] Text file has no metadata to strip")
            return file_data
    
    else:
        print(f"[WARN] Unknown category: {category}")
        return file_data

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
# ---- File validation helpers ----
# ===============================================================
def detect_file_category(ext: str) -> str or None:
    """Detect file category by extension"""
    ext = ext.lower()
    for category, config in FILE_CATEGORIES.items():
        if ext in config['extensions']:
            return category
    return None

def validate_image_file(file_data: bytes, ext: str) -> tuple or None:
    """Validate image files (photo category)"""
    try:
        img = Image.open(io.BytesIO(file_data))
        
        # Check resolution
        if img.width > MAX_IMAGE_WIDTH or img.height > MAX_IMAGE_HEIGHT:
            print(f"[WARN] Image resolution {img.width}x{img.height} exceeds maximum")
            return None
        
        if img.width * img.height > MAX_PIXELS:
            print(f"[WARN] Total pixels exceeds maximum")
            return None
        
        # Verify format
        image_format = img.format
        if image_format not in SAFE_MIME_MAPPING:
            print(f"[WARN] Image format '{image_format}' not allowed")
            return None
        
        mime_type = SAFE_MIME_MAPPING.get(image_format)
        print(f"[OK] Image validated: {img.width}x{img.height}, format={image_format}")
        return (mime_type, image_format)
    
    except Exception as e:
        print(f"[WARN] Image validation failed: {e}")
        return None

def validate_generic_file(file_data: bytes, ext: str, category: str) -> str or None:
    """Validate non-image files (video/audio/document)"""
    mime_type = EXT_TO_MIME.get(ext.lower())
    if not mime_type:
        print(f"[WARN] No MIME mapping for extension: {ext}")
        return None
    
    print(f"[OK] File validated: category={category}, mime={mime_type}")
    return mime_type

def validate_file(file_data: bytes, original_filename: str) -> tuple or None:
    """
    Validate any file and return (category, mime_type, original_filename, ext, image_format)
    """
    try:
        # Size check
        if len(file_data) < MIN_FILE_SIZE:
            print(f"[WARN] File size too small: {len(file_data)} bytes")
            return None
        
        # Extract extension
        if not original_filename or '.' not in original_filename:
            print(f"[WARN] Invalid filename format")
            return None
        
        ext = original_filename.rsplit('.', 1)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            print(f"[WARN] File extension '{ext}' not allowed")
            return None
        
        # Detect category
        category = detect_file_category(ext)
        if not category:
            print(f"[WARN] Could not detect category for extension: {ext}")
            return None
        
        # Check size limit for category
        max_size = FILE_CATEGORIES[category]['max_size']
        if len(file_data) > max_size:
            print(f"[WARN] File size {len(file_data)} exceeds max for {category}: {max_size}")
            return None
        
        # Category-specific validation
        image_format = None # Изменено
        if category == 'photo':
            result = validate_image_file(file_data, ext)
            if not result:
                return None
            mime_type, image_format = result # Изменено (было mime_type, _)
        else:
            mime_type = validate_generic_file(file_data, ext, category)
            if not mime_type:
                return None
        
        # Sanitize original filename
        safe_filename = secure_filename(original_filename)
        if not safe_filename:
            safe_filename = f"file.{ext}"
        
        return (category, mime_type, safe_filename, ext, image_format) # Изменено (добавлены ext, image_format)
    
    except Exception as e:
        print(f"[ERROR] File validation failed: {e}")
        return None

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
    """Get client IP subnet - более гибкий подход"""
    try:
        # Проверяем X-Forwarded-For (для proxy/nginx)
        if request.headers.get('X-Forwarded-For'):
            ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        else:
            ip = get_remote_address()
        
        if not ip or ip == '127.0.0.1':
            return "local"  # Локальный доступ - всегда разрешен
        
        if '.' in ip:
            octets = ip.split('.')
            return '.'.join(octets[:3])
        if ':' in ip:
            segments = ip.split(':')
            return ':'.join(segments[:3])
        return "unknown"
    except:
        return "unknown"

def generate_auth_token(username: str) -> tuple:
    """Генерирует auth token с метаданными браузера и OS"""
    
    # Получаем User-Agent
    user_agent_string = request.headers.get('User-Agent', 'Unknown')
    browser, os_name = get_browser_info_from_user_agent(user_agent_string)
    
    # Проверяем, есть ли уже сессия с таким браузером/OS/IP
    existing_sessions = get_all_user_sessions(username)
    old_token = None
    
    for session in existing_sessions:
        if (session.get('browser') == browser and 
            session.get('os') == os_name and 
            session.get('ip_subnet') == get_client_ip_subnet()):
            # Нашли существующую сессию с тем же браузером/OS/IP
            old_token = session.get('token')
            break
    
    # Генерируем новый токен
    token = str(uuid.uuid4())
    current_time = int(time.time())
    
    # Если есть старая сессия с такой же конфигурацией, завершаем её
    if old_token:
        terminate_session(old_token, username)
        print(f"[INFO] Replaced existing session for {username}")
    
    # Сохраняем новые метаданные
    save_session_metadata(token, username, browser, os_name, current_time)
    
    ip_subnet = get_client_ip_subnet()
    token_data = f"{username}|{ip_subnet}"
    r.setex(f"auth_token:{token}", AUTH_TOKEN_TTL, token_data.encode("utf-8"))
    r.setex(f"user_session:{username}", AUTH_TOKEN_TTL, token.encode("utf-8"))
    
    print(f"[OK] Auth token generated for {username} ({browser} on {os_name})")
    return token, old_token

def verify_token(token: str, strict_ip_check: bool = False) -> str or None:
    """
    Проверяет токен аутентификации и возвращает username или None
    
    """
    if not token:
        return None
    
    token_data_bytes = r.get(f"auth_token:{token}")
    if not token_data_bytes:
        print(f"[WARN] Token not found in Redis: {token[:20]}...")
        return None
    
    token_data = token_data_bytes.decode("utf-8")
    
    if '|' not in token_data:
        # Старый формат без IP
        return token_data
    
    username, stored_subnet = token_data.split('|', 1)
    current_subnet = get_client_ip_subnet()
    
    # Если strict_ip_check = True (только для критичных операций)
    if strict_ip_check:
        if stored_subnet != current_subnet and current_subnet != "local" and stored_subnet != "local":
            print(f"[SECURITY] IP subnet mismatch for {username}: stored={stored_subnet}, current={current_subnet}")
            revoke_token(token)
            return None
    else:
        # Мягкая проверка - только логируем изменения
        if current_subnet != "local" and stored_subnet != "local" and stored_subnet != current_subnet:
            print(f"[INFO] IP changed for {username}: {stored_subnet} → {current_subnet}")
            # Обновляем IP в токене, но не отзываем его
            new_token_data = f"{username}|{current_subnet}"
            # Получаем оставшееся время жизни токена
            ttl = r.ttl(f"auth_token:{token}")
            if ttl > 0:
                r.setex(f"auth_token:{token}", ttl, new_token_data.encode("utf-8"))
    
    return username

def revoke_token(token: str):
    """Отзывает токен"""
    try:
        token_data_bytes = r.get(f"auth_token:{token}")
        if token_data_bytes:
            token_data = token_data_bytes.decode("utf-8")
            if '|' in token_data:
                username = token_data.split('|')[0]
            else:
                username = token_data
            r.delete(f"user_session:{username}")
    except:
        pass
    r.delete(f"auth_token:{token}")
    print(f"[OK] Auth token revoked")

# ===============================================================
# ---- Session Management (с информацией о браузере и OS) ----
# ===============================================================

def get_browser_info_from_user_agent(user_agent_string: str) -> tuple:
    """
    Парсит User-Agent и возвращает (browser, os)
    Возвращает кортеж: ("Chrome 120", "Windows 10")
    """
    try:
        ua = parse_user_agent(user_agent_string)
        
        # Браузер
        browser_name = ua.browser.family or "Unknown"
        browser_version = ua.browser.version_string or "0"
        # Берём только major версию
        browser_major = browser_version.split('.')[0] if browser_version else "0"
        browser = f"{browser_name} {browser_major}"
        
        # ОС
        os_name = ua.os.family or "Unknown"
        os_version = ua.os.version_string or ""
        os = f"{os_name} {os_version}".strip()
        
        return (browser, os)
    except Exception as e:
        print(f"[WARN] Failed to parse User-Agent: {e}")
        return ("Unknown Browser", "Unknown OS")

def save_session_metadata(token: str, username: str, browser: str, os: str, created_at: int):
    """
    Сохраняет метаданные сессии в Redis
    """
    try:
        metadata = {
            'username': username,
            'browser': browser,
            'os': os,
            'created_at': created_at,
            'last_activity': created_at,
            'ip_subnet': get_client_ip_subnet()
        }
        
        pipe = r.pipeline()
        pipe.multi()
        
        # Сохраняем метаданные
        pipe.setex(
            f"session_metadata:{token}",
            SESSION_METADATA_TTL,
            json.dumps(metadata).encode("utf-8")
        )
        
        # Добавляем токен в Set пользователя
        pipe.sadd(f"user_sessions:{username}", token)
        
        pipe.execute()
        
        print(f"[OK] Session metadata saved for {username}: {browser} on {os}")
    except Exception as e:
        print(f"[ERROR] Failed to save session metadata: {e}")

def get_all_user_sessions(username: str) -> list:
    """
    Получает все активные сессии пользователя
    Возвращает список dict'ов с информацией о каждой сессии
    """
    try:
        tokens = r.smembers(f"user_sessions:{username}")
        sessions = []
        
        for token_bytes in tokens:
            token = token_bytes.decode("utf-8") if isinstance(token_bytes, bytes) else token_bytes
            
            metadata_bytes = r.get(f"session_metadata:{token}")
            if not metadata_bytes:
                # Сессия истекла или удалена
                r.srem(f"user_sessions:{username}", token)
                continue
            
            try:
                metadata = json.loads(metadata_bytes.decode("utf-8"))
                metadata['token'] = token
                sessions.append(metadata)
            except Exception as e:
                print(f"[WARN] Failed to parse session metadata for token {token[:20]}: {e}")
                continue
        
        # Сортируем по created_at (новые сверху)
        sessions.sort(key=lambda x: x['created_at'], reverse=True)
        
        return sessions
    except Exception as e:
        print(f"[ERROR] Failed to get user sessions: {e}")
        return []

def terminate_session(token: str, username: str) -> bool:
    """
    Завершает конкретную сессию
    """
    try:
        metadata_bytes = r.get(f"session_metadata:{token}")
        if not metadata_bytes:
            print(f"[WARN] Session not found: {token}")
            return False
        
        metadata = json.loads(metadata_bytes.decode("utf-8"))
        token_username = metadata.get('username')
        
        if token_username != username:
            print(f"[SECURITY] User {username} tried to terminate session of {token_username}")
            return False
        
        pipe = r.pipeline()
        pipe.multi()
        
        # Удаляем метаданные
        pipe.delete(f"session_metadata:{token}")
        
        # Удаляем из Set пользователя
        pipe.srem(f"user_sessions:{username}", token)
        
        # Удаляем auth token
        pipe.delete(f"auth_token:{token}")
        
        pipe.execute()
        
        print(f"[OK] Session terminated: {token[:20]}... for {username}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to terminate session: {e}")
        return False

def terminate_all_other_sessions(current_token: str, username: str) -> bool:
    """
    Завершает все остальные сессии пользователя (кроме текущей)
    """
    try:
        tokens = r.smembers(f"user_sessions:{username}")
        
        pipe = r.pipeline()
        pipe.multi()
        
        for token_bytes in tokens:
            token = token_bytes.decode("utf-8") if isinstance(token_bytes, bytes) else token_bytes
            
            if token == current_token:
                continue
            
            # Удаляем метаданные
            pipe.delete(f"session_metadata:{token}")
            
            # Удаляем auth token
            pipe.delete(f"auth_token:{token}")
            
            # Удаляем из Set
            pipe.srem(f"user_sessions:{username}", token)
        
        pipe.execute()
        
        print(f"[OK] All other sessions terminated for {username}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to terminate all sessions: {e}")
        return False

# ===============================================================
# ----  2: ДОБАВЛЕНИЕ HELPER ФУНКЦИЙ ДЛЯ ГРУПП ----
# ===============================================================
def generate_group_code() -> str:
    """Генерирует уникальный 8-значный код группы (буквы + цифры)"""
    import random
    import string
    
    while True:
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        # Проверяешь что такого кода ещё нет
        if not Group.query.filter_by(group_code=code).first():
            return code

def verify_group_session(token: str) -> dict or None:
    """
    Проверяет групповую сессию и возвращает {username, group_id, ip_subnet} или None
    """
    if not token:
        print(f"[WARN] Empty token in verify_group_session")
        return None
    
    session_data_bytes = r.get(f"group_session:{token}")
    if not session_data_bytes:
        print(f"[WARN] Group session token not found in Redis: {token[:20]}...")
        return None
    
    try:
        session_data = json.loads(session_data_bytes.decode("utf-8"))
    except:
        print(f"[ERROR] Could not parse group session data")
        return None
    
    # Проверяем IP, но не блокируем - только логируем
    current_subnet = get_client_ip_subnet()
    stored_subnet = session_data.get('ip_subnet')
    
    if stored_subnet and stored_subnet != current_subnet:
        print(f"[INFO] IP changed for {session_data.get('username')}: {stored_subnet} → {current_subnet}")
        # Обновляем IP в сессии
        session_data['ip_subnet'] = current_subnet
        session_data['last_activity'] = int(time.time())
        
        # Получаем оставшееся время жизни
        ttl = r.ttl(f"group_session:{token}")
        if ttl > 0:
            r.setex(f"group_session:{token}", ttl, json.dumps(session_data).encode("utf-8"))
    else:
        # Просто обновляем time activity
        session_data['last_activity'] = int(time.time())
        ttl = r.ttl(f"group_session:{token}")
        if ttl > 0:
            r.setex(f"group_session:{token}", ttl, json.dumps(session_data).encode("utf-8"))
    
    return session_data

def generate_group_session_token(username: str, group_id: int) -> str:
    """
    Генерирует и сохраняет групповую сессию
    
    ИСПРАВЛЕНИЕ: Лучше обработка старых сессий и более предсказуемое поведение
    """
    # Проверяем старую сессию
    old_session_bytes = r.get(f"user_group_session:{username}:{group_id}")
    old_token = old_session_bytes.decode("utf-8") if old_session_bytes else None
    
    # Генерируем новый токен
    token = str(uuid.uuid4())
    ip_subnet = get_client_ip_subnet()
    
    session_data = {
        'username': username,
        'group_id': group_id,
        'ip_subnet': ip_subnet,
        'created_at': int(time.time()),
        'last_activity': int(time.time())  # Добавляем время последней активности
    }
    
    pipe = r.pipeline()
    pipe.multi()
    
    # Удаляем старую сессию
    if old_token:
        pipe.delete(f"group_session:{old_token}")
    
    # Сохраняем новую
    pipe.setex(f"group_session:{token}", AUTH_TOKEN_TTL, json.dumps(session_data).encode("utf-8"))
    pipe.setex(f"user_group_session:{username}:{group_id}", AUTH_TOKEN_TTL, token.encode("utf-8"))
    pipe.execute()
    
    print(f"[OK] Group session generated for {username} in group {group_id}")
    return token

def revoke_group_session(token: str):
    """Отзывает сессию группы"""
    session_data_bytes = r.get(f"group_session:{token}")
    if session_data_bytes:
        try:
            session_data = json.loads(session_data_bytes.decode("utf-8"))
            username = session_data.get('username')
            group_id = session_data.get('group_id')
            if username and group_id:
                r.delete(f"user_group_session:{username}:{group_id}")
        except:
            pass
    r.delete(f"group_session:{token}")
    print(f"[OK] Group session revoked")

def is_user_in_group(username: str, group_id: int) -> bool:
    """Проверяет состоит ли пользователь в группе"""
    member = GroupMember.query.filter_by(
        group_id=group_id, 
        username=username
    ).first()
    return member is not None

def get_group_members_count(group_id: int) -> int:
    """Возвращает количество участников в группе"""
    return GroupMember.query.filter_by(group_id=group_id).count()

def add_user_to_group(group_id: int, username: str, role: str = 'member') -> bool:
    """Добавляет пользователя в группу"""
    try:
        # Проверяешь что группа существует
        group = Group.query.filter_by(id=group_id).first()
        if not group:
            return False
        
        # Проверяешь максимум участников
        current_count = get_group_members_count(group_id)
        if current_count >= group.max_members:
            print(f"[WARN] Group {group_id} is full ({group.max_members} members)")
            return False
        
        # Проверяешь не уже ли в группе
        if is_user_in_group(username, group_id):
            return True
        
        # Добавляешь
        member = GroupMember(
            group_id=group_id,
            username=username,
            role=role
        )
        db.session.add(member)
        db.session.commit()
        
        # Добавляешь в Redis список
        r.sadd(f"group_members:{group_id}", username)
        r.sadd(f"group_members:online:{group_id}", username)
        
        print(f"[OK] User {username} added to group {group_id}")
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Failed to add user to group: {e}")
        return False

def remove_user_from_group(group_id: int, username: str) -> bool:
    """Удаляет пользователя из группы"""
    try:
        member = GroupMember.query.filter_by(
            group_id=group_id,
            username=username
        ).first()
        
        if member:
            db.session.delete(member)
            db.session.commit()
        
        # Удаляешь из Redis
        r.srem(f"group_members:{group_id}", username)
        r.srem(f"group_members:online:{group_id}", username)
        
        # Отзываешь сессию
        session_token_bytes = r.get(f"user_group_session:{username}:{group_id}")
        if session_token_bytes:
            revoke_group_session(session_token_bytes.decode("utf-8"))
        
        print(f"[OK] User {username} removed from group {group_id}")
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Failed to remove user from group: {e}")
        return False

def get_user_groups(username: str) -> list:
    """Возвращает список всех групп пользователя с информацией"""
    try:
        members = GroupMember.query.filter_by(username=username).all()
        
        groups_info = []
        for member in members:
            group = Group.query.filter_by(id=member.group_id).first()
            if group:
                groups_info.append({
                    'id': group.id,
                    'name': group.name,
                    'code': group.group_code,
                    'creator': group.creator,
                    'role': member.role,
                    'joined_at': member.format_time()
                })
        
        return groups_info
    except Exception as e:
        print(f"[ERROR] Failed to get user groups: {e}")
        return []

def get_group_info(group_id: int, include_members: bool = False) -> dict or None:
    """Возвращает информацию о группе"""
    try:
        group = Group.query.filter_by(id=group_id).first()
        if not group:
            return None
        
        info = {
            'id': group.id,
            'name': group.name,
            'code': group.group_code,
            'creator': group.creator,
            'created_at': group.format_time(),
            'max_members': group.max_members,
            'member_count': get_group_members_count(group_id)
        }
        
        if include_members:
            members = GroupMember.query.filter_by(group_id=group_id).all()
            info['members'] = [
                {'username': m.username, 'role': m.role, 'joined_at': m.format_time()}
                for m in members
            ]
        
        return info
    except Exception as e:
        print(f"[ERROR] Failed to get group info: {e}")
        return None

def delete_group(group_id: int) -> bool:
    """Удаляет группу и ВСЕ её сообщения, участников и файлы"""
    try:
        group = Group.query.filter_by(id=group_id).first()
        if not group:
            return False
        
        group_name = group.name
        group_code = group.group_code
        
        print(f"[INFO] Starting deletion of group {group_id} ({group_name}#{group_code})")
        
        print(f"[INFO] Finding files to delete...")
        messages = Message.query.filter_by(group_id=group_id).all()
        file_ids_to_delete = []
        
        for msg in messages:
            if msg.message_type in ('photo', 'file'):
                try:
                    plain = msg.get_plain()
                    if isinstance(plain, dict) and 'file_id' in plain:
                        file_ids_to_delete.append(plain['file_id'])
                except Exception as e:
                    print(f"[WARN] Could not parse file_id from message {msg.id}: {e}")
        
        #  2: Удаляем файлы с диска
        if file_ids_to_delete:
            print(f"[INFO] Deleting {len(file_ids_to_delete)} files from disk...")
            files = File.query.filter(File.id.in_(file_ids_to_delete)).all()
            for file_record in files:
                file_path = os.path.join(UPLOAD_FOLDER, file_record.filename)
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                        print(f"[OK] Deleted file: {file_path}")
                    except Exception as e:
                        print(f"[WARN] Failed to delete file {file_path}: {e}")
            
            # Удаляем записи файлов из БД
            File.query.filter(File.id.in_(file_ids_to_delete)).delete(synchronize_session=False)
            db.session.flush()
            print(f"[OK] File records deleted from DB")
        
        #  3: Удаляем все сообщения группы
        print(f"[INFO] Deleting messages for group {group_id}...")
        Message.query.filter_by(group_id=group_id).delete(synchronize_session=False)
        db.session.flush()
        print(f"[OK] Messages deleted")
        
        #  4: Удаляем всех участников группы
        print(f"[INFO] Deleting members for group {group_id}...")
        members = GroupMember.query.filter_by(group_id=group_id).all()
        for member in members:
            # Отзываем их сессии
            session_token_bytes = r.get(f"user_group_session:{member.username}:{group_id}")
            if session_token_bytes:
                revoke_group_session(session_token_bytes.decode("utf-8"))
        
        # Удаляем всех членов одним запросом
        GroupMember.query.filter_by(group_id=group_id).delete(synchronize_session=False)
        db.session.flush()
        print(f"[OK] Members deleted")
        
        #  5: Удаляем саму группу
        print(f"[INFO] Deleting group {group_id}...")
        Group.query.filter_by(id=group_id).delete(synchronize_session=False)
        db.session.flush()
        print(f"[OK] Group row deleted")
        
        #  6: Коммитим все изменения
        db.session.commit()
        print(f"[OK] Transaction committed")
        
        #  7: Удаляем из Redis
        r.delete(f"group_members:{group_id}")
        r.delete(f"group_members:online:{group_id}")
        r.delete(f"chat:group:{group_id}")
        
        print(f"[OK] Group {group_id} deleted completely with all messages, members and files")
        return True
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Failed to delete group: {e}")
        import traceback
        traceback.print_exc()
        return False

def delete_user_account(username: str) -> bool:
    """
    Удаляет пользователя и ВСЕ его данные:
    """
    try:
        print(f"[INFO] Starting deletion of account: {username}")
        
        #  1: Получаем всех групп, где пользователь - создатель
        print(f"[INFO] Finding groups created by {username}...")
        creator_groups = Group.query.filter_by(creator=username).all()
        
        for group in creator_groups:
            print(f"[INFO] Deleting creator group: {group.id} ({group.name})")
            delete_group(group.id)
        
        #  2: Удаляем пользователя из всех групп, где он - член
        print(f"[INFO] Removing {username} from all groups...")
        member_records = GroupMember.query.filter_by(username=username).all()
        
        for member in member_records:
            # Отзываем его сессии в этих группах
            session_token_bytes = r.get(f"user_group_session:{username}:{member.group_id}")
            if session_token_bytes:
                revoke_group_session(session_token_bytes.decode("utf-8"))
            
            db.session.delete(member)
        
        db.session.flush()
        print(f"[OK] Removed {username} from all groups")
        
        #  3: Находим все файлы пользователя
        print(f"[INFO] Finding files from {username}...")
        user_files = File.query.filter_by(username=username).all()
        file_ids_to_delete = [f.id for f in user_files]
        
        #  4: Удаляем файлы с диска
        if user_files:
            print(f"[INFO] Deleting {len(user_files)} files from disk...")
            for file_record in user_files:
                file_path = os.path.join(UPLOAD_FOLDER, file_record.filename)
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                        print(f"[OK] Deleted file: {file_path}")
                    except Exception as e:
                        print(f"[WARN] Failed to delete file {file_path}: {e}")
            
            # Удаляем записи файлов из БД
            File.query.filter(File.id.in_(file_ids_to_delete)).delete(synchronize_session=False)
            db.session.flush()
            print(f"[OK] File records deleted from DB")
        
        #  5: Удаляем все сообщения пользователя
        print(f"[INFO] Deleting all messages from {username}...")
        Message.query.filter_by(username=username).delete(synchronize_session=False)
        db.session.flush()
        print(f"[OK] Messages deleted")
        
        #  6: Удаляем сам аккаунт
        print(f"[INFO] Deleting user account: {username}...")
        user = User.query.filter_by(username=username).first()
        if user:
            db.session.delete(user)
            db.session.flush()
        
        #  7: Коммитим все изменения
        db.session.commit()
        print(f"[OK] Transaction committed")
        
        #  8: Очищаем Redis сессии
        print(f"[INFO] Cleaning up Redis sessions for {username}...")
        r.delete(f"user_sessions:{username}")
        r.delete(f"online_users:{username}")
        
        # Удаляем все auth tokens пользователя
        try:
            session_keys = r.keys(f"session_metadata:*")
            for key in session_keys:
                try:
                    metadata_bytes = r.get(key)
                    if metadata_bytes:
                        metadata = json.loads(metadata_bytes.decode("utf-8"))
                        if metadata.get('username') == username:
                            token = key.decode("utf-8").replace("session_metadata:", "")
                            r.delete(f"auth_token:{token}")
                            r.delete(f"session_metadata:{token}")
                except Exception as e:
                    pass
        except Exception as e:
            print(f"[WARN] Failed to cleanup all session keys: {e}")
        
        print(f"[OK] Account {username} deleted completely with all data")
        return True
        
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Failed to delete account: {e}")
        import traceback
        traceback.print_exc()
        return False

def extract_token_from_request() -> str or None:
    """Извлекает токен из запроса (заголовок, форма или HttpOnly cookie)"""
    
    #Проверяем Authorization заголовок (Bearer token)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if token:
            print(f"[DEBUG] Token from Authorization header: {token[:20]}...")
            return token
    
    #Проверяем форму (POST параметр)
    if request.method == "POST":
        token = request.form.get("token", "").strip()
        if token:
            print(f"[DEBUG] Token from form: {token[:20]}...")
            return token
    
    # Проверяем HttpOnly cookie
    token = request.cookies.get("auth_token", "").strip()
    if token:
        print(f"[DEBUG] Token from HttpOnly cookie: {token[:20]}...")
        return token
    
    print("[DEBUG] No token found in request (header, form, or cookie)")
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
        if response.mimetype == 'text/html' or request.path in ['/', '/login', '/register', '/groups']:
            if nonce:
                response.headers['Content-Security-Policy'] = (
                    f"default-src 'self'; "
                    f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
                    f"style-src 'self' 'unsafe-inline'; "
                    f"img-src 'self' data: https:; "
                    f"media-src 'self'; "
                    f"connect-src 'self';"
                )
            else:
                response.headers['Content-Security-Policy'] = (
                    "default-src 'self'; "
                    "script-src 'self' https://cdn.jsdelivr.net; "
                    "style-src 'self' 'unsafe-inline'; "
                    "img-src 'self' data:; "
                    "media-src 'self'; "
                    "connect-src 'self';"
                )
    
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    
    if is_production:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# ===============================================================
# ---- File Signed URL helpers ----
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

def generate_signed_file_url(file_token: str) -> dict:
    secret = get_or_create_signed_url_secret()
    expiration = int(time.time()) + FILE_URL_TTL
    
    message = f"{file_token}:{expiration}"
    signature = hmac.new(
        secret.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return {
        "token": file_token,
        "signature": signature,
        "expires": expiration
    }

def verify_signed_file_url(file_token: str, signature: str, expiration: str) -> bool:
    try:
        secret = get_or_create_signed_url_secret()
        exp_timestamp = int(expiration)
        
        if time.time() > exp_timestamp:
            print(f"[WARN] Signed URL expired: {file_token}")
            return False
        
        message = f"{file_token}:{exp_timestamp}"
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            print(f"[WARN] Invalid signature for file: {file_token}")
            return False
        
        return True
    except Exception as e:
        print(f"[ERROR] Signature verification failed: {e}")
        return False

def save_file(username: str, file_obj) -> tuple or None:
    """Save any supported file type"""
    try:
        file_data = file_obj.read()
        original_filename = file_obj.filename
        
        # Validate file
        validation_result = validate_file(file_data, original_filename)
        if not validation_result:
            return None
        
        # Распаковка результата валидации
        category, mime_type, safe_filename, ext, image_format = validation_result
        
        # ---- METADATA STRIPPING ----
        print(f"[INFO] Stripping metadata for {original_filename} ({category})")
        clean_data = strip_file_metadata(file_data, category, ext, image_format)
        if clean_data is None:
            print(f"[ERROR] Metadata stripping failed for {original_filename}. Aborting upload.")
            return None
        print(f"[OK] Metadata stripped. Size: {len(file_data)} -> {len(clean_data)}")
        # ---------------------------------------------------
        
        # Generate unique storage filename and token
        unique_filename = f"{secrets.token_urlsafe(32)}.bin"
        file_token = secrets.token_urlsafe(24)
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        
        # Encrypt and save
        encrypted_data = encrypt_file(clean_data)
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
        
        # Create File record
        file_record = File(
            username=username,
            filename=unique_filename,
            file_token=file_token,
            original_filename=safe_filename,
            file_category=category,
            filesize=len(clean_data),
            mime_type=mime_type
        )
        db.session.add(file_record)
        db.session.flush()
        
        # Create Message record
        message_type = 'photo' if category == 'photo' else 'file'
        file_data_json = json.dumps({
            "file_id": file_record.id,
            "file_token": file_token,
            "category": category,
            "filename": safe_filename
        })
        encrypted_content = encrypt_message(file_data_json)
        
        message = Message(
            username=username,
            content=encrypted_content,
            message_type=message_type,
            created_at=file_record.created_at
        )
        db.session.add(message)
        db.session.commit()
        
        print(f"[OK] File saved: {unique_filename} ({category}) by {username}, Message ID: {message.id}")
        return (file_record, message)
        
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Failed to save file: {e}")
        return None

def load_file_by_token(file_token: str) -> tuple or None:
    """Load and decrypt file by token"""
    try:
        file_record = File.query.filter_by(file_token=file_token).first()
        if not file_record:
            return None
        
        file_path = os.path.join(UPLOAD_FOLDER, file_record.filename)
        if not os.path.exists(file_path):
            print(f"[ERROR] File not found: {file_path}")
            return None
        
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = decrypt_file(encrypted_data)
        if decrypted_data is None:
            print(f"[ERROR] Could not decrypt file: {file_record.filename}")
            return None
        
        return (decrypted_data, file_record.mime_type, file_record.original_filename, file_record.file_category)
    except Exception as e:
        print(f"[ERROR] Failed to load file: {e}")
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
# ---- HELPER FUNCTIONS after Tor helpers section ----
# ===============================================================

def extract_youtube_id(url: str) -> str or None:
    """Extract YouTube video ID with better pattern matching"""
    patterns = [
        r'(?:youtube\.com/watch\?v=|youtu\.be/|youtube\.com/embed/)([a-zA-Z0-9_-]{11})',
        r'youtube\.com/shorts/([a-zA-Z0-9_-]{11})',
        r'youtube\.com/live/([a-zA-Z0-9_-]{11})'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    return None

def detect_service_type(url: str) -> str:
    """Detect which service the URL belongs to - IMPROVED"""
    url_lower = url.lower()
    
    # YouTube check (highest priority after exact match)
    if re.search(YOUTUBE_PATTERN, url_lower):
        return 'youtube'
    
    # Vimeo
    if re.search(VIMEO_PATTERN, url_lower):
        return 'vimeo'
    
    # Instagram
    if re.search(INSTAGRAM_PATTERN, url_lower):
        return 'instagram'
    
    # TikTok
    if re.search(TIKTOK_PATTERN, url_lower):
        return 'tiktok'
    
    # Image detection - УЛУЧШЕНО
    # Проверяем расширения
    if re.search(r'\.(jpg|jpeg|png|gif|webp|bmp)(?:\?|#|$)', url_lower):
        return 'image'
    
    # Проверяем паттерны CDN/хостингов изображений
    image_indicators = [
        r'/images?/',
        r'/img/',
        r'/photo/',
        r'/picture/',
        r'/thumb',
        r'gstatic\.com/',
        r'imgur\.com/',
        r'cloudinary\.com/',
        r'unsplash\.com/',
        r'pexels\.com/',
        r'pixabay\.com/',
        r'imagecdn',
        r'cdn.*image',
        r'fbcdn\.net',
        r'twimg\.com',
    ]
    
    for indicator in image_indicators:
        if re.search(indicator, url_lower):
            return 'image'
    
    return 'unknown'

def get_youtube_thumbnail(video_id: str) -> str or None:
    """Generate YouTube thumbnail URL with fallback chain"""
    try:
        # Try quality chain: maxresdefault -> hqdefault -> mqdefault -> default
        # We'll return maxresdefault and let browser/client handle fallback
        thumbnails = [
            f"https://img.youtube.com/vi/{video_id}/maxresdefault.jpg",
            f"https://img.youtube.com/vi/{video_id}/hqdefault.jpg",
            f"https://img.youtube.com/vi/{video_id}/mqdefault.jpg",
            f"https://img.youtube.com/vi/{video_id}/default.jpg"
        ]
        
        # Return highest quality, browser will fallback via onerror
        return thumbnails[0]
    except Exception as e:
        print(f"[WARN] Failed to generate YouTube thumbnail: {e}")
        return None

def get_oembed_preview(url: str, service_type: str) -> dict or None:
    """Fetch preview data via OEmbed API"""
    try:
        oembed_endpoints = {
            'vimeo': 'https://vimeo.com/api/oembed.json',
            'instagram': 'https://www.instagram.com/oembed',
            'tiktok': 'https://www.tiktok.com/oembed'
        }
        
        if service_type not in oembed_endpoints:
            return None
        
        endpoint = oembed_endpoints[service_type]
        
        session = get_tor_session()
        response = session.get(
            endpoint,
            params={'url': url},
            timeout=URL_PREVIEW_REQUEST_TIMEOUT,
            headers={
                'User-Agent': 'Mozilla/5.0',
                'Referer': 'https://example.com'
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                'title': data.get('title', '')[:URL_PREVIEW_MAX_TITLE_LENGTH],
                'thumbnail_url': data.get('thumbnail_url'),
                'description': (data.get('description', '') or '')[:URL_PREVIEW_MAX_DESCRIPTION_LENGTH]
            }
    except Exception as e:
        print(f"[WARN] OEmbed failed for {service_type}: {e}")
    
    return None

def validate_image_url(url: str) -> bool:
    """
    Validate that URL is a real image - AGGRESSIVE approach
    Prioritizes showing images over strict validation
    """
    try:
        url_lower = url.lower()
        
        # First: Direct image extensions (most reliable)
        if re.search(r'\.(jpg|jpeg|png|gif|webp|bmp|svg)(?:\?|#|$)', url_lower):
            print(f"[OK] Image validated by extension: {url[:80]}")
            return True
        
        # Second: Known CDN patterns that ALWAYS serve images
        cdn_patterns = [
            r'i\.natgeofe\.com',
            r'cdn\.pixabay\.com',
            r'images\.unsplash\.com',
            r'i\.imgur\.com',
            r'media\.giphy\.com',
            r'substackcdn\.com',
            r'images\.pexels\.com',
            r'static\.wikia\.nocookie\.net',
            r'upload\.wikimedia\.org',
            r'.*\.cloudfront\.net.*\.(jpg|jpeg|png|gif|webp)',
            r'.*\.akamaihd\.net.*\.(jpg|jpeg|png|gif|webp)',
            r'pbs\.twimg\.com/media',
            r'scontent.*\.fbcdn\.net',
            r'.*\.googleusercontent\.com',
        ]
        
        for pattern in cdn_patterns:
            if re.search(pattern, url_lower):
                print(f"[OK] Image validated by CDN pattern: {url[:80]}")
                return True
        
        # Third: URL path/query contains image keywords
        if re.search(r'(/image/|/img/|/photo/|/picture/|/thumbnail/|image_url=|img_url=)', url_lower):
            print(f"[OK] Image validated by path keyword: {url[:80]}")
            return True
        
        # Fourth: Try HEAD request with AGGRESSIVE headers (last resort)
        try:
            session = get_tor_session()
            response = session.head(
                url,
                timeout=3,
                allow_redirects=True,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Referer': 'https://www.google.com/',
                    'DNT': '1',
                    'Sec-Fetch-Dest': 'image',
                    'Sec-Fetch-Mode': 'no-cors',
                    'Sec-Fetch-Site': 'cross-site'
                }
            )
            
            content_type = response.headers.get('content-type', '').lower()
            
            # Check content-type
            if any(img_type in content_type for img_type in ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp', 'image/']):
                print(f"[OK] Image validated by HEAD content-type: {url[:80]}")
                return True
            
            # Some servers return 200 even for HEAD on images
            if response.status_code == 200:
                print(f"[OK] Image validated by HEAD 200: {url[:80]}")
                return True
                
        except Exception as e:
            print(f"[INFO] HEAD request failed for {url[:80]}: {e}")
            # If HEAD fails but URL looks like image, ACCEPT IT
            if re.search(r'(image|img|photo|picture|thumb)', url_lower):
                print(f"[OK] Image validated by fallback keyword match: {url[:80]}")
                return True
        
        # Final fallback: if URL has common image hosting domains
        image_hosts = [
            'imgur', 'flickr', 'photobucket', 'tinypic', 'imageshack',
            'postimg', 'imgbb', 'imgbox', 'gyazo', 'prnt.sc'
        ]
        
        if any(host in url_lower for host in image_hosts):
            print(f"[OK] Image validated by image host: {url[:80]}")
            return True
        
        print(f"[WARN] Could not validate image: {url[:80]}")
        return False
        
    except Exception as e:
        print(f"[ERROR] Image validation failed: {e}")
        # AGGRESSIVE: If in doubt, accept it
        if re.search(r'(\.jpg|\.jpeg|\.png|\.gif|\.webp|image|img|photo)', url.lower()):
            print(f"[OK] Image validated by exception fallback: {url[:80]}")
            return True
        return False

# ===============================================================
# ---- ИЗМЕНЕННАЯ ФУНКЦИЯ ----
# ===============================================================
def fetch_url_preview(url: str) -> dict or None:
    """Main function to fetch URL preview data - IMPROVED v2"""
    try:
        # Normalize URL
        if not url.startswith('http'):
            url = 'https://' + url
        
        # Check cache first
        cached = URLPreview.query.filter_by(url=url).first()
        if cached and not cached.is_expired():
            print(f"[OK] Using cached preview for {url[:80]}")
            return {
                'service_type': cached.service_type,
                'title': cached.title,
                'thumbnail_url': cached.thumbnail_url,
                'description': cached.description
            }
        
        # Detect service
        service_type = detect_service_type(url)
        print(f"[INFO] Fetching preview for {service_type}: {url[:80]}")
        
        preview_data = {
            'service_type': service_type,
            'title': None,
            'thumbnail_url': None,
            'description': None
        }
        
        # Get service-specific preview
        if service_type == 'youtube':
            video_id = extract_youtube_id(url)
            if video_id:
                preview_data['title'] = 'YouTube Video'
                preview_data['thumbnail_url'] = get_youtube_thumbnail(video_id)
                print(f"[OK] YouTube thumbnail: {preview_data['thumbnail_url']}")
            else:
                preview_data['title'] = 'YouTube Video'
                print(f"[WARN] Could not extract YouTube ID from {url[:80]}")
        
        elif service_type in ('vimeo', 'instagram', 'tiktok'):
            oembed_data = get_oembed_preview(url, service_type)
            if oembed_data:
                preview_data.update(oembed_data)
                print(f"[OK] OEmbed preview loaded for {service_type}")
            else:
                print(f"[WARN] OEmbed failed for {service_type}: {url[:80]}")
        
        elif service_type == 'image':
            print(f"[INFO] Validating image URL: {url[:80]}")
            if validate_image_url(url):
                preview_data['title'] = 'Image'
                preview_data['thumbnail_url'] = url
                print(f"[OK] Image preview set: {url[:80]}")
            else:
                # Even if validation fails, still try to show it
                print(f"[WARN] Image validation failed, but setting thumbnail anyway: {url[:80]}")
                preview_data['title'] = 'Image'
                preview_data['thumbnail_url'] = url
        
        elif service_type == 'unknown':
            # НОВОЕ: Попытка обработать unknown как возможное изображение
            print(f"[INFO] Unknown URL type, checking if it's an image: {url[:80]}")
            if validate_image_url(url):
                preview_data['service_type'] = 'image'
                preview_data['title'] = 'Image'
                preview_data['thumbnail_url'] = url
                print(f"[OK] Unknown URL detected as image: {url[:80]}")
        
        # Save to cache
        ttl = datetime.datetime.utcnow() + datetime.timedelta(seconds=URL_PREVIEW_CACHE_TTL)
        
        existing = URLPreview.query.filter_by(url=url).first()
        if existing:
            existing.service_type = preview_data['service_type']
            existing.title = preview_data['title']
            existing.thumbnail_url = preview_data['thumbnail_url']
            existing.description = preview_data['description']
            existing.cached_at = datetime.datetime.utcnow()
            existing.ttl = ttl
        else:
            preview_obj = URLPreview(
                url=url,
                service_type=preview_data['service_type'],
                title=preview_data['title'],
                thumbnail_url=preview_data['thumbnail_url'],
                description=preview_data['description'],
                ttl=ttl
            )
            db.session.add(preview_obj)
        
        db.session.commit()
        
        print(f"[OK] Preview cached for {preview_data['service_type']}: thumbnail={preview_data['thumbnail_url'] is not None}")
        return preview_data
    
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Failed to fetch URL preview for {url[:80]}: {e}")
        import traceback
        traceback.print_exc()
        return None
# ===============================================================


def extract_urls_from_text(text: str) -> list:
    """Extract all URLs from message text"""
    urls = URL_PATTERN.findall(text)
    
    # Deduplicate and limit
    unique_urls = list(set(urls))[:MAX_URLS_PER_MESSAGE]
    
    return unique_urls

def get_previews_for_urls(urls: list) -> dict:
    """Get preview data for all URLs in a list"""
    previews = {}
    
    for url in urls:
        preview = fetch_url_preview(url)
        if preview:
            previews[url] = preview
    
    return previews


# ===============================================================
# ---- Message formatting helpers ----
# ===============================================================
def format_message_for_sse(msg: Message) -> str:
    """Format message for SSE with signed URLs and UTC timestamp"""
    ts = msg.format_time()  # Unix timestamp
    
    if msg.message_type == 'photo':
        plain = msg.get_plain()
        if isinstance(plain, dict) and 'file_id' in plain:
            file_id = plain['file_id']
            file_record = File.query.filter_by(id=file_id).first()
            
            if file_record:
                signed_data = generate_signed_file_url(file_record.file_token)
                file_url = f"/file/{signed_data['token']}?sig={signed_data['signature']}&exp={signed_data['expires']}"
                return f"[{ts}] {msg.username}: [PHOTO:{file_id}:{file_url}]"
            else:
                return f"[{ts}] {msg.username}: [PHOTO:{file_id}]"
        return f"[{ts}] {msg.username}: [PHOTO]"
    
    elif msg.message_type == 'file':
        plain = msg.get_plain()
        if isinstance(plain, dict) and 'file_id' in plain:
            file_id = plain['file_id']
            file_record = File.query.filter_by(id=file_id).first()
            
            if file_record:
                signed_data = generate_signed_file_url(file_record.file_token)
                file_url = f"/file/{signed_data['token']}?sig={signed_data['signature']}&exp={signed_data['expires']}"
                category = plain.get('category', 'file')
                
                if category == 'audio':
                    return f"[{ts}] {msg.username}: [AUDIO:{file_id}:{file_url}]"
                elif category == 'video':
                    return f"[{ts}] {msg.username}: [VIDEO:{file_id}:{file_url}]"
                else:
                    filename = plain.get('filename', 'file')
                    return f"[{ts}] {msg.username}: [FILE:{file_id}:{category}:{filename}:{file_url}]"
            else:
                category = plain.get('category', 'file')
                if category == 'audio':
                    return f"[{ts}] {msg.username}: [AUDIO:{file_id}]"
                elif category == 'video':
                    return f"[{ts}] {msg.username}: [VIDEO:{file_id}]"
                else:
                    filename = plain.get('filename', 'file')
                    return f"[{ts}] {msg.username}: [FILE:{file_id}:{category}:{filename}]"
        return f"[{ts}] {msg.username}: [FILE]"

# ===============================================================
# ---- DELETE MESSAGE FUNCTION ----
# ===============================================================

def can_delete_message(username: str, message_id: int) -> bool:
    """Проверить может ли пользователь удалить сообщение (только автор)"""
    msg = Message.query.filter_by(id=message_id).first()
    if not msg:
        return False
    
    # Только автор сообщения может его удалить
    return msg.username == username

def delete_message_by_id(message_id: int) -> bool:
    try:
        msg = Message.query.filter_by(id=message_id).first()
        
        if not msg:
            print(f"[WARN] Message {message_id} not found")
            return False
        
        group_id = msg.group_id
        print(f"[INFO] Starting deletion of message {message_id} from group {group_id}")
        
        # Если это фото или файл - удалить файл с диска
        if msg.message_type in ('photo', 'file'):
            try:
                plain = msg.get_plain()
                if isinstance(plain, dict) and 'file_id' in plain:
                    file_id = plain['file_id']
                    file_record = File.query.filter_by(id=file_id).first()
                    
                    if file_record:
                        file_path = os.path.join(UPLOAD_FOLDER, file_record.filename)
                        
                        # Удалить физический файл
                        if os.path.exists(file_path):
                            try:
                                os.remove(file_path)
                                print(f"[OK] Deleted file from disk: {file_path}")
                            except Exception as e:
                                print(f"[WARN] Failed to delete file from disk: {e}")
                        
                        # Удалить запись файла из БД
                        try:
                            db.session.delete(file_record)
                            db.session.flush()
                            print(f"[OK] Deleted file record from DB: {file_id}")
                        except Exception as e:
                            print(f"[ERROR] Failed to delete file record: {e}")
                            db.session.rollback()
                            return False
                    else:
                        print(f"[WARN] File record not found: {file_id}")
            except Exception as e:
                print(f"[WARN] Error processing file deletion: {e}")
        
        # Удалить само сообщение из БД
        try:
            db.session.delete(msg)
            db.session.flush()
            print(f"[OK] Message record deleted from DB")
        except Exception as e:
            print(f"[ERROR] Failed to delete message record: {e}")
            db.session.rollback()
            return False
        
        # КОММИТИМ все изменения ОДИН раз
        try:
            db.session.commit()
            print(f"[OK] Transaction committed successfully")
        except Exception as e:
            print(f"[ERROR] Failed to commit transaction: {e}")
            db.session.rollback()
            return False
        
        # ПОСЛЕ успешного коммита - публикуем событие удаления
        if group_id:
            try:
                delete_notification = f"DELETE_MESSAGE:{message_id}"
                r.publish(f"chat:group:{group_id}", delete_notification.encode("utf-8"))
                print(f"[OK] Published delete notification: {delete_notification}")
            except Exception as e:
                print(f"[WARN] Failed to publish delete notification: {e}")
        
        print(f"[OK] Message {message_id} deleted completely (group: {group_id})")
        return True
        
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Failed to delete message: {e}")
        import traceback
        traceback.print_exc()
        return False

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per 15 minutes", methods=["POST"])
def register():
    if request.method == "POST":
        # Для AJAX запросов возвращаем JSON
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        
        if request.is_json:
            data = request.get_json()
            username = data.get("user", "").strip()
            password = data.get("password", "").strip()
        else:
            username = request.form.get("user", "").strip()
            password = request.form.get("password", "").strip()
        
        print(f"[DEBUG] Register POST: username='{username}', password_len={len(password)}, is_ajax={is_ajax}")

        valid_username, username_error = validate_username(username)
        if not valid_username:
            try:
                argon2Hasher.verify(DUMMY_HASH, password)
            except:
                pass
            
            print(f"[WARN] Invalid username: {username_error}")
            if is_ajax:
                return jsonify({"error": username_error}), 400
            
            nonce = generate_nonce()
            request._csp_nonce = nonce
            return render_template("register.html", nonce=nonce, error=username_error), 400

        valid_password, password_error = validate_password(password)
        if not valid_password:
            try:
                argon2Hasher.verify(DUMMY_HASH, password)
            except:
                pass
            
            print(f"[WARN] Invalid password: {password_error}")
            if is_ajax:
                return jsonify({"error": password_error}), 400
            
            nonce = generate_nonce()
            request._csp_nonce = nonce
            return render_template("register.html", nonce=nonce, error=password_error), 400

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"[WARN] User already exists: {username}")
            if is_ajax:
                return jsonify({"error": "A user with this name already EXISTS."}), 400
            
            nonce = generate_nonce()
            request._csp_nonce = nonce
            return render_template("register.html", nonce=nonce, error="A user with this name already EXISTS."), 400

        try:
            password_hash = argon2Hasher.hash(password)
            new_user = User(username=username, password_hash=password_hash)
            db.session.add(new_user)
            db.session.commit()
            
            print(f"[OK] User registered: {username}")
            
            if is_ajax:
                return jsonify({"success": True, "message": "Account created successfully!"}), 201
            
            return redirect("/login")
        except Exception as e:
            db.session.rollback()
            print(f"[ERROR] Registration failed: {e}")
            if is_ajax:
                return jsonify({"error": "Registration failed. Please try again."}), 500
            nonce = generate_nonce()
            request._csp_nonce = nonce
            return render_template("register.html", nonce=nonce, error="Registration failed. Please try again."), 500

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
            return jsonify({"error": "INCORRECT username or password"}), 400

        valid_password, password_error = validate_password(password)
        if not valid_password:
            try:
                argon2Hasher.verify(DUMMY_HASH, password)
            except:
                pass
            return jsonify({"error": "INCORRECT username or password"}), 400

        user = User.query.filter_by(username=username).first()
        if not user:
            try:
                argon2Hasher.verify(DUMMY_HASH, password)
            except:
                pass
            return jsonify({"error": "INCORRECT username or password"}), 400

        try:
            argon2Hasher.verify(user.password_hash, password)
            auth_token, old_token = generate_auth_token(username)
            
            print(f"[OK] Login successful for {username}, token: {auth_token[:20]}...")
            
            response = make_response(jsonify({
                "success": True,
                "token": auth_token,
                "username": username,
                "redirect": "/groups"
            }))
            
            # Устанавливаем HttpOnly cookie для автоматической отправки
            response.set_cookie(
                'auth_token',
                auth_token,
                max_age=AUTH_TOKEN_TTL,
                httponly=True,
                secure=is_production,
                samesite='Lax'
            )
            
            return response, 200
            
        except VerifyMismatchError:
            return jsonify({"error": "INCORRECT username or password"}), 400

    nonce = generate_nonce()
    request._csp_nonce = nonce
    return render_template("login.html", nonce=nonce)

# ===============================================================
# ---- Group Management Routes ----
# ===============================================================

@app.route("/groups", methods=["GET"])
@limiter.limit("30 per minute")
def list_groups():
    token = extract_token_from_request()
    
    # Если нет - пытаемся из cookie
    if not token:
        token = request.cookies.get('auth_token', '').strip()
        print(f"[DEBUG] Token from cookie: {token[:20] if token else 'None'}...")
    
    username = verify_token(token, strict_ip_check=False)
    
    if not username:
        print(f"[WARN] User not authenticated")
        return redirect("/login")
    
    print(f"[OK] User {username} accessing /groups")
    
    nonce = generate_nonce()
    request._csp_nonce = nonce
    
    try:
        user_groups = get_user_groups(username)
        print(f"[OK] Found {len(user_groups)} groups for {username}")
    except Exception as e:
        print(f"[ERROR] Failed to get user groups: {e}")
        user_groups = []
    
    response = make_response(render_template(
        "groups.html", 
        user=username, 
        groups=user_groups, 
        nonce=nonce
    ))
    
    # Обновляем cookie чтобы сессия не истекла
    if token:
        response.set_cookie(
            'auth_token',
            token,
            max_age=AUTH_TOKEN_TTL,
            httponly=True,
            secure=is_production,
            samesite='Lax'
        )
    
    return response

@app.route("/api/groups/list", methods=["GET"])
@limiter.limit("20 per minute")
def api_list_groups():
    """API endpoint для получения списка групп пользователя"""
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return jsonify({"error": "Unauthorized"}), 401
    
    groups = get_user_groups(username)
    
    return jsonify({"groups": groups}), 200

@app.route("/api/groups/create", methods=["POST"])
@limiter.limit("5 per hour")
def api_create_group():
    """Создание новой группы"""
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400
    
    group_name = data.get("name", "").strip()
    password = data.get("password", "").strip()
    root_password = data.get("root_password", "").strip()
    max_members = data.get("max_members", 100)
    
    # Валидация
    if not group_name or len(group_name) < 3 or len(group_name) > 50:
        return jsonify({"error": "Group name must be 3-50 characters"}), 400
    
    if not password or len(password) < 8 or len(password) > 128:
        return jsonify({"error": "Password must be 8-128 characters"}), 400
    
    if not root_password or len(root_password) < 8 or len(root_password) > 128:
        return jsonify({"error": "Root password must be 8-128 characters"}), 400
    
    if password == root_password:
        return jsonify({"error": "Passwords cannot be the same"}), 400
    
    if not isinstance(max_members, int) or max_members < 2 or max_members > 1000:
        return jsonify({"error": "Max members must be 2-1000"}), 400
    
    try:
        # Генерируешь уникальный код
        group_code = generate_group_code()
        
        # Хешируешь пароли
        password_hash = argon2Hasher.hash(password)
        root_password_hash = argon2Hasher.hash(root_password)
        
        # Создаешь группу
        group = Group(
            name=group_name,
            group_code=group_code,
            creator=username,
            password_hash=password_hash,
            root_password_hash=root_password_hash,
            max_members=max_members
        )
        db.session.add(group)
        db.session.flush()  # Чтобы получить ID
        
        # Добавляешь создателя как CREATOR
        member = GroupMember(
            group_id=group.id,
            username=username,
            role='creator'
        )
        db.session.add(member)
        db.session.commit()
        
        # Инициализируешь в Redis
        r.sadd(f"group_members:{group.id}", username)
        r.sadd(f"group_members:online:{group.id}", username)
        
        print(f"[OK] Group created: {group.name}#{group.group_code} by {username}")
        
        return jsonify({
            "success": True,
            "group_id": group.id,
            "group_code": group.group_code,
            "message": f"Group '{group_name}#{group_code}' created successfully"
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Failed to create group: {e}")
        return jsonify({"error": "Failed to create group"}), 500

@app.route("/api/groups/join", methods=["POST"])
@limiter.limit("10 per hour; 60 per day")
def api_join_group():
    """Присоединение к существующей группе"""
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400
    
    group_code = data.get("group_code", "").strip().upper()
    password = data.get("password", "").strip()
    
    if not group_code or len(group_code) != 8:
        return jsonify({"error": "Invalid group code"}), 400
    
    if not password:
        return jsonify({"error": "Password required"}), 400
    
    # Rate limiting для защиты от брутфорса
    ip = get_remote_address()
    rate_key = f"group_join_attempt:{group_code}:{ip}"
    attempts = r.get(rate_key)
    
    if attempts and int(attempts) >= 5:
        return jsonify({"error": "Too many attempts. Try again later."}), 429
    
    try:
        # Ищешь группу
        group = Group.query.filter_by(group_code=group_code).first()
        
        if not group:
            r.incr(rate_key)
            r.expire(rate_key, 900)  # 15 минут
            return jsonify({"error": "Invalid group code or password"}), 401
        
        # Проверяешь пароль
        try:
            argon2Hasher.verify(group.password_hash, password)
        except VerifyMismatchError:
            r.incr(rate_key)
            r.expire(rate_key, 900)
            return jsonify({"error": "Invalid group code or password"}), 401
        
        # Проверяешь максимум участников
        if get_group_members_count(group.id) >= group.max_members:
            return jsonify({"error": "Group is full"}), 403
        
        # Добавляешь в группу
        success = add_user_to_group(group.id, username, 'member')
        if not success:
            return jsonify({"error": "Failed to join group"}), 500
        
        # Генерируешь сессию
        session_token = generate_group_session_token(username, group.id)
        
        # Очищаешь counter после успеха
        r.delete(rate_key)
        
        print(f"[OK] User {username} joined group {group.group_code}")
        
        return jsonify({
            "success": True,
            "group_id": group.id,
            "session_token": session_token,
            "message": f"Successfully joined '{group.name}#{group.group_code}'"
        }), 200
        
    except Exception as e:
        print(f"[ERROR] Failed to join group: {e}")
        return jsonify({"error": "Failed to join group"}), 500

@app.route("/api/groups/<int:group_id>/info", methods=["GET"])
@limiter.limit("30 per minute")
def api_group_info(group_id: int):
    """Получает информацию о группе и список участников"""
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Проверяешь что юзер в группе
    if not is_user_in_group(username, group_id):
        return jsonify({"error": "Not a member of this group"}), 403
    
    group_info = get_group_info(group_id, include_members=True)
    
    if not group_info:
        return jsonify({"error": "Group not found"}), 404
    
    # Добавляешь информацию об онлайн статусе
    online_members = r.smembers(f"group_members:online:{group_id}")
    online_members = [m.decode("utf-8") if isinstance(m, bytes) else m for m in online_members]
    
    group_info['online_members'] = online_members
    
    return jsonify(group_info), 200

@app.route("/api/groups/<int:group_id>/leave", methods=["POST"])
@limiter.limit("30 per minute")
def api_leave_group(group_id: int):
    """Выход из группы"""
    token = extract_token_from_request()
    session = verify_group_session(token)
    
    if not session:
        return jsonify({"error": "Unauthorized"}), 401
    
    username = session['username']
    
    # Проверяешь что это правильная группа
    if session['group_id'] != group_id:
        return jsonify({"error": "Invalid group"}), 403
    
    # Удаляешь из группы
    remove_user_from_group(group_id, username)
    
    print(f"[OK] User {username} left group {group_id}")
    
    return jsonify({"success": True, "message": "Left the group"}), 200

@app.route("/api/groups/<int:group_id>/delete", methods=["POST"])
@limiter.limit("5 per hour")
def api_delete_group(group_id: int):
    # Используем основной auth токен, не групповой
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        print(f"[WARN] Delete attempt without valid auth token")
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400
    
    root_password = data.get("root_password", "").strip()
    
    if not root_password:
        return jsonify({"error": "Root password required"}), 400
    
    try:
        group = Group.query.filter_by(id=group_id).first()
        
        if not group:
            return jsonify({"error": "Group not found"}), 404
        
        # Сохраняем информацию о группе ДО удаления
        group_name = group.name
        group_code = group.group_code
        
        # Проверяем, что это создатель группы
        if group.creator != username:
            print(f"[SECURITY] Unauthorized delete attempt by {username} on group {group_id} (creator: {group.creator})")
            return jsonify({"error": "Only creator can delete group"}), 403
        
        # Проверяем root-пароль
        try:
            argon2Hasher.verify(group.root_password_hash, root_password)
        except VerifyMismatchError:
            print(f"[SECURITY] Invalid root password attempt on group {group_id} by {username}")
            return jsonify({"error": "Invalid root password"}), 403
        
        # Удаляем группу
        success = delete_group(group_id)
        
        if not success:
            return jsonify({"error": "Failed to delete group"}), 500
        
        return jsonify({
            "success": True,
            "message": f"Group '{group_name}#{group_code}' deleted successfully"
        }), 200
        
    except Exception as e:
        print(f"[ERROR] Failed to delete group: {e}")
        return jsonify({"error": "Failed to delete group"}), 500

@app.route("/api/sessions/list", methods=["GET"])
@limiter.limit("30 per minute")
def api_list_sessions():
    """Получить все активные сессии пользователя"""
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return jsonify({"error": "Unauthorized"}), 401
    
    sessions = get_all_user_sessions(username)
    
    # Добавляем информацию о текущей сессии
    current_token = token
    
    for session in sessions:
        session['is_current'] = (session['token'] == current_token)
        # Форматируем timestamp'ы
        session['created_at_formatted'] = datetime.datetime.fromtimestamp(
            session['created_at'], tz=datetime.timezone.utc
        ).isoformat() + 'Z'
        session['last_activity_formatted'] = datetime.datetime.fromtimestamp(
            session['last_activity'], tz=datetime.timezone.utc
        ).isoformat() + 'Z'
    
    return jsonify({"sessions": sessions}), 200

@app.route("/api/sessions/<session_token>/terminate", methods=["POST"])
@limiter.limit("30 per minute")
def api_terminate_session(session_token: str):
    """Завершить конкретную сессию"""
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return jsonify({"error": "Unauthorized"}), 401
    
    if session_token == token:
        # Завершение текущей сессии = выход
        terminate_session(session_token, username)
        return jsonify({"success": True, "message": "Session terminated. Logging out..."}), 200
    else:
        # Завершение другой сессии
        success = terminate_session(session_token, username)
        
        if not success:
            return jsonify({"error": "Session not found or not yours"}), 403
        
        return jsonify({"success": True, "message": "Session terminated"}), 200

@app.route("/api/sessions/terminate-all", methods=["POST"])
@limiter.limit("10 per hour")
def api_terminate_all_sessions():
    """Завершить все остальные сессии"""
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return jsonify({"error": "Unauthorized"}), 401
    
    success = terminate_all_other_sessions(token, username)
    
    if success:
        return jsonify({"success": True, "message": "All other sessions terminated"}), 200
    else:
        return jsonify({"error": "Failed to terminate sessions"}), 500

@app.route("/api/sessions/<session_token>/update-activity", methods=["POST"])
@limiter.limit("60 per minute")
def api_update_session_activity(session_token: str):
    """Обновить время последней активности сессии"""
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return jsonify({"error": "Unauthorized"}), 401
    
    if token != session_token:
        return jsonify({"error": "Token mismatch"}), 403
    
    try:
        metadata_bytes = r.get(f"session_metadata:{token}")
        if not metadata_bytes:
            return jsonify({"error": "Session not found"}), 404
        
        metadata = json.loads(metadata_bytes.decode("utf-8"))
        metadata['last_activity'] = int(time.time())
        
        r.setex(
            f"session_metadata:{token}",
            SESSION_METADATA_TTL,
            json.dumps(metadata).encode("utf-8")
        )
        
        return jsonify({"success": True}), 200
    except Exception as e:
        print(f"[ERROR] Failed to update session activity: {e}")
        return jsonify({"error": "Failed to update"}), 500

@app.route("/group/<int:group_id>/chat")
@limiter.limit("100 per minute")
def group_chat(group_id: int):
    token = extract_token_from_request()
    username = verify_token(token, strict_ip_check=False)
    
    if not username:
        print(f"[WARN] Unauthenticated access to /group/{group_id}/chat")
        return redirect("/login")
    
    if not is_user_in_group(username, group_id):
        print(f"[SECURITY] User {username} tried to access group {group_id} without membership")
        return redirect("/groups")
    
    print(f"[OK] User {username} entering group {group_id} chat")
    
    # Mark user online in this group
    mark_user_online_in_group(username, group_id)
    mark_user_online_global(username)
    
    group = Group.query.filter_by(id=group_id).first()
    group_name = group.name if group else "Unknown Group"
    
    # Проверяем, есть ли уже сессия для этого пользователя в этой группе
    existing_session_bytes = r.get(f"user_group_session:{username}:{group_id}")
    if existing_session_bytes:
        # Используем существующую сессию
        group_session_token = existing_session_bytes.decode("utf-8")
        print(f"[OK] Reusing existing group session for {username} in group {group_id}")
    else:
        # Создаем новую сессию
        group_session_token = generate_group_session_token(username, group_id)
    
    nonce = generate_nonce()
    request._csp_nonce = nonce
    
    response = make_response(render_template(
        "group_chat.html", 
        auth_token=group_session_token,
        user=username, 
        group_id=group_id,
        group_name=group_name,
        nonce=nonce
    ))
    
    # Устанавливаем правильный CSP с nonce
    response.headers['Content-Security-Policy'] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
        f"style-src 'self' 'unsafe-inline'; "
        f"img-src 'self' data: https:; "
        f"media-src 'self'; "
        f"connect-src 'self';"
    )
    
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    
    if is_production:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response
    
@app.route("/api/groups/<int:group_id>/members", methods=["GET"])
@limiter.limit("30 per minute")
def api_get_group_members(group_id: int):
    """Get members with correct online status"""
    token = extract_token_from_request()
    session = verify_group_session(token)
    
    if not session:
        return abort(401)
    
    if session['group_id'] != group_id:
        return abort(403)
    
    username = session['username']
    
    if not is_user_in_group(username, group_id):
        return abort(403)
    
    try:
        members = GroupMember.query.filter_by(group_id=group_id).all()
        
        members_list = []
        for member in members:
            # Check if user is online globally
            is_online = is_user_online_global(member.username)
            
            members_list.append({
                'username': member.username,
                'role': member.role,
                'joined_at': member.format_time(),
                'is_online': is_online
            })
        
        # Sort: online first, then creator, then by username
        members_list.sort(key=lambda x: (not x['is_online'], x['role'] != 'creator', x['username']))
        
        return jsonify({
            'members': members_list,
            'total': len(members_list)
        }), 200
        
    except Exception as e:
        print(f"[ERROR] Failed to get group members: {e}")
        return jsonify({"error": "Failed to get members"}), 500

@app.route("/api/groups/<int:group_id>/members/online", methods=["POST"])
@limiter.limit("60 per minute")
def api_set_member_online(group_id: int):
    token = extract_token_from_request()
    session = verify_group_session(token)

    if not session:
        return abort(401)

    if session['group_id'] != group_id:
        return abort(403)

    username = session['username']

    if not is_user_in_group(username, group_id):
        return abort(403)

    try:
        # Mark online in this group
        mark_user_online_in_group(username, group_id)
        # Also mark online globally
        mark_user_online_global(username)

        return jsonify({"success": True}), 200
    except Exception as e:
        print(f"[ERROR] Failed to set member online: {e}")
        return jsonify({"error": "Failed to update status"}), 500

@app.route("/api/user/online", methods=["POST"])
@limiter.limit("30 per minute")
def api_mark_user_online():
    """Mark user as online (global heartbeat from groups.html)"""
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return jsonify({"error": "Unauthorized"}), 401
    
    success = mark_user_online_global(username)
    
    if success:
        return jsonify({"success": True}), 200
    else:
        return jsonify({"error": "Failed to update status"}), 500

# ===============================================================
# ---- DELETE MESSAGE API ROUTE ----
# ===============================================================

@app.route("/group/<int:group_id>/message/<int:message_id>/delete", methods=["POST"])
@limiter.limit("30 per minute")
def api_delete_message(group_id: int, message_id: int):
    """
    Удалить сообщение (только автор может удалить свое сообщение)
    """
    token = extract_token_from_request()
    
    if not token:
        return abort(401)
    
    session = verify_group_session(token)
    
    if not session:
        return abort(401)
    
    if session['group_id'] != group_id:
        return abort(403)
    
    username = session['username']
    
    if not is_user_in_group(username, group_id):
        return abort(403)
    
    # Проверить, может ли пользователь удалить это сообщение
    if not can_delete_message(username, message_id):
        print(f"[SECURITY] User {username} tried to delete message {message_id} (not author)")
        return jsonify({"error": "You can only delete your own messages"}), 403
    
    # Удалить сообщение
    success = delete_message_by_id(message_id)
    
    if not success:
        return jsonify({"error": "Failed to delete message"}), 500
    
    # Продлить сессию
    updated_session_data = session.copy()
    updated_session_data['last_activity'] = int(time.time())
    
    pipe = r.pipeline()
    pipe.multi()
    pipe.setex(f"group_session:{token}", AUTH_TOKEN_TTL, json.dumps(updated_session_data).encode("utf-8"))
    pipe.setex(f"user_group_session:{username}:{group_id}", AUTH_TOKEN_TTL, token.encode("utf-8"))
    pipe.execute()
    
    return jsonify({"success": True, "message": "Message deleted"}), 200

# ===============================================================
# ---- Chat message routes (для групп) ----
# ===============================================================

def save_message_to_group(username: str, group_id: int, content: str):
    """Save text message to group with URL preview extraction"""
    sanitized_content = sanitize_text(content)

    if not sanitized_content:
        return None
    
    if len(sanitized_content) > MAX_MESSAGE_LENGTH:
        return None

    # Extract URLs from message
    urls = extract_urls_from_text(sanitized_content)
    url_previews = {}
    
    if urls:
        url_previews = get_previews_for_urls(urls)
    
    # Store message data with previews
    message_data = {
        'text': sanitized_content,
        'urls': url_previews
    }
    
    plaintext = json.dumps(message_data)
    ciphertext = encrypt_message(plaintext)
    
    msg = Message(
        group_id=group_id,  # ДОБАВЛЕНО
        username=username, 
        content=ciphertext,
        message_type='text'
    )
    db.session.add(msg)
    db.session.commit()
    
    # Publish to Redis для этой группы
    ts = msg.format_time()
    message_text = f"[{ts}] {username}: {sanitized_content}|URLS:{json.dumps(url_previews)}"
    r.publish(f"chat:group:{group_id}", message_text.encode("utf-8"))
    
    increment_message_count()
    
    return msg

def event_stream_group(group_id: int):
    """SSE stream - для определенной группы"""
    pubsub = r.pubsub(ignore_subscribe_messages=True)
    pubsub.subscribe(f"chat:group:{group_id}")
    
    for message in pubsub.listen():
        data = message.get("data")
        if isinstance(data, bytes):
            try:
                data = data.decode("utf-8")
            except Exception:
                data = str(data)
        yield f"data: {data}\n\n"

# ===============================================================
# ---- ONLINE STATUS MANAGEMENT ----
# ===============================================================

def mark_user_online_global(username: str) -> bool:
    """Mark user as online globally (heartbeat)"""
    try:
        # Set TTL to 60 seconds - if user closes browser, auto-cleanup
        r.setex(f"online_users:{username}", 60, str(int(time.time())))
        print(f"[OK] User {username} marked online (global)")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to mark user online: {e}")
        return False

def mark_user_online_in_group(username: str, group_id: int) -> bool:
    """Mark user as online in specific group"""
    try:
        r.sadd(f"group_members:online:{group_id}", username)
        r.expire(f"group_members:online:{group_id}", 60)
        print(f"[OK] User {username} marked online in group {group_id}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to mark user online in group: {e}")
        return False

def mark_user_offline_global(username: str) -> bool:
    """Mark user as offline globally"""
    try:
        r.delete(f"online_users:{username}")
        print(f"[OK] User {username} marked offline (global)")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to mark user offline: {e}")
        return False

def mark_user_offline_from_all_groups(username: str) -> bool:
    """Remove user from all group online lists"""
    try:
        # Get all group IDs user is member of
        members = GroupMember.query.filter_by(username=username).all()
        
        for member in members:
            r.srem(f"group_members:online:{member.group_id}", username)
        
        print(f"[OK] User {username} removed from all group online lists")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to mark user offline from groups: {e}")
        return False

def is_user_online_global(username: str) -> bool:
    """Check if user is online globally"""
    try:
        return r.exists(f"online_users:{username}") > 0
    except Exception as e:
        print(f"[ERROR] Failed to check user online status: {e}")
        return False

@app.route("/group/<int:group_id>/post", methods=["POST"])
@limiter.limit("30 per minute")
def post_to_group(group_id: int):
    """
    Отправить сообщение в группу
    Обновляет последнюю активность сессии
    """
    token = extract_token_from_request()
    
    if not token:
        print(f"[WARN] No token in post_to_group")
        return abort(401)
    
    session = verify_group_session(token)
    
    if not session:
        print(f"[WARN] Invalid group session: {token[:20] if token else 'NONE'}...")
        return abort(401)
    
    if session['group_id'] != group_id:
        print(f"[SECURITY] User {session.get('username')} tried wrong group")
        return abort(403)
    
    # Проверяем членство
    username = session['username']
    if not is_user_in_group(username, group_id):
        print(f"[SECURITY] User {username} not in group {group_id}")
        return abort(403)
    
    text = request.form.get("message", "").strip()
    if not text:
        return ("", 204)
    
    if len(text) > MAX_MESSAGE_LENGTH:
        return jsonify({"error": "Message too long", "max_length": MAX_MESSAGE_LENGTH}), 400
    
    msg = save_message_to_group(username, group_id, text)
    if not msg:
        return ("", 204)
    
    # Обновляем групповую сессию
    pipe = r.pipeline()
    pipe.multi()
    
    updated_session_data = session.copy()
    updated_session_data['last_activity'] = int(time.time())
    
    pipe.setex(f"group_session:{token}", AUTH_TOKEN_TTL, json.dumps(updated_session_data).encode("utf-8"))
    pipe.setex(f"user_group_session:{username}:{group_id}", AUTH_TOKEN_TTL, token.encode("utf-8"))
    pipe.execute()
    
    # Обновляем метаданные основной сессии (для панели сессий)
    try:
        metadata_bytes = r.get(f"session_metadata:{token}")
        if metadata_bytes:
            metadata = json.loads(metadata_bytes.decode("utf-8"))
            metadata['last_activity'] = int(time.time())
            r.setex(
                f"session_metadata:{token}",
                SESSION_METADATA_TTL,
                json.dumps(metadata).encode("utf-8")
            )
            print(f"[OK] Updated session metadata for {username}")
    except Exception as e:
        print(f"[WARN] Failed to update session metadata: {e}")
    
    return ("", 204)

@app.route("/group/<int:group_id>/stream")
@limiter.limit("100 per minute")
def stream_group(group_id: int):
    """
    SSE stream для группы
    ИСПРАВЛЕНИЯ:
    - Лучше обработка ошибок
    - Автоматическое продление сессии
    """
    token = extract_token_from_request()
    
    if not token:
        return abort(401)
    
    session = verify_group_session(token)
    
    if not session:
        return abort(401)
    
    if session['group_id'] != group_id:
        return abort(403)
    
    if not is_user_in_group(session['username'], group_id):
        return abort(403)
    
    # Продляем сессию при подключении к потоку
    username = session['username']
    updated_session_data = session.copy()
    updated_session_data['last_activity'] = int(time.time())
    
    pipe = r.pipeline()
    pipe.multi()
    pipe.setex(f"group_session:{token}", AUTH_TOKEN_TTL, json.dumps(updated_session_data).encode("utf-8"))
    pipe.setex(f"user_group_session:{username}:{group_id}", AUTH_TOKEN_TTL, token.encode("utf-8"))
    pipe.execute()
    
    return Response(event_stream_group(group_id), mimetype="text/event-stream")


@app.route("/group/<int:group_id>/history")
@limiter.limit("30 per minute")
def history_group(group_id: int):
    """
    Загрузить историю сообщений группы
    """
    token = extract_token_from_request()
    
    if not token:
        return abort(401)
    
    session = verify_group_session(token)
    
    if not session:
        return abort(401)
    
    if session['group_id'] != group_id:
        return abort(403)
    
    if not is_user_in_group(session['username'], group_id):
        return abort(403)
    
    # Продляем сессию при загрузке истории
    username = session['username']
    updated_session_data = session.copy()
    updated_session_data['last_activity'] = int(time.time())
    
    pipe = r.pipeline()
    pipe.multi()
    pipe.setex(f"group_session:{token}", AUTH_TOKEN_TTL, json.dumps(updated_session_data).encode("utf-8"))
    pipe.setex(f"user_group_session:{username}:{group_id}", AUTH_TOKEN_TTL, token.encode("utf-8"))
    pipe.execute()
    
    before_id = request.args.get('before_id', type=int)
    limit = request.args.get('limit', default=50, type=int)
    
    if limit > 100:
        limit = 100
    
    query = Message.query.filter_by(group_id=group_id).order_by(Message.created_at.desc())
    
    if before_id:
        before_msg = Message.query.filter_by(id=before_id).first()
        if before_msg:
            query = query.filter(Message.created_at < before_msg.created_at)
    
    messages = query.limit(limit).all()
    
    file_ids = []
    for msg in messages:
        if msg.message_type in ('photo', 'file'):
            plain = msg.get_plain()
            if isinstance(plain, dict) and 'file_id' in plain:
                file_ids.append(plain['file_id'])
    
    file_urls = {}
    if file_ids:
        files = File.query.filter(File.id.in_(file_ids)).all()
        for file_record in files:
            signed_data = generate_signed_file_url(file_record.file_token)
            file_urls[file_record.id] = {
                'url': f"/file/{signed_data['token']}?sig={signed_data['signature']}&exp={signed_data['expires']}",
                'category': file_record.file_category,
                'filename': file_record.original_filename
            }
    
    result = []
    for msg in reversed(messages):
        ts = msg.format_time()
        
        if msg.message_type == 'photo':
            plain = msg.get_plain()
            if isinstance(plain, dict) and 'file_id' in plain:
                file_id = plain['file_id']
                if file_id in file_urls:
                    message_text = f"[{ts}] {msg.username}: [PHOTO:{file_id}:{file_urls[file_id]['url']}]"
                else:
                    message_text = f"[{ts}] {msg.username}: [PHOTO:{file_id}]"
            else:
                message_text = f"[{ts}] {msg.username}: [PHOTO]"
        
        elif msg.message_type == 'file':
            plain = msg.get_plain()
            if isinstance(plain, dict) and 'file_id' in plain:
                file_id = plain['file_id']
                category = plain.get('category', 'file')
                filename = plain.get('filename', 'file')
                
                if file_id in file_urls:
                    # НОВОЕ: Обработка аудио
                    if category == 'audio':
                        message_text = f"[{ts}] {msg.username}: [AUDIO:{file_id}:{file_urls[file_id]['url']}]"
                    elif category == 'video':
                        message_text = f"[{ts}] {msg.username}: [VIDEO:{file_id}:{file_urls[file_id]['url']}]"
                    else:
                        message_text = f"[{ts}] {msg.username}: [FILE:{file_id}:{category}:{filename}:{file_urls[file_id]['url']}]"
                else:
                    if category == 'audio':
                        message_text = f"[{ts}] {msg.username}: [AUDIO:{file_id}]"
                    elif category == 'video':
                        message_text = f"[{ts}] {msg.username}: [VIDEO:{file_id}]"
                    else:
                        message_text = f"[{ts}] {msg.username}: [FILE:{file_id}:{category}:{filename}]"
            else:
                message_text = f"[{ts}] {msg.username}: [FILE]"
        
        else:
            plain_data = msg.get_plain()
            if isinstance(plain_data, dict):
                sanitized_content = plain_data.get('text', '')
                url_previews = plain_data.get('urls', {})
                message_text = f"[{ts}] {msg.username}: {sanitized_content}|URLS:{json.dumps(url_previews)}"
            elif isinstance(plain_data, str):
                message_text = f"[{ts}] {msg.username}: {plain_data}|URLS:{{}}"
            else:
                message_text = f"[{ts}] {msg.username}: [INVALID MESSAGE]"

        result.append({
            "id": msg.id,
            "text": message_text
        })
    
    return jsonify({
        "messages": result,
        "has_more": len(messages) == limit
    }), 200

# ===============================================================
# ---- File upload and download routes ----
# ===============================================================
@app.route("/group/<int:group_id>/upload", methods=["POST"])
@limiter.limit("10 per minute; 100 per day")
def upload_to_group(group_id: int):
    """
    Загрузить файл в группу
    Обновляет последнюю активность сессии
    """
    token = extract_token_from_request()
    
    if not token:
        return abort(401)
    
    session = verify_group_session(token)
    
    if not session:
        return abort(401)
    
    if session['group_id'] != group_id:
        return abort(403)
    
    username = session['username']
    
    if not is_user_in_group(username, group_id):
        return abort(403)
    
    if "file" not in request.files:
        return "No file part", 400
    
    file = request.files["file"]
    if file.filename == "":
        return "No selected file", 400
    
    result = save_file(username, file)
    if not result:
        return jsonify({
            "error": "Invalid file",
            "message": "File validation failed. Check file type, size limits:\n"
                      "Photos (jpg,png,gif,webp): 10MB, 16384x16384\n"
                      "Videos (mp4,mov,webm): 100MB\n"
                      "Audio (mp3,m4a,ogg,wav): 50MB\n"
                      "Documents (pdf,txt): 25MB"
        }), 400
    
    file_record, message = result
    
    message.group_id = group_id
    db.session.commit()
    
    message_text = format_message_for_sse(message)
    r.publish(f"chat:group:{group_id}", message_text.encode("utf-8"))
    
    # Обновляем групповую сессию
    pipe = r.pipeline()
    pipe.multi()
    
    updated_session_data = session.copy()
    updated_session_data['last_activity'] = int(time.time())
    
    pipe.setex(f"group_session:{token}", AUTH_TOKEN_TTL, json.dumps(updated_session_data).encode("utf-8"))
    pipe.setex(f"user_group_session:{username}:{group_id}", AUTH_TOKEN_TTL, token.encode("utf-8"))
    pipe.execute()
    
    # Обновляем метаданные основной сессии (для панели сессий)
    try:
        metadata_bytes = r.get(f"session_metadata:{token}")
        if metadata_bytes:
            metadata = json.loads(metadata_bytes.decode("utf-8"))
            metadata['last_activity'] = int(time.time())
            r.setex(
                f"session_metadata:{token}",
                SESSION_METADATA_TTL,
                json.dumps(metadata).encode("utf-8")
            )
            print(f"[OK] Updated session metadata for {username}")
    except Exception as e:
        print(f"[WARN] Failed to update session metadata: {e}")
    
    increment_message_count()
    
    return jsonify({
        "file_id": file_record.id,
        "message_id": message.id,
        "category": file_record.file_category
    }), 200

@app.route("/file/sign/<int:file_id>", methods=["GET"])
@limiter.limit("20 per minute")
def sign_file_url(file_id: int):
    """Generate signed URL for file access"""
    token = extract_token_from_request()
    # Используем verify_token, т.к. этот эндпоинт может быть вызван
    # со страницы /groups, а не только из чата
    username = verify_token(token)
    
    if not username:
        # Пытаемся проверить сессию группы, если обычная не удалась
        session = verify_group_session(token)
        if not session:
            return abort(401)
        username = session['username']
    
    file_record = File.query.filter_by(id=file_id).first()
    if not file_record:
        return abort(404)
    
    # ВАЖНО: Проверяем, что юзер состоит в группе,
    # которой принадлежит сообщение с этим файлом
    msg = Message.query.filter(
        (Message.content.like(f'%\"file_id\": {file_id}%')) | 
        (Message.content.like(f'%\"file_id\":{file_id}%'))
    ).first()
    
    if msg and msg.group_id:
        if not is_user_in_group(username, msg.group_id):
            print(f"[SECURITY] User {username} tried to sign file {file_id} from group {msg.group_id} without membership")
            return abort(403)
    elif msg is None:
        # Файл есть, сообщения нет? (маловероятно)
        # Проверяем, что юзер - владелец файла
        if file_record.username != username:
             print(f"[SECURITY] User {username} tried to sign file {file_id} (owner: {file_record.username})")
             return abort(403)
    
    signed_data = generate_signed_file_url(file_record.file_token)
    
    return jsonify({
        "url": f"/file/{signed_data['token']}?sig={signed_data['signature']}&exp={signed_data['expires']}",
        "category": file_record.file_category,
        "filename": file_record.original_filename
    }), 200

@app.route("/file/<file_token>")
@limiter.limit("60 per minute")
def get_file(file_token: str):
    """Download or display file by signed URL"""
    signature = request.args.get('sig', '')
    expiration = request.args.get('exp', '')
    
    if not verify_signed_file_url(file_token, signature, expiration):
        return abort(403)
    
    result = load_file_by_token(file_token)
    if not result:
        return abort(404)
    
    decrypted_data, mime_type, original_filename, category = result
    
    # Determine Content-Disposition based on category
    if category == 'photo':
        # Photos display inline
        as_attachment = False
        disposition_filename = None
    else:
        # Videos, audio, documents force download
        as_attachment = True
        disposition_filename = original_filename
    
    response = send_file(
        io.BytesIO(decrypted_data),
        mimetype=mime_type,
        as_attachment=as_attachment,
        download_name=disposition_filename
    )
    
    # Security headers
    if category == 'photo':
        response.headers['Content-Security-Policy'] = "default-src 'none'; img-src 'self'"
    else:
        response.headers['Content-Security-Policy'] = "default-src 'none'"
    
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    
    return response

@app.route("/api/account/delete", methods=["POST"])
@limiter.limit("5 per hour")
def api_delete_account():
    """Удалить аккаунт пользователя после проверки пароля"""
    token = extract_token_from_request()
    username = verify_token(token)
    
    if not username:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400
    
    password = data.get("password", "").strip()
    
    if not password:
        return jsonify({"error": "Password required"}), 400
    
    try:
        # Получаем пользователя
        user = User.query.filter_by(username=username).first()
        
        if not user:
            print(f"[WARN] User not found during deletion: {username}")
            return jsonify({"error": "User not found"}), 404
        
        # Проверяем пароль
        try:
            argon2Hasher.verify(user.password_hash, password)
        except VerifyMismatchError:
            print(f"[SECURITY] Wrong password attempt for account deletion by {username}")
            return jsonify({"error": "Invalid password"}), 403
        
        # Удаляем аккаунт
        success = delete_user_account(username)
        
        if not success:
            return jsonify({"error": "Failed to delete account"}), 500
        
        print(f"[OK] Account deleted successfully: {username}")
        
        return jsonify({
            "success": True,
            "message": "Account deleted successfully"
        }), 200
        
    except Exception as e:
        print(f"[ERROR] Failed to delete account: {e}")
        return jsonify({"error": "Failed to delete account"}), 500

@app.route("/logout", methods=["POST"])
def logout():
    token = extract_token_from_request()
    
    if token:
        # Получаем username до удаления токена
        token_data_bytes = r.get(f"auth_token:{token}")
        if token_data_bytes:
            token_data = token_data_bytes.decode("utf-8")
            if '|' in token_data:
                username = token_data.split('|')[0]
            else:
                username = token_data
            
            # Mark offline
            mark_user_offline_global(username)
            mark_user_offline_from_all_groups(username)
        
        # Отзываем токены
        revoke_token(token)
        revoke_group_session(token)
    
    # СОЗДАЕМ ОТВЕТ С УДАЛЕНИЕМ COOKIE
    response = make_response("", 204)
    
    # Удаляем cookie (устанавливаем max_age=0)
    response.set_cookie(
        'auth_token',
        '',
        max_age=0,
        httponly=True,
        secure=is_production,
        samesite='Lax'
    )
    
    print("[OK] User logged out, cookie cleared")
    
    return response

@app.route("/verify-session", methods=["GET"])
@limiter.limit("10 per minute")
def verify_session():
    token = extract_token_from_request()
    
    # Проверяем оба типа сессий
    username = verify_token(token)
    if username:
        return jsonify({"valid": True, "type": "user"}), 200
    
    session = verify_group_session(token)
    if session:
        return jsonify({"valid": True, "type": "group", "group_id": session.get('group_id')}), 200
    
    return jsonify({"valid": False}), 401

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
