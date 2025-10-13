import os
import datetime
import threading
import time
from flask import Flask, render_template, request, redirect, Response, abort
from flask_sqlalchemy import SQLAlchemy
import redis
import requests
from stem import Signal
from stem.control import Controller
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

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

class Message(db.Model):
    id = db.Column(db.BigInteger, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)  # Encrypted message content
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)

    def get_plain(self):
        return decrypt_message(self.content)

    def as_text(self):
        ts = self.created_at.strftime("%H:%M:%S")
        return f"[{ts}] {self.username}: {self.get_plain()}"

class Secret(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), unique=True, nullable=False, index=True)
    value = db.Column(db.Text, nullable=False)  # Encrypted with master key
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

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
# ---- Encryption helpers ----
# ===============================================================
def encrypt_message(plaintext: str) -> str:
    return data_fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

def decrypt_message(ciphertext: str) -> str:
    try:
        return data_fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return "[UNDECRYPTABLE MESSAGE]"

def get_tor_password():
    return get_secret_decrypted("TOR_PASS_ENC")

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
    ciphertext = encrypt_message(content)
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
            # If OK — show chat
            return render_template("index.html", user=username)
        except VerifyMismatchError:
            return "INCORRECT password", 400

    return render_template("login.html")

# ===============================================================
# ---- Chat message routes ----
# ===============================================================
@app.route("/post", methods=["POST"])
def post():
    username = request.form.get("user", "").strip()
    if not username:
        return abort(403)
    text = request.form.get("message", "").strip()
    if not text:
        return ("", 204)
    save_message(username, text)

    def tor_rotate_and_log():
        rotate_tor_identity()
        _log_tor_ip_background()

    threading.Thread(target=tor_rotate_and_log, daemon=True).start()
    return ("", 204)

@app.route("/stream")
def stream():
    """Live chat stream endpoint."""
    return Response(event_stream(), mimetype="text/event-stream")

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

