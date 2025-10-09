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

# ---- Flask app config ----
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "phasma_secret_change_me")
app.config["DEBUG"] = True
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/phasma"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# NOTE: flask.session is NOT used — no persistent cookies are set

# ---- Database ----
db = SQLAlchemy(app)
r = redis.StrictRedis(host="127.0.0.1", port=6379, db=0, decode_responses=False)

# ---- Models ----
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.BigInteger, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, index=True)

    def as_text(self):
        ts = self.created_at.strftime("%H:%M:%S")
        return f"[{ts}] {self.username}: {self.content}"

with app.app_context():
    db.create_all()
    print("[OK] Database tables created (if missing)")

# ---- Tor SOCKS5 and ControlPort ----
SOCKS5_ADDR = "127.0.0.1:9050"
TOR_CONTROL_PORT = 9051
TOR_PASS_FILE = "tor_pass.txt"
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
    global tor_session
    if not tor_control_available():
        print("[WARN] Tor ControlPort unavailable")
        return
    try:
        with Controller.from_port(port=TOR_CONTROL_PORT) as c:
            if not os.path.exists(TOR_PASS_FILE):
                print("[WARN] Password file tor_pass.txt not found")
                return
            password = open(TOR_PASS_FILE).read().strip()
            c.authenticate(password=password)
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

# ---- Auto-rotate Tor in background ----
def auto_rotate_tor(interval=10):
    while True:
        rotate_tor_identity()
        time.sleep(interval)

threading.Thread(target=auto_rotate_tor, args=(10,), daemon=True).start()

# ---- Helpers ----
def save_message(username, content):
    msg = Message(username=username, content=content)
    db.session.add(msg)
    db.session.commit()
    r.publish("chat", msg.as_text().encode("utf-8"))
    return msg

def _log_tor_ip_background():
    try:
        resp = fetch_via_tor("https://ifconfig.co/json")
        if resp.ok:
            data = resp.json()
            ip = data.get("ip")
            print("[INFO] Outgoing request via Tor. Exit IP:", ip)
        else:
            print("[WARN] Tor fetch failed, status:", resp.status_code)
    except Exception as e:
        print("[ERROR] Tor request failed:", e)

def event_stream():
    # Send recent history first
    with app.app_context():
        last = Message.query.order_by(Message.created_at.desc()).limit(200).all()
        for m in reversed(last):
            yield f"data: {m.as_text()}\n\n"

    # Redis channel
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

# ---- Flask routes ----
@app.route("/")
def root():
    # Always redirect to /login — no sessions used
    return redirect("/login")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("user", "").strip()
        if not username:
            return "User name required", 400
        user = User.query.filter_by(username=username).first()
        if not user:
            db.session.add(User(username=username))
            db.session.commit()
        return render_template("index.html", user=username)
    return render_template("login.html")

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
    return Response(event_stream(), mimetype="text/event-stream")

# ---- Startup ----
if __name__ == "__main__":
    print(f"[INFO] Starting Flask app on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)

