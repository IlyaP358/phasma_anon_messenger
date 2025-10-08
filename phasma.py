import os
import flask
import redis
import requests
import datetime
import threading
import time
from stem import Signal
from stem.control import Controller

app = flask.Flask("labex-sse-chat")
app.secret_key = "labex"
app.config["DEBUG"] = True

r = redis.StrictRedis()

# ---- Tor SOCKS5 and ControlPort ----
SOCKS5_ADDR = "127.0.0.1:9050"
TOR_CONTROL_PORT = 9051
TOR_PASS_FILE = "tor_pass.txt"
# session created automaticly after rotate_tor_identity
session = None

def create_tor_session():
    s = requests.Session()
    s.proxies.update({
        "http": f"socks5h://{SOCKS5_ADDR}",
        "https": f"socks5h://{SOCKS5_ADDR}",
    })
    return s


def tor_control_available():
    try:
        import socket
        with socket.create_connection(("127.0.0.1", TOR_CONTROL_PORT), timeout=1):
            return True
    except Exception:
        return False


def rotate_tor_identity():
    global session
    if not tor_control_available():
        print("Tor ControlPort unavailable")
        return False

    try:
        with Controller.from_port(port=TOR_CONTROL_PORT) as controller:
            if not os.path.exists(TOR_PASS_FILE):
                print(f"⚠️ password file  {TOR_PASS_FILE} not found!!!")
                return False
            with open(TOR_PASS_FILE, "r") as f:
                password = f.read().strip()
            controller.authenticate(password=password)
            controller.signal(Signal.NEWNYM)
            print("Ok Tor identity rotated")

            time.sleep(5)
            session = create_tor_session()
            return True
    except Exception as e:
        print("X ERROR coonect to Tor ControlPort:", e)
        return False


def fetch_via_tor(url, **kwargs):
    global session
    if session is None:
        session = create_tor_session()
    return session.get(url, timeout=15, **kwargs)


# ---- auto rotate every 10 sek ----
def auto_rotate_tor(interval=10):
    while True:
        rotate_tor_identity()
        time.sleep(interval)

threading.Thread(target=auto_rotate_tor, args=(10,), daemon=True).start()


# ---- Flask routes ----
@app.route("/")
def home():
    if "user" not in flask.session:
        return flask.redirect("/login")
    return flask.render_template("index.html", user=flask.session["user"])


def event_stream():
    pubsub = r.pubsub()
    pubsub.subscribe("chat")
    for message in pubsub.listen():
        if message.get("data") and isinstance(message["data"], bytes):
            yield f"data: {message['data'].decode()}\n\n"


@app.route("/login", methods=["GET", "POST"])
def login():
    if flask.request.method == "POST":
        flask.session["user"] = flask.request.form["user"]
        return flask.redirect("/")
    return flask.render_template("login.html")


@app.route("/post", methods=["POST"])
def post():
    message = flask.request.form.get("message", "")
    user = flask.session.get("user", "anonymous")
    now = datetime.datetime.now().replace(microsecond=0).time()

    r.publish("chat", f"[{now.isoformat()}] {user}: {message}\n")

    rotate_tor_identity()

    try:
        resp = fetch_via_tor("https://ifconfig.co/json")
        if resp.ok:
            print("Outgoing request via Tor. Exit IP:", resp.json().get("ip"))
    except Exception as e:
        print("Tor request failed:", e)

    return flask.Response(status=204)


@app.route("/stream")
def stream():
    return flask.Response(event_stream(), mimetype="text/event-stream")


# ---- Startup ----
if __name__ == "__main__":
    print("Starting Flask app with Tor SOCKS5:", SOCKS5_ADDR)
    if not tor_control_available():
        print("⚠️ Warning: Tor ControlPort 9051 недоступен. rotate_tor_identity() не будет работать.")
    app.run(host="127.0.0.1", port=5000, debug=True)

