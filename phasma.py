import datetime
import flask
import redis
import requests
from stem import Signal
from stem.control import Controller
import socket
import os

app = flask.Flask("labex-sse-chat")
app.secret_key = "labex"
app.config["DEBUG"] = True
r = redis.StrictRedis()

# ---- Tor SOCKS5 и ControlPort ----
SOCKS5_ADDR = "127.0.0.1:9050"
TOR_CONTROL_PORT = 9051
TOR_COOKIE_PATH = "/var/run/tor/control.authcookie"  # путь по умолчанию для Linux

# requests с прокси через Tor
session = requests.Session()
session.proxies.update({
    "http": f"socks5h://{SOCKS5_ADDR}",
    "https": f"socks5h://{SOCKS5_ADDR}",
})

def tor_control_available():
    try:
        with socket.create_connection(("127.0.0.1", TOR_CONTROL_PORT), timeout=1):
            return True
    except Exception:
        return False

def rotate_tor_identity():
    # Проверка доступности Tor ControlPort
    if not tor_control_available():
        print("Tor ControlPort недоступен.")
        return False
    try:
        with Controller.from_port(port=TOR_CONTROL_PORT) as controller:
            controller.authenticate(cookie_path=TOR_COOKIE_PATH if os.path.exists(TOR_COOKIE_PATH) else None)
            controller.signal(Signal.NEWNYM)
            print("Tor identity rotated.")
            return True
    except Exception as e:
        print("Ошибка подключения к Tor ControlPort:", e)
        return False

def fetch_via_tor(url, **kwargs):
    # GET через Tor SOCKS5
    return session.get(url, timeout=15, **kwargs)

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

    # Смена Tor-личности
    rotate_tor_identity()

    # Исходящий запрос через Tor
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

# ---- Запуск ----
if __name__ == "__main__":
    print("Starting Flask app with Tor SOCKS5:", SOCKS5_ADDR)
    if not tor_control_available():
        print("Warning: Tor ControlPort 9051 недоступен. rotate_tor_identity() не будет работать.")
    app.run(host="127.0.0.1", port=5000, debug=True)
