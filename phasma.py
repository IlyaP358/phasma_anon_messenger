import datetime
import flask
import redis

app = flask.Flask("labex-sse-chat")
app.secret_key = "labex"
app.config["DEBUG"] = True
r = redis.StrictRedis()


## Функция маршрута домашней страницы
@app.route("/")
def home():
    ## Если пользователь не авторизован, перенаправляем его на страницу входа
    if "user" not in flask.session:
        return flask.redirect("/login")
    user = flask.session["user"]
    return flask.render_template("index.html", user=user)


## Генератор сообщений
def event_stream():
    ## Создаем систему публикации/подписки
    pubsub = r.pubsub()
    ## Используем метод подписки системы публикации/подписки для подписки на канал
    pubsub.subscribe("chat")
    for message in pubsub.listen():
        data = message["data"]
        if type(data) == bytes:
            yield "data: {}\n\n".format(data.decode())


## Функция входа, вход требуется при первом посещении
@app.route("/login", methods=["GET", "POST"])
def login():
    if flask.request.method == "POST":
        ## Сохраняем имя пользователя в словаре сессии и затем перенаправляем на домашнюю страницу
        flask.session["user"] = flask.request.form["user"]
        return flask.redirect("/")
    return flask.render_template("login.html")


## Получаем данные, отправленные JavaScript с использованием метода POST
@app.route("/post", methods=["POST"])
def post():
    message = flask.request.form["message"]
    user = flask.session.get("user", "anonymous")
    now = datetime.datetime.now().replace(microsecond=0).time()
    r.publish("chat", "[{}] {}: {}\n".format(now.isoformat(), user, message))
    return flask.Response(status=204)


## Интерфейс потока событий
@app.route("/stream")
def stream():
    ## Объект, возвращаемый функцией этого маршрута, должен быть типа text/event-stream
    return flask.Response(event_stream(), mimetype="text/event-stream")


## Запускаем приложение Flask
app.run()
