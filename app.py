from flask import Flask, render_template, request, redirect, session, send_from_directory
from werkzeug.utils import secure_filename
from functools import wraps
from markupsafe import escape
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import sqlite3
import bcrypt

app = Flask(__name__)

app.config['SECRET_KEY'] = 'your_secret_key'

Talisman(app, content_security_policy=None)
app.config["UPLOAD_FOLDER"] = "uploads"

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

@app.after_request
def set_security_headers(response):
    response.headers['Server'] = 'SecureServer'
    return response


def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if "admin" not in session:

            return redirect("/login")

        return f(*args, **kwargs)

    return decorated_function

app.secret_key = "secretkey"

# Create database
def init_db():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    c.execute('''
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT
    )
    ''')

    c.execute('''
   CREATE TABLE IF NOT EXISTS news(
    id INTEGER PRIMARY KEY,
    title TEXT,
    content TEXT,
    image TEXT
)
    ''')

    conn.commit()
    conn.close()

init_db()

@app.route("/")
def home():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    c.execute("SELECT * FROM news")
    news = c.fetchall()

    conn.close()

    return render_template("index.html", news=news)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]
        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
)

        conn = sqlite3.connect("database.db")
        c = conn.cursor()

        c.execute(
            "INSERT INTO users(username,password) VALUES(?,?)",
            (username, hashed_password)
        )

        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
@limiter.limit("5 per minute")
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        c = conn.cursor()

        c.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        )

        user = c.fetchone()

        conn.close()

        if user:

            stored_password = user[2]

            if bcrypt.checkpw(
                password.encode('utf-8'),
                stored_password
            ):

                session["admin"] = True

                return redirect("/dashboard")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():

    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    c.execute("SELECT * FROM news")
    news = c.fetchall()

    conn.close()

    return render_template("dashboard.html", news=news)


@app.route("/add", methods=["GET","POST"])
@login_required
def add_news():

    if request.method == "POST":

        title = request.form["title"]
        content = request.form["content"]

        image = request.files["image"]

        filename = secure_filename(image.filename)

        image.save(
            os.path.join(
                app.config["UPLOAD_FOLDER"],
                filename
            )
        )

        conn = sqlite3.connect("database.db")
        c = conn.cursor()

        c.execute(
            "INSERT INTO news(title,content,image) VALUES(?,?,?)",
            (title, content, filename)
        )

        conn.commit()
        conn.close()

        return redirect("/dashboard")

    return render_template("add_news.html")


@app.route("/delete/<int:id>")
@login_required
def delete_news(id):

    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    c.execute("DELETE FROM news WHERE id=?", (id,))

    conn.commit()
    conn.close()

    return redirect("/dashboard")

@app.route("/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit_news(id):

    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    if request.method == "POST":

        title = request.form["title"]
        content = request.form["content"]

        c.execute(
            "UPDATE news SET title=?, content=? WHERE id=?",
            (title, content, id)
        )

        conn.commit()
        conn.close()

        return redirect("/dashboard")

    c.execute("SELECT * FROM news WHERE id=?", (id,))
    news = c.fetchone()

    conn.close()

    return render_template("edit_news.html", news=news)

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")

@app.route('/uploads/<filename>')
def uploaded_file(filename):

    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        filename
    )


app.run(host="0.0.0.0", port=5000, debug=True)