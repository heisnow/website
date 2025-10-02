from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_bcrypt import Bcrypt
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "secret"
bcrypt = Bcrypt(app)

DB_DIR = "data"
DB_NAME = os.path.join(DB_DIR, "users.db")

def init_db():
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR)
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            locked INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

init_db()


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if password != confirm_password:
            flash("兩次密碼輸入不一致！", "error")
            return redirect(url_for("register"))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                      (username, email, hashed_pw))
            conn.commit()
            conn.close()
            flash("註冊成功！請登入。", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("此電子郵件已被註冊！", "error")
            return redirect(url_for("register"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT id, username, password, failed_attempts, locked FROM users WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()

        if not user:
            flash("帳號不存在！", "error")
            return redirect(url_for("login"))

        user_id, username, hashed_pw, failed_attempts, locked = user

        if locked:
            flash("此帳號已被鎖定，請聯絡管理員！", "error")
            return redirect(url_for("login"))

        if bcrypt.check_password_hash(hashed_pw, password):
            # 成功登入
            session["user_id"] = user_id
            session["username"] = username

            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("UPDATE users SET failed_attempts=0 WHERE id=?", (user_id,))
            conn.commit()
            conn.close()

            flash(f"登入成功！歡迎 {username}！", "success")
            return redirect(url_for("home"))
        else:
            failed_attempts += 1
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            if failed_attempts >= 5:
                c.execute("UPDATE users SET failed_attempts=?, locked=1 WHERE id=?", (failed_attempts, user_id))
                flash("密碼錯誤超過 5 次，帳號已被鎖定！", "error")
            else:
                c.execute("UPDATE users SET failed_attempts=? WHERE id=?", (failed_attempts, user_id))
                flash(f"密碼錯誤！您已錯誤 {failed_attempts}/5 次", "error")
            conn.commit()
            conn.close()
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/home")
def home():
    if "username" not in session:
        flash("請先登入！", "error")
        return redirect(url_for("login"))
    return render_template("home.html", username=session["username"])

@app.route("/logout")
def logout():
    session.clear()
    flash("您已成功登出", "success")
    return redirect(url_for("index"))

@app.route("/check_email", methods=["POST"])
def check_email():
    email = request.json.get("email")
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT 1 FROM users WHERE email=?", (email,))
    exists = c.fetchone() is not None
    conn.close()
    return jsonify({"exists": exists})

if __name__ == "__main__":
    app.run(debug=True)
