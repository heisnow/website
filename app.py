from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import sqlite3, os, json, secrets
from dotenv import load_dotenv

# ---------------- 載入 .env ----------------
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "secret")
bcrypt = Bcrypt(app)

# ---------------- Gmail 寄信設定 (從 .env 讀取) ----------------
app.config.update(
    MAIL_SERVER="smtp.gmail.com",
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.getenv("MAIL_USER"),
    MAIL_PASSWORD=os.getenv("MAIL_PASS"),
    MAIL_DEFAULT_SENDER=os.getenv("MAIL_USER")
)
mail = Mail(app)

# ---------------- 資料庫設定 ----------------
DB_DIR = "data"
DB_NAME = os.path.join(DB_DIR, "users.db")
JSON_FILE = os.path.join(DB_DIR, "users.json")

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
            locked INTEGER DEFAULT 0,
            verified INTEGER DEFAULT 0,
            verification_token TEXT,
            register_ip TEXT
        )
    ''')
    conn.commit()
    conn.close()

def sync_to_json():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, username, email, password, failed_attempts, locked, verified, register_ip FROM users")
    rows = c.fetchall()
    conn.close()

    users = [
        {
            "id": r[0],
            "username": r[1],
            "email": r[2],
            "password": r[3],
            "failed_attempts": r[4],
            "locked": bool(r[5]),
            "verified": bool(r[6]),
            "register_ip": r[7]
        }
        for r in rows
    ]

    with open(JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=4)

init_db()

# ---------------- 註冊 ----------------
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
        verification_token = secrets.token_urlsafe(32)
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)

        try:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("""
                INSERT INTO users (username, email, password, verification_token, register_ip)
                VALUES (?, ?, ?, ?, ?)
            """, (username, email, hashed_pw, verification_token, ip))
            conn.commit()
            conn.close()
            sync_to_json()

            # 發送驗證信
            verify_link = url_for('verify_token', token=verification_token, _external=True)
            msg = Message(
                "帳號驗證",
                recipients=[email],
                sender=os.getenv("MAIL_USER")
            )
            msg.body = f"您好！請點擊以下連結驗證您的帳號：\n{verify_link}\n\n如果不是您本人操作請忽略此信。"
            mail.send(msg)

            # 寄信後導向動畫頁面
            return redirect(url_for("check_email_page", email=email))
        except sqlite3.IntegrityError:
            flash("此電子郵件已被註冊！", "error")
            return redirect(url_for("register"))

    return render_template("register.html")

# ---------------- 顯示去收信動畫頁 ----------------
@app.route("/check_email_page")
def check_email_page():
    email = request.args.get("email")
    return render_template("check_email.html", email=email)

# ---------------- 驗證連結 ----------------
@app.route("/verify/<token>")
def verify_token(token):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE verification_token=? AND verified=0", (token,))
    user = c.fetchone()

    if user:
        c.execute("UPDATE users SET verified=1, verification_token=NULL WHERE id=?", (user[0],))
        conn.commit()
        conn.close()
        sync_to_json()
        flash("驗證成功！您可以登入了", "success")
        return redirect(url_for("login"))
    else:
        conn.close()
        flash("驗證連結無效或已被使用", "error")
        return redirect(url_for("index"))

# ---------------- 登入 ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT id, username, password, failed_attempts, locked, verified FROM users WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()

        if not user:
            flash("帳號不存在！", "error")
            return redirect(url_for("login"))

        user_id, username, hashed_pw, failed_attempts, locked, verified = user

        if not verified:
            flash("請先到信箱點擊驗證連結！", "error")
            return redirect(url_for("login"))

        if locked:
            flash("此帳號已被鎖定，請聯絡管理員！", "error")
            return redirect(url_for("login"))

        if bcrypt.check_password_hash(hashed_pw, password):
            session["user_id"] = user_id
            session["username"] = username

            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("UPDATE users SET failed_attempts=0 WHERE id=?", (user_id,))
            conn.commit()
            conn.close()

            sync_to_json()
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

            sync_to_json()
            return redirect(url_for("login"))

    return render_template("login.html")

# ---------------- 首頁 ----------------
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

# ---------------- AJAX 檢查 Email 是否存在 ----------------
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
