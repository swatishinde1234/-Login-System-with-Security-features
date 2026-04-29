from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt
import time

app = Flask(__name__)
app.secret_key = "secret123"

# =====================================================
# 🔐 LOGIN ATTEMPT TRACKING
# =====================================================
failed_attempts = {}

# =====================================================
# 🗄️ DATABASE CONNECTION
# =====================================================
def get_db():
    return sqlite3.connect("database.db")

# =====================================================
# 🧱 CREATE TABLE
# =====================================================
conn = get_db()
conn.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT,
    password BLOB
)
""")
conn.commit()
conn.close()

# =====================================================
# 🔐 LOGIN
# =====================================================
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"].encode()

        # 🚫 LOGIN LIMIT
        if username in failed_attempts:
            attempts, lock_time = failed_attempts[username]
            if attempts >= 5 and time.time() < lock_time:
                return "🔒 Account locked for 60 seconds"

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT password FROM users WHERE username=?", (username,))
        user = cur.fetchone()
        conn.close()

        # ❌ USER NOT FOUND
        if not user:
            attempts, _ = failed_attempts.get(username, (0, 0))
            attempts += 1
            failed_attempts[username] = (attempts, time.time() + 60)
            return "❌ Invalid user"

        stored_password = bytes(user[0])

        # 🔐 PASSWORD CHECK
        if bcrypt.checkpw(password, stored_password):
            session["user"] = username
            failed_attempts[username] = (0, 0)
            return redirect("/dashboard")
        else:
            attempts, _ = failed_attempts.get(username, (0, 0))
            attempts += 1
            lock_time = time.time() + 60 if attempts >= 5 else 0
            failed_attempts[username] = (attempts, lock_time)

            return f"❌ Wrong password (Attempt {attempts})"

    return render_template("login.html")


# =====================================================
# 📝 REGISTER
# =====================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        username = request.form["username"]

        hashed_password = bcrypt.hashpw(
            request.form["password"].encode(),
            bcrypt.gensalt()
        )

        conn = get_db()
        conn.execute("INSERT INTO users VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()

        return redirect("/")

    return render_template("register.html")


# =====================================================
# 🏠 DASHBOARD
# =====================================================
@app.route("/dashboard")
def dashboard():
    if "user" in session:
        return render_template("dashboard.html", user=session["user"])
    return redirect("/")


# =====================================================
# 🚪 LOGOUT
# =====================================================
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")


# =====================================================
# ▶️ RUN APP
# =====================================================
if __name__ == "__main__":
    app.run(debug=True)