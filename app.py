from flask import Flask, request, jsonify, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import psycopg2
import os
print("CURRENT WORKING DIRECTORY:", os.getcwd())
# ---------------- LOAD ENV ----------------
load_dotenv(override=True)

DATABASE_URL = os.getenv("DATABASE_URL")
print("DATABASE_URL BEING USED:", DATABASE_URL)
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL missing")

# ---------------- APP SETUP ----------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key")

app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False  # True only in HTTPS
)

CORS(
    app,
    supports_credentials=True,
    origins=["http://127.0.0.1:5500"]
)

# ---------------- DB CONNECTION ----------------
def get_db():
    return psycopg2.connect(DATABASE_URL)


# ---------------- MODELS (STRUCTURE ONLY) ----------------
class User:
    def __init__(self, id, username, email, password_hash):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash


class Note:
    def __init__(self, id, title, content, user_id):
        self.id = id
        self.title = title
        self.content = content
        self.user_id = user_id


# ================= AUTH =================

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    if not data or not all(k in data for k in ("username", "email", "password")):
        return jsonify({"error": "Invalid input"}), 400

    password_hash = generate_password_hash(data["password"])

    conn = get_db()
    cur = conn.cursor()

    try:
        # Check existing user
        cur.execute(
            "SELECT id FROM users WHERE email=%s OR username=%s;",
            (data["email"], data["username"])
        )
        if cur.fetchone():
            return jsonify({"error": "User already exists"}), 400

        # Insert user
        cur.execute(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (%s, %s, %s);
            """,
            (data["username"], data["email"], password_hash)
        )

        conn.commit()
        return jsonify({"message": "registered"}), 201

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

    finally:
        cur.close()
        conn.close()


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data or "email" not in data or "password" not in data:
        return jsonify({"error": "Invalid input"}), 400

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute(
            "SELECT id, username, email, password_hash FROM users WHERE email=%s;",
            (data["email"],)
        )

        row = cur.fetchone()

        if not row or not check_password_hash(row[3], data["password"]):
            return jsonify({"error": "Invalid credentials"}), 401

        user = User(*row)
        session["user_id"] = user.id

        return jsonify({"message": "logged in"})

    finally:
        cur.close()
        conn.close()


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "logged out"})


# ================= NOTES CRUD =================

@app.route("/notes", methods=["POST"])
def create_note():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            INSERT INTO notes (title, content, user_id)
            VALUES (%s, %s, %s);
            """,
            (data["title"], data["content"], session["user_id"])
        )

        conn.commit()
        return jsonify({"message": "note created"}), 201

    finally:
        cur.close()
        conn.close()


@app.route("/notes", methods=["GET"])
def get_notes():
    if "user_id" not in session:
        return jsonify([])

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT id, title, content, user_id
            FROM notes
            WHERE user_id=%s
            ORDER BY id DESC;
            """,
            (session["user_id"],)
        )

        rows = cur.fetchall()

        notes = [Note(*row) for row in rows]

        return jsonify([
            {
                "id": n.id,
                "title": n.title,
                "content": n.content
            }
            for n in notes
        ])

    finally:
        cur.close()
        conn.close()


@app.route("/notes/<int:note_id>", methods=["PUT"])
def update_note(note_id):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            UPDATE notes
            SET title=%s, content=%s
            WHERE id=%s AND user_id=%s
            RETURNING id;
            """,
            (data["title"], data["content"], note_id, session["user_id"])
        )

        if not cur.fetchone():
            return jsonify({"error": "Not found"}), 404

        conn.commit()
        return jsonify({"message": "updated"})

    finally:
        cur.close()
        conn.close()


@app.route("/notes/<int:note_id>", methods=["DELETE"])
def delete_note(note_id):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            DELETE FROM notes
            WHERE id=%s AND user_id=%s
            RETURNING id;
            """,
            (note_id, session["user_id"])
        )

        if not cur.fetchone():
            return jsonify({"error": "Not found"}), 404

        conn.commit()
        return jsonify({"message": "deleted"})

    finally:
        cur.close()
        conn.close()

@app.route("/notes/<int:note_id>", methods=["GET"])
def get_single_note(note_id):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute(
            """
            SELECT id, title, content
            FROM notes
            WHERE id=%s AND user_id=%s;
            """,
            (note_id, session["user_id"])
        )

        row = cur.fetchone()

        if not row:
            return jsonify({"error": "Not found"}), 404

        return jsonify({
            "id": row[0],
            "title": row[1],
            "content": row[2]
        })

    finally:
        cur.close()
        conn.close()

# ================= HEALTH =================

@app.route("/")
def health():
    return jsonify({"status": "ok"})

def init_db():
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            );
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE
            );
        """)

        conn.commit()
        print("Tables ensured.")
    finally:
        cur.close()
        conn.close()
        
@app.route("/list-tables")
def list_tables():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT tablename 
        FROM pg_tables 
        WHERE schemaname='public';
    """)
    tables = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(tables)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)