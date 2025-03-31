from flask import Flask, request, jsonify
from public_class.Config_mysql import get_db_connection
from public_class.SQL_method import execute_query, execute_insert
import hashlib
import secrets
import time

app = Flask(__name__)

user_tokens = {}  # user_id -> (token, expire_time)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    return hash_password(password) == hashed

def generate_token():
    return secrets.token_hex(32)

def set_user_token(user_id, token):
    expire_time = int(time.time()) + 3600  # valid for 1 hour
    user_tokens[user_id] = (token, expire_time)

def validate_session(user_id, token):
    if user_id not in user_tokens:
        return False
    stored_token, expire_time = user_tokens[user_id]
    if stored_token != token or time.time() > expire_time:
        return False
    return True

def revoke_token(user_id):
    if user_id in user_tokens:
        del user_tokens[user_id]

def register_user(username, password):
    conn = get_db_connection()
    query_check = "SELECT * FROM users WHERE username = %s"
    if execute_query(conn, query_check, (username,)):
        return {"status": "error", "message": "Username already exists."}

    password_hash = hash_password(password)
    query_insert = "INSERT INTO users (username, password_hash) VALUES (%s, %s)"
    execute_insert(conn, query_insert, (username, password_hash))
    return {"status": "success"}

def login_user(username, password):
    conn = get_db_connection()
    query = "SELECT user_id, password_hash FROM users WHERE username = %s"

    result = execute_query(conn, query, (username,))
    if not result:
        return {"status": "error", "message": "User not found."}

    user_id, password_hash_db = result[0]
    if not verify_password(password, password_hash_db):
        return {"status": "error", "message": "Invalid password."}

    token = generate_token()
    set_user_token(user_id, token)
    return {"status": "success", "token": token, "user_id": user_id}

def logout_user(user_id):
    revoke_token(user_id)

def reset_password(username, old_password, new_password):
    conn = get_db_connection()
    query_check = "SELECT password_hash FROM users WHERE username = %s"
    result = execute_query(conn, query_check, (username,))
    
    if not result:
        return False

    password_hash_db = result[0][0]

    if not verify_password(old_password, password_hash_db):
        return False

    password_hash = hash_password(new_password)
    query_update = "UPDATE users SET password_hash = %s WHERE username = %s"
    execute_insert(conn, query_update, (password_hash, username))
    return True



@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    result = register_user(username, password)
    return jsonify(result)

@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.json
        print("🧾 Login request received:", data)
        username = data.get("username")
        password = data.get("password")
        result = login_user(username, password)
        return jsonify(result)
    except Exception as e:
        print("❌ Login error:", e)
        return jsonify({"status": "error", "message": str(e)})


@app.route("/logout", methods=["POST"])
def logout():
    data = request.json
    user_id = data.get("user_id")
    token = data.get("token")
    if validate_session(user_id, token):
        logout_user(user_id)
        return jsonify({"status": "success"})
    else:
        return jsonify({"status": "error", "message": "Invalid token"})

@app.route("/reset_password", methods=["POST"])
def reset_pw():
    data = request.json
    user_id = data.get("user_id")
    token = data.get("token")
    old_password = data.get("old_password")
    new_password = data.get("new_password")

    if not validate_session(user_id, token):
        return jsonify({"status": "error", "message": "Invalid session."})

    conn = get_db_connection()
    result = execute_query(conn, "SELECT username, password_hash FROM users WHERE user_id = %s", (user_id,))
    if not result:
        return jsonify({"status": "error", "message": "User not found."})

    username, password_hash_db = result[0]
    if not verify_password(old_password, password_hash_db):
        return jsonify({"status": "error", "message": "Old password incorrect."})

    password_hash = hash_password(new_password)
    execute_insert(conn, "UPDATE users SET password_hash = %s WHERE user_id = %s", (password_hash, user_id))
    return jsonify({"status": "success"})


if __name__ == "__main__":
    app.run(port=5050, ssl_context=("cert.pem", "key.pem"))
