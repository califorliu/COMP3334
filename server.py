from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import hashlib
import secrets
import time
import random
import base64
import sys
import os
import Encrypt
from public_class.SQL_method import execute_query, execute_insert
from public_class.Config_mysql import get_db_connection

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "public_class")))
from Main import Main

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", ping_interval=10, ping_timeout=30)
main_obj = Main()
user_tokens = {}  # user_id -> (token, expire_time)
connected_clients = {}  # for WebSocket
queue_TOTP = []  # Store TOTPs for verification

# --- Token functions ---
def hash_password(password): return hashlib.sha256(password.encode()).hexdigest()
def verify_password(password, hashed): return hash_password(password) == hashed
def generate_token(): return secrets.token_hex(32)
def set_user_token(user_id, token): user_tokens[user_id] = (token, int(time.time()) + 3600)
def validate_session(user_id, token):
    if user_id not in user_tokens: return False
    stored_token, expire = user_tokens[user_id]
    return stored_token == token and time.time() <= expire
def revoke_token(user_id): user_tokens.pop(user_id, None)

# --- User functions ---
def register_user(username, password):
    conn = get_db_connection()
    if execute_query(conn, "SELECT * FROM users WHERE username = %s", (username,)):
        return {"status": "error", "message": "Username already exists."}

    password_hash = hash_password(password)
    secret_key_OTP = base64.b32encode(secrets.token_bytes(10)).decode("utf-8")

    private_bytes, public_bytes = Encrypt.generate_key_pair()
    private_b64 = base64.b64encode(private_bytes).decode("utf-8")
    public_b64 = base64.b64encode(public_bytes).decode("utf-8")

    execute_insert(conn,
        "INSERT INTO users (username, password_hash, secret_key_OTP, device_ID) VALUES (%s, %s, %s, %s)",
        (username, password_hash, secret_key_OTP, None))

    result = execute_query(conn, "SELECT user_id FROM users WHERE username = %s", (username,))
    user_id = result[0][0] if result else None
    return {
        "status": "success",
        "private_key": private_b64,
        "public_key": public_b64,
        "message": "Please enter this code on your OTP app.",
        "user_id": user_id,
        "secret_key_OTP": secret_key_OTP
    }

def login_user(username, password):
    conn = get_db_connection()
    result = execute_query(conn, "SELECT user_id, password_hash, secret_key_OTP FROM users WHERE username = %s", (username,))
    if not result:
        return {"status": "error", "message": "User not found."}
    
    user_id, password_hash_db, secret_key_OTP = result[0]
    if not verify_password(password, password_hash_db):
        return {"status": "error", "message": "Invalid password."}

    # Generate TOTP and store in queue
    hotp = Encrypt.TOTP(secret_key_OTP)
    queue_TOTP.append({"user_id": user_id, "TOTP": hotp})

    # Wait for OTP verification (max 60s)
    for i in range(60):
        if main_obj.is_user_logged_in(user_id):
            token = generate_token()
            set_user_token(user_id, token)
            return {"status": "success", "token": token, "user_id": user_id}
        time.sleep(1)

    return {"status": "error", "message": "OTP timeout. Login failed."}

def reset_password(user_id, token, old_password, new_password):
    if not validate_session(user_id, token):
        return {"status": "error", "message": "Invalid session."}
    
    conn = get_db_connection()
    result = execute_query(conn, "SELECT username, password_hash FROM users WHERE user_id = %s", (user_id,))
    if not result: return {"status": "error", "message": "User not found."}
    
    username, password_hash_db = result[0]
    if not verify_password(old_password, password_hash_db):
        return {"status": "error", "message": "Old password incorrect."}
    
    password_hash = hash_password(new_password)
    execute_insert(conn, "UPDATE users SET password_hash = %s WHERE user_id = %s", (password_hash, user_id))
    return {"status": "success"}

# --- REST API Routes ---
@app.route("/register", methods=["POST"])
def register(): return jsonify(register_user(**request.json))

@app.route("/login", methods=["POST"])
def login():
    try:
        return jsonify(login_user(**request.json))
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/logout", methods=["POST"])
def logout():
    data = request.json
    if validate_session(data.get("user_id"), data.get("token")):
        revoke_token(data["user_id"])
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "message": "Invalid token"})

@app.route("/reset_password", methods=["POST"])
def reset_pw():
    data = request.json
    return jsonify(reset_password(data["user_id"], data["token"], data["old_password"], data["new_password"]))

@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    data = request.json
    user_id = data.get("user_id")
    otp = data.get("otp")
    
    for entry in queue_TOTP:
        if entry["user_id"] == user_id and entry["TOTP"] == otp:
            queue_TOTP.remove(entry)
            main_obj.logged_in_users.append(user_id)
            return jsonify({"status": "success"})
    return jsonify({"status": "failed", "message": "Invalid OTP or user_id"})

@app.route("/")
def index(): return "🔒 Unified Secure Server Running with WebSocket + HTTPS"

@socketio.on("connect")
def handle_connect():
    sid = request.sid
    connected_clients[sid] = request.remote_addr

@socketio.on("register_device")
def handle_register_device(data):
    username = data["username"]
    device_type = data["device"]
    sid = request.sid
    if username not in connected_clients:
        connected_clients[username] = {"client": None, "OTPApp": None}
    connected_clients[username][device_type] = sid
    emit("register_ack", {"status": "success", "device": device_type})

@socketio.on("TOTP_bind")
def handle_hotp_bind(data):
    code_str = data.get("code")
    deviceID = data.get("deviceID")
    
    if not code_str or not deviceID:
        return {"status": "failed", "message": "Missing required fields"}

    try:
        code = int(str(code_str).strip())
    except (ValueError, TypeError):
        return {"status": "failed", "message": "Invalid code format"}

    user_id, secret_key_OTP = main_obj.isCodeInBindAccountQueue(code)
    
    if user_id and secret_key_OTP:
        try:
            success = main_obj.bindDeviceID(user_id, deviceID)
            if success:
                return {
                    "status": "success",
                    "user_id": user_id,
                    "secret_key_OTP": secret_key_OTP
                }
            else:
                return {"status": "failed", "message": "Device binding failed"}
        except Exception as e:
            return {"status": "failed", "message": "Internal binding error"}
    else:
        return {"status": "failed", "message": "Invalid or expired binding code"}

@socketio.on("login_hotp")
def handle_login_hotp(data):
    result = main_obj.verity_user_TOTP(data.get("OTP"), data.get("user_id"))
    if result:
        emit("login_ack", {"status": "success"})
    else:
        emit("login_ack", {"status": "failed"})

if __name__ == "__main__":
    cert_path = os.path.join("certs", "cert.pem")
    key_path = os.path.join("certs", "key.pem")
    socketio.run(app, host="127.0.0.1", port=5050, ssl_context=(cert_path, key_path), debug=True)