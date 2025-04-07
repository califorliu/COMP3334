from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import hashlib, secrets, time, random, base64
import sys, os
import Encrypt
import base64

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "public_class")))
from public_class.Config_mysql import get_db_connection
from public_class.SQL_method import execute_query, execute_insert
from Main import Main

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", ping_interval=10, ping_timeout=30)
main_obj = Main()
user_tokens = {}  # user_id -> (token, expire_time)
connected_clients = {}  # for WebSocket

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
    secret_key = base64.b32encode(secrets.token_bytes(10)).decode("utf-8")

    private_bytes, public_bytes = Encrypt.generate_key_pair()
    private_b64 = base64.b64encode(private_bytes).decode("utf-8")
    public_b64 = base64.b64encode(public_bytes).decode("utf-8")

    execute_insert(conn,
        "INSERT INTO users (username, password_hash, secret_key) VALUES (%s, %s, %s, %s)",
        (username, password_hash, secret_key, public_bytes.decode("utf-8")))

    result = execute_query(conn, "SELECT user_id FROM users WHERE username = %s", (username,))
    user_id = result[0][0] if result else None
    bind_code = random.randint(100000, 999999)

    main_obj.bindAccount_queue.append({
        "user_id": user_id, "secret_key": secret_key,
        "code": bind_code
    })

    return {
        "status": "success",
        "bind_code": bind_code,
        "private_key": private_b64,
        "public_key": public_b64,
        "message": "Please enter this code on your OTP app."
    }


def login_user(username, password):
    conn = get_db_connection()
    result = execute_query(conn, "SELECT user_id, password_hash FROM users WHERE username = %s", (username,))
    if not result: return {"status": "error", "message": "User not found."}
    user_id, password_hash_db = result[0]
    if not verify_password(password, password_hash_db): return {"status": "error", "message": "Invalid password."}

    token = generate_token()
    set_user_token(user_id, token)
    main_obj.generateHOTP(user_id)
    return {"status": "success", "token": token, "user_id": user_id}


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
        print("🧾 Login request:", request.json)
        return jsonify(login_user(**request.json))
    except Exception as e:
        print("❌ Login error:", e)
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

@app.route("/")
def index(): return "🔒 Unified Secure Server Running with WebSocket + HTTPS"

@socketio.on("connect")
def handle_connect():
    sid = request.sid
    connected_clients[sid] = request.remote_addr
    print(f"Client {sid} connected.")


@socketio.on("register_device")
def handle_register_device(data):
    username = data["username"]
    device_type = data["device"]
    sid = request.sid
    if username not in connected_clients:
        connected_clients[username] = {"client": None, "OTPApp": None}
    connected_clients[username][device_type] = sid
    print(f"✅ {username} registered {device_type} with sid {sid}")
    emit("register_ack", {"status": "success", "device": device_type})

@socketio.on("HOTP_bind")
def handle_hotp_bind(data):
    print("📥 Received HOTP_bind with code:", data)
    print("📋 Current bindAccount_queue:", main_obj.bindAccount_queue)

    code_str = data.get("code")
    deviceID = data.get("deviceID")
    
    if not code_str or not deviceID:
        print("❌ Missing code or deviceID")
        return {"status": "failed", "message": "Missing required fields"}

    try:
        # Convert to integer, removing any leading/trailing whitespace
        code = int(str(code_str).strip())
    except (ValueError, TypeError):
        print("❌ Invalid HOTP code format received:", code_str)
        return {"status": "failed", "message": "Invalid code format"}

    # Get user_id and secret_key from queue
    user_id, secret_key = main_obj.isCodeInBindAccountQueue(code)
    
    if user_id and secret_key:
        try:
            success = main_obj.bindDeviceID(user_id, deviceID)
            if success:
                print(f"✅ Successfully bound device {deviceID} to user {user_id}")
                return {
                    "status": "success",
                    "user_id": user_id,
                    "secret_key": secret_key
                }
            else:
                print(f"❌ Failed to bind device for user {user_id}")
                return {"status": "failed", "message": "Device binding failed"}
        except Exception as e:
            print(f"❌ Binding error: {e}")
            return {"status": "failed", "message": "Internal binding error"}
    else:
        print(f"❌ Code {code} not found in bindAccount_queue")
        return {"status": "failed", "message": "Invalid or expired binding code"}

@socketio.on("login_hotp")
async def handle_login_hotp(data):
    result = await main_obj.verity_user_TOTP(data.get("OTP"),data.get("user_id"))

    if result:
        emit("login_ack", {"status": "success"})
    else:
        emit("login_ack", {"status": "failed"})



if __name__ == "__main__":
    cert_path = os.path.join("certs", "cert.pem")
    key_path = os.path.join("certs", "key.pem")

    socketio.run(app, host="127.0.0.1", port=5050, ssl_context=(cert_path, key_path), debug=True)

