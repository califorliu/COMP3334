from flask import Flask, request, jsonify, send_from_directory
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
def register_user(username, password,bindCode,public_key):

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

    if result:
        user_id = result[0][0]
        execute_insert(conn,
        "INSERT INTO keys (user_id, public_key) VALUES (%s, %s)",
        (user_id, public_key))
    else:
        None
    # user_id = result[0][0] if result else None

    user_id = result[0][0] if result else None

    main_obj.insertBindAccountQueue(user_id,bindCode,secret_key_OTP)

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
    main_obj.generateTOTP(user_id,secret_key_OTP)

    # Wait for OTP verification (max 30s)
    for i in range(30):
        if main_obj.is_user_logged_in(user_id):
            token = generate_token()
            set_user_token(user_id, token)
            print("yessss")
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

def execute_query(conn, query, params=None):
    with conn.cursor() as cursor:
        cursor.execute(query, params or ())
        if query.strip().lower().startswith('select'):
            # Get column names from cursor description
            columns = [desc[0] for desc in cursor.description]
            results = cursor.fetchall()
            return columns, results
        conn.commit()
    return None

def view_file_list(user_id, token):
    if not validate_session(user_id, token):
        return {"status": "error", "message": "Invalid session."}
    
    try:
        with get_db_connection() as conn:  # Assuming you have connection pooling
            columns, data = execute_query(
                conn,
                "SELECT file_id, file_name, upload_time FROM files WHERE user_id = %s",
                (user_id,)
            )
            
            if not data:
                return {'error': 'No files found', 'status': 404}
            
            return {
                'count': len(data),
                'files': [dict(zip(columns, row)) for row in data]
            }
            
    except Exception as e:
        return {'error': str(e), 'status': 500}

def view_key_list(user_id, token):
    if not validate_session(user_id, token):
        return {"status": "error", "message": "Invalid session."}
    try:
        with get_db_connection() as conn:  # Assuming you have connection pooling
            columns, data = execute_query(
                conn,
                "SELECT file_name, encrypted_path FROM files WHERE user_id = %s AND encrypted_path IS NOT NULL",
                (user_id)
            )
            
            if not data:
                return {'error': 'No files found', 'status': 404}
            
            return {
                'count': len(data),
                'files': [dict(zip(columns, row)) for row in data]
            }
            
    except Exception as e:
        return {'error': str(e), 'status': 500}
    
def share_to_target(user_id, token, target_id, filename, share_key):
    if not validate_session(user_id, token):
        return {"status": "error", "message": "Invalid session."}
    try:
        conn = get_db_connection()
        execute_insert(conn,
                    "INSERT INTO files (file_name, user_id, encrypted_path) VALUES (%s, %s, %s)",
                    (filename, target_id,share_key))
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

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
    hotp = data.get("hotp")
    
    main_obj.insertQueue_TOTP(hotp,user_id)

    return jsonify({"status": "ok"})

@app.route('/filelist', methods=["POST"])
def file_list():
    data = request.json
    return jsonify(view_file_list(data["user_id"], data["token"]))

@app.route('/keylist', methods=["POST"])
def key_list():
    data = request.json
    return jsonify(view_key_list(data["user_id"], data["token"]))

@app.route('/keylist', methods=["POST"])
def key_list():
    data = request.json
    return jsonify(view_key_list(data["user_id"], data["token"]))

@app.route('/download', methods=["POST"])
def down_file():
    data = request.json
    
    if not validate_session(data["user_id"], data["token"]):
        return {"status": "error", "message": "Invalid session."}
        
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        data["filename"],
        as_attachment=True
    )


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    data = request.json
    if not validate_session(data["user_id"], data["token"]):
        return {"status": "error", "message": "Invalid session."}
    if request.method == 'POST':
        # Check if file exists in request
        if 'file' not in request.files:
            return 'No file part in request', 400
            
        file = request.files['file']
        filename= file.filename
        # Check if file is selected
        if filename == '':
            return 'No selected file', 400
            
        # Validate file type
        if file:
            # Secure filename to prevent path traversal
            # filename = secure_filename(file.filename)
            # Save file to upload folder
            try:
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                conn = get_db_connection()
                execute_insert(conn,
                    "INSERT INTO files (file_name, user_id) VALUES (%s, %s)",
                    (filename, data["user_id"]))
                return f'File {filename} uploaded successfully'
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)})

@app.route('/share', methods=["POST"])
def share():
    data = request.json
    return jsonify(share_to_target(data["user_id"], data["token"],data["target"],data["filename"],data["share_key"]))

@app.route('/get_public_key', methods=["POST"])
def get_public_key():
    data = request.json
    try:
        conn = get_db_connection()
        result = execute_query(conn, "SELECT public_key FROM keys WHERE user_id = %s", (data["target"],))
        return result[0][0]
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})



@app.route("/")
def index(): return "🔒 Unified Secure Server Running with WebSocket + HTTPS"


@app.route("/bind_device", methods=["POST"])
def bind_device():
    data = request.json
    code_str = data.get("code")
    deviceID = data.get("deviceID")

    if not code_str or not deviceID:
        return jsonify({"status": "failed", "message": "Missing required fields"})

    try:
        code = int(str(code_str).strip())
    except (ValueError, TypeError):
        return jsonify({"status": "failed", "message": "Invalid code format"})

    user_id, secret_key_OTP = main_obj.isCodeInBindAccountQueue(code)


    if user_id and secret_key_OTP:
        try:
            success = main_obj.bindDeviceID(user_id, deviceID)
            if success:
                return jsonify({
                    "status": "success",
                    "user_id": user_id,
                    "secret_key_OTP": secret_key_OTP
                })
            else:
                return jsonify({"status": "failed", "message": "Device binding failed"})
        except Exception as e:
            return jsonify({"status": "failed", "message": "Internal binding error"})
    else:
        return jsonify({"status": "failed", "message": "Invalid or expired binding code"})


@socketio.on("connect")
def handle_connect():
    sid = request.sid
    connected_clients[sid] = request.remote_addr


if __name__ == "__main__":
    cert_path = os.path.join("certs", "cert.pem")
    key_path = os.path.join("certs", "key.pem")
    socketio.run(app, host="127.0.0.1", port=5050, ssl_context=(cert_path, key_path), debug=True,allow_unsafe_werkzeug=True)