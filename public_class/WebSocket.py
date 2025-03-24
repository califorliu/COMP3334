from flask import Flask, request
from flask_socketio import SocketIO, emit

import sys
import os


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from Main import Main


# connected_clients keeps track of all currently connected clients by their session ID (sid).
# It maps either:
# 1. sid (str) -> IP address (str) during basic connection,
# 2. or username (str) -> { "client": sid, "OTPApp": sid } after device registration.
# Example:
# {
#     "abc123": "192.168.1.100",                      # Before device type registration
#     "winko": {
#         "client": "abc123",
#         "OTPApp": "xyz789"
#     }
# }
connected_clients = {}


app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", ping_interval=10, ping_timeout=30)

main_obj = Main()


@app.route("/")
def index():
    return "WebSocket Server Running"


@socketio.on("connect")
def handle_connect():
    sid = request.sid  # retrieve the current client's session ID
    connected_clients[sid] = request.remote_addr  # 
    print(f"Client {sid} connected.")


@socketio.on("register_device")
def handle_register_device(data):
    username = data["username"]
    device_type = data["device"]  # "client" or "OTPapplication"
    sid = request.sid

    if username not in connected_clients:
        connected_clients[username] = {"client": None, "OTPApp": None}

    connected_clients[username][device_type] = sid
    print(f"✅ {username} registered {device_type} with sid {sid}")

    # response to client registration successful
    emit("register_ack", {"status": "success", "device": device_type})




#OTP application bind the device number to the account
@socketio.on("OTP_bind")
async def handle_bindACcount_event(bind_code):

    #check if there are any registered accounts waiting to be bound
    user_id, secret_key = main_obj.isCodeInBindAccountQueue(bind_code["code"])

    if user_id and secret_key:
        #if yes, bind the device number and account, and send the user id and key for local storage.
        main_obj.bindDeviceID(user_id,secret_key)
        return {"status": "success", "user_id":user_id,"secret_key":secret_key} 
    else:
        return {"status": "failed"}







# IMPORTANT!!!!
# do not change this
if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=3334, debug=True)