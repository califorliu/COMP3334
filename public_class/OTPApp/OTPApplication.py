import os
import json
import sys
import secrets
import hmac
import hashlib
import base64
import struct


# from connect to server
import socketio
import requests

session = requests.Session()
session.verify = False
sio = socketio.Client(http_session=session)
try:
    sio.connect("https://127.0.0.1:5050")
except Exception as e:
    print("❌ Connection to server failed:", e)
    sys.exit(1)


@sio.event
def connect():
    #print("Connected to server.")
    sio.emit("register_device", {"username": "", "device": ""}) 


@sio.on("register_ack")
def handle_register_ack(data):
    print(f"Registered as {data['device']} successfully!")

# @sio.on("login_otp")
# def login_otp(OTP):
#     sio.emit("login_otp", OTP)

# @sio.on("login_ack")
# def handle_login_ack(data):
#     print(f"Logged in as {data['username']} successfully!")
#


@sio.on("server_message")
def handle_server_message(data):
    print(f"📩 Message from server: {data['message']}")





def check_otp_data():
    json_path = os.path.join(os.path.dirname(__file__), "OTPData.json")

    if not os.path.exists(json_path):
        print("OTPData.json not found!")
        sys.exit(1)

    with open(json_path, "r", encoding="utf-8") as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError:
            print("OTPData.json is not valid JSON!")

    secret_key = data.get("secret_key", "").strip()

    if not secret_key:
        print("secret_key is missing or empty in OTPData.json!")
        return False

    return True

def bindToAccount():
    verity_code = input("Please input the code you see in desktop client: ").strip()
    deviceID = secrets.token_hex(30)
    try:
        response = sio.call("OTP_bind", {"code": verity_code, "deviceID": deviceID}, timeout=10)
        if response and response.get("status") == "success":
            json_path = os.path.join(os.path.dirname(__file__), "OTPData.json")
            try:
                with open(json_path, "w", encoding="utf-8") as file:
                    json.dump({
                        "user_id": response["user_id"],
                        "secret_key": response["secret_key"],
                        "counter": 0,
                        "deviceID": deviceID
                    }, file, indent=4)
                print("✅ JSON successfully written to:", json_path)
            except Exception as e:
                print("❌ Failed to write JSON:", e)
        else:
            print("❌ Binding failed:", response.get("message", "Unknown error"))
    except Exception as e:
        print("❌ Failed to contact server:", e)

def generateHOTP():

    with open('OTPData.json', 'r', encoding='utf-8') as f:
        data = json.load(f)

    secret_key =data.get['secret_key']
    counter = data.get['counter']
    user_id = data.get['user_id']


    OCTP = HOTP(secret_key, counter)
    return (OCTP, user_id)
def HOTP(secret, counter, digits=6):
    key = base64.b32decode(secret, True)

    # convert counter to 8 bytes
    counter_bytes = struct.pack(">Q", counter)
    # HMAC-SHA1
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    # get the offset
    offset = hmac_hash[-1] & 0x0F

    binary = struct.unpack(">I", hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF  # take 31-bit
    otp = binary % (10 ** digits)
    return str(otp).zfill(digits)  # make sure that the length is 6 digits

def verity():
    OTP,user_id = generateHOTP()

    print("your OTP: %s",OTP)







if __name__ == '__main__':
    

    while(True):
        # if the OTPapp does not register for a account
        if check_otp_data():
            bindToAccount()


        else:
            user_choice =input("do you want to get one-time password?(Y/N)")

            if user_choice == "Y":
                verity()
            else:
                continue
            
        
    #sys.exit(main())