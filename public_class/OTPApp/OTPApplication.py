import os
import json
import sys
import secrets
import hmac
import hashlib
import base64
import struct
import time


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


# if it becomes true, it means that the verification has been executed (success or failure).
isChecked = False



@sio.event
def connect():
    #print("Connected to server.")
    sio.emit("register_device", {"username": "", "device": ""}) 



@sio.on("register_ack")
def handle_register_ack(data):
    print(f"Registered as {data['device']} successfully!")

@sio.on("login_ack")
def handle_login_ack(data):
    if(data["status"] != "success"): print("Login failed,please make sure your client is opening.")
    isChecked = True



@sio.on("login_totp")
def login_totp(OTP,user_id):
    sio.emit("login_totp",{ "OTP":OTP,"user_id":user_id})




def check_otp_data():
    json_path = os.path.join(os.path.dirname(__file__), "OTPData.json")

    #if no json file
    if not os.path.exists(json_path):
        print("OTPData.json not found!")
        return False


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



def generateTOTP():

    with open('OTPData.json', 'r', encoding='utf-8') as f:
        data = json.load(f)

    secret_key =data.get['secret_key']
    user_id = data.get['user_id']

    totp = TOTP(secret_key)
    return (totp, user_id)


def TOTP(secret, digits=6,time_step = 30):
    key = base64.b32decode(secret, True)
    counter = int(time.time())

    # convert counter to 8 bytes
    counter_bytes = struct.pack(">Q", counter)
    # HMAC-SHA1
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    # get the offset
    offset = hmac_hash[-1] & 0x0F

    binary = struct.unpack(">I", hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF  # take 31-bit
    otp = binary % (10 ** digits)
    return str(otp).zfill(digits)  # make sure that the length is 6 digits


def login():
    OTP,user_id = generateTOTP()

    login_totp(OTP,user_id)

    i = 0;
    while(i <= 30):
        print(f"now you can sign-in on the client, The validity time is {30 - i} seconds left.")
        time.sleep(1)
        i += 1

        if isChecked:
            print("The verification has been completed.")
            break



if __name__ == '__main__':
    

    while(True):
        # if the OTPapp does not register for a account
        if check_otp_data():
            bindToAccount()


        else:
            user_choice =input("do you want to login on the client? (Y/N)")

            if user_choice == "Y":
                isChecked = False
                login()
            else:
                continue
            
        
    #sys.exit(main())