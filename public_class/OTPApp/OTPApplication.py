import os
import json
import time
import base64
import hmac
import hashlib
import struct
import requests
from datetime import datetime
import secrets

# Initialize a requests session with SSL verification disabled
session = requests.Session()
session.verify = False  # Ignore SSL verification (for testing only)

url = "https://127.0.0.1:5050/verify_otp"

# Generate a TOTP (HMAC-based One-Time Password)
def TOTP(secret, digits=6, time_step=30):
    key = base64.b32decode(secret, True)
    counter = int(time.time() // time_step)
    counter_bytes = struct.pack(">Q", counter)
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = hmac_hash[-1] & 0x0F
    binary = struct.unpack(">I", hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF
    otp = binary % (10 ** digits)
    return str(otp).zfill(digits)

def check_otp_data():
    json_path = os.path.join(os.path.dirname(__file__), "OTPData.json")

    #if no json file
    if not os.path.exists(json_path):
        print("OTPData.json not found!")
        return False

    try:
        with open(json_path, "r", encoding="utf-8") as file:
            data = json.load(file)
    except (json.JSONDecodeError, FileNotFoundError):
        print("OTPData.json is not valid JSON!")
        return False

    if not data:
        print("OTPData.json is empty!")
        return False

    modified = False
    if "secret_key" not in data:
        data["secret_key"] = ""
        modified = True
    if "user_id" not in data:
        data["user_id"] = ""
        modified = True


    if modified:
        with open(json_path, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)
        print("✅ Fields added to JSON, but please retry.")
        return False

    return True

def bindToAccount():
    verity_code = input("No account is bound. Please input the code you see in desktop client: ").strip()
    deviceID = ''.join(secrets.choice("0123456789") for _ in range(15))

    payload = {
        "code": verity_code,
        "deviceID": deviceID
    }

    try:
        response = session.post("https://127.0.0.1:5050/bind_device", json=payload)
        result = response.json()

        if result and result.get("status") == "success":
            json_path = os.path.join(os.path.dirname(__file__), "OTPData.json")

            try:
                with open(json_path, "w", encoding="utf-8") as file:
                    json.dump({
                        "user_id": result["user_id"],
                        "secret_key": result["secret_key_OTP"],
                        "deviceID": deviceID
                    }, file, indent=4)
                print("✅ JSON successfully written to:", json_path)
            except Exception as e:
                print("❌ Failed to write JSON:", e)
        else:
            print("❌ Binding failed:", result.get("message", "Unknown error"))
    except Exception as e:
        print("❌ Failed to contact server:", e)




# Submit OTP to the server
def submit_otp(user_id, hotp):

    payload = {"user_id": user_id, "hotp": hotp}
    print(f"Submitting OTP at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    response = session.post(url, json=payload)

def getSecret():
    json_path = os.path.join(os.path.dirname(__file__), "OTPData.json")
    with open(json_path, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print("❌ OTPData.json is empty or invalid!")
            return None
    secret_key = data.get("secret_key")
    user_id = data.get("user_id")

    if not secret_key or not user_id:
        print("❌ Missing required OTP data. Goodbye!")
        return None

    return secret_key, user_id


# Main execution loop
def main():


    while (True):
        # if the OTPapp does not register for a account
        if not check_otp_data():
            bindToAccount()

        else:
            user_choice = input("do you want to login on the client? (Y/N)").strip().lower()


            if user_choice != "y": continue;

            secret_key, user_id = getSecret()
            otp = TOTP(secret_key)
            print(f"Sending OTP for user_id {user_id} => {otp} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            submit_otp(user_id, otp)

            for remaining in range(30, 0, -1):
                print(f"⏳ You have {remaining} seconds remaining...")
                time.sleep(1)




if __name__ == "__main__":
    main()

