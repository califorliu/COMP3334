import os
import json
import time
import base64
import hmac
import hashlib
import struct
import requests
from datetime import datetime

# Initialize a requests session with SSL verification disabled
session = requests.Session()
session.verify = False  # Ignore SSL verification (for testing only)

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

# Submit OTP to the server
def submit_otp(user_id, otp):
    url = "https://127.0.0.1:5050/verify_otp"
    payload = {"user_id": user_id, "otp": otp}
    print(f"Submitting OTP at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    response = session.post(url, json=payload)
    return response.json()

# Main execution loop
def main():
    json_path = os.path.join(os.path.dirname(__file__), "OTPData.json")
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    secret_key = data.get("secret_key")
    user_id = data.get("user_id")
    
    if not user_id or not secret_key:
        print("❌ OTPData.json is missing user_id or secret_key")
        return
    
    print(f"OTP App started with user_id: {user_id}, secret_key: {secret_key}")
    while True:
        choice = input("Press [Y] to complete OTP login (or any other key to exit): ").strip().lower()
        if choice == "y":
            otp = TOTP(secret_key)
            print(f"Sending OTP for user_id {user_id} => {otp} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            response = submit_otp(user_id, otp)
            #print(f"Server response: {response}")
            if response.get("status") == "success":
                print("✅ OTP verification successful")
                break
            else:
                print("❌ OTP verification failed")
        else:
            print("Exiting app")
            break

if __name__ == "__main__":
    main()