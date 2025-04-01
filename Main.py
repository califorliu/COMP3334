import Encrypt

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from public_class import SQL_method

class Main:
    def __init__(self):
        self.bindAccount_queue = []
    
    def isCodeInBindAccountQueue(self, code):
        # Ensure code is an integer for comparison
        code = int(code) if not isinstance(code, int) else code
        for i, entry in enumerate(self.bindAccount_queue):
            # Ensure queue code is treated as integer
            queue_code = int(entry.get("code")) if not isinstance(entry.get("code"), int) else entry.get("code")
            if queue_code == code:
                # Remove and return the matched entry
                entry = self.bindAccount_queue.pop(i)
                return entry["user_id"], entry["secret_key"]
        return None, None
    
    def bindDeviceID(self, user_id, deviceID):
        try:
            success = SQL_method.bindDeviceByUserID(deviceID, user_id)
            return success
        except Exception as e:
            print(f"❌ Error binding deviceID: {e}")
            return False
    _instance = None

    # bindAccount_queue stores temporary binding information during the account binding process.
    # Each dictionary contains:
    # {
    #     "user_id": int,             # ID of the user
    #     "secret_key": str,          # User's unique secret key for OTP generation
    #     "counter": int,             # HOTP counter value
    #     "code": int                 # Random code for identifying or verifying the binding
    # }
    bindAccount_queue = []

    # queue_OTP stores recent OTPs for each user to verify incoming OTPs from devices.
    # Each dictionary contains:
    # {
    #     "user_id": int,             # ID of the user
    #     "OTPs": list[str]           # List of 5 OTPs (2 before, current counter, and 2 after current counter)
    # }
    queue_OTP = []


    # for register event.
    # when the user registers an account, conveniently bind the user's mobile phone.
    # if the code entered by the user matches the one-time code generated by the mobile phone, then the binding is successful.




    # server generate OTP by counter, then save into bindAccount_queue to wait for verity.
    # due to each client and server having its own counter, to improve fault tolerance, calculate the counters from the 2 before, current counter and after 2 counter.
    @classmethod
    def generateHOTP(cls, user_id: int):
        result = SQL_method.get_user_and_increaseOTPCounter(user_id)
        if not result or len(result) != 2:
            print("❌ Failed to get user counter info.")
            return

        secret_key, counter = result  # 預期為 (secret_key, counter)

        OTPs = [
            Encrypt.hotp(secret_key, counter - 2),
            Encrypt.hotp(secret_key, counter - 1),
            Encrypt.hotp(secret_key, counter),
            Encrypt.hotp(secret_key, counter + 1),
            Encrypt.hotp(secret_key, counter + 2)
        ]

        otp_entry = {
            "user_id": user_id,
            "OTPs": OTPs
        }
        cls.queue_OTP.append(otp_entry)
        print(f"✅ OTPs generated and queued for user {user_id}")



    # check if OTP_fromMobile is in the queue_OTP queue.
    # if yes, return true(user login success). otherwise byebye.
    @classmethod
    def verity_user_OTP(cls, OTP_fromMobile: str, user_id: int):
        for entry in cls.queue_OTP:
            if entry["user_id"] == user_id:
                if OTP_fromMobile in entry["OTPs"]:
                    print(f"✅ OTP verified for user {user_id}")
                    return True
                else:
                    print(f"❌ OTP mismatch for user {user_id}")
                    return False

        print(f"❌ No OTP entry found for user {user_id}")
        return False






    # for Singleton pattern.
    def __init__(self):
        self.bindAccount_queue = []
        self.queue_OTP = []

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Main, cls).__new__(cls)
            cls._instance.__init__()
        return cls._instance