import Encrypt

import sys
import os

from public_class.OTPApp.OTPApplication import bindToAccount

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from public_class import SQL_method
from Encrypt import TOTP



class Main:
    _instance = None

    # bindAccount_queue stores temporary binding information during the account binding process.
    # Each dictionary contains:
    # {
    #     "user_id": int,             # ID of the user
    #     "code": int                 # Random code for identifying or verifying the binding
    #     "secret_key":str
    # }
    bindAccount_queue = []

    # queue_OTP stores recent OTPs for each user to verify incoming OTPs from devices.
    # Each dictionary contains:
    # {
    #     "user_id": int,             # ID of the user
    #     "TOTP": str           # List of 5 OTPs (2 before, current counter, and 2 after current counter)
    # }
    queue_TOTP = []


    logged_in_users = []


    # for register event.
    # when the user registers an account, conveniently bind the user's mobile phone.
    # if the code entered by the user matches the one-time code generated by the mobile phone, then the binding is successful.
    def isCodeInBindAccountQueue(self, code):

        for i, entry in enumerate(self.bindAccount_queue):
            queue_code = int(entry.get("code"))
            if queue_code == code :
                entry = self.bindAccount_queue.pop(i)
                return entry["user_id"], entry["secret_key"]
        return None, None


    def insertBindAccountQueue(self,user_id,code,secret_key):
        self.bindAccount_queue.append({"user_id": user_id, "code": code,"secret_key":secret_key})


    def bindDeviceID(self, user_id, deviceID):
        try:
            success = SQL_method.bindDeviceByUserID(deviceID, user_id)
            return success
        except Exception as e:
            print(f"❌ Error binding deviceID: {e}")
            return False



    # server generate OTP by counter, then save into bindAccount_queue to wait for verity.
    @classmethod
    def generateTOTP(cls, user_id,secret_key_OTP):

        TOTP = Encrypt.TOTP(secret_key_OTP)  # TOTP changed every 30 seconds

        cls.insertQueue_TOTP(TOTP, user_id)
        print(f"✅ TOTP queued for user {user_id}: {TOTP}")



    # check if user is in the queue_OTP queue.
    # if yes, return true(user login success). otherwise byebye.
    @classmethod
    def insertQueue_TOTP(self, code, user_id):
        # Check if this (user_id, code) pair already exists
        for entry in self.queue_TOTP:
            if entry["user_id"] == user_id and entry["TOTP"] == code:
                print(f"✅ Code matched directly for user {user_id}, logging in.")
                self.logged_in_users.append(user_id)
                return

        self.queue_TOTP.append({"user_id": user_id, "TOTP": code})




    @classmethod
    def is_user_logged_in(cls, user_id):
        if user_id in cls.logged_in_users:
            cls.logged_in_users.remove(user_id)
            return True
        return False




    @classmethod

    # for Singleton pattern.
    def __init__(self):
        self.bindAccount_queue = []
        self.queue_OTP = []

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Main, cls).__new__(cls)
            cls._instance.__init__()
        return cls._instance