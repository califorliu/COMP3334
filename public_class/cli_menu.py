import os
import requests
import urllib3
import json
from public_class import otp_interface
from public_class.Config_mysql import get_db_connection
from public_class.SQL_method import execute_query, execute_insert
from public_class import encryption_algo
from tabulate import tabulate

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_BASE = "https://127.0.0.1:5050"

session = {
    "token": None,
    "user_id": None
}

def main_menu():
    print("\n==== Secure Storage CLI Menu ====")
    print("1. Register")
    print("2. Login")
    print("3. Upload File")
    print("4. Download File")
    print("5. Share File")
    print("6. View Logs")
    print("7. Reset Password")
    print("8. Logout")
    print("9. OTP Operations")
    print("0. Exit")
    return input("Choose an option (0-9): ")

def register():
    username = input("Username: ")
    password = input("Password: ")

    private_key,public_key=encryption_algo.pkc_generatekey()

    res = requests.post(f"{API_BASE}/register", json={"username": username, "password": password, "public_key":public_key}, verify=False)
    data = res.json()

    if data.get("status") == "success":
        print("[System meessage] User registered successfully.")
        user_id = data.get("user_id")

        encryption_algo.save_key_to_file(private_key,user_id+"private_key.txt")

        secret_key_OTP = data.get("secret_key_OTP")

        # Update OTPData.json with user_id and secret_key_OTP
        otp_path = os.path.join(os.path.dirname(__file__), "OTPApp", "OTPData.json")
        try:
            if not os.path.exists(os.path.dirname(otp_path)):
                return

            if os.path.exists(otp_path):
                with open(otp_path, "r", encoding="utf-8") as f:
                    otp_data = json.load(f)
            else:
                otp_data = {"deviceID": ""}

            otp_data["user_id"] = user_id
            otp_data["secret_key"] = secret_key_OTP

            with open(otp_path, "w", encoding="utf-8") as f:
                json.dump(otp_data, f, indent=4)
        except Exception:
            pass
    else:
        print("[System meessage] Registration failed:", data.get("message"))

def login():
    username = input("Username: ")
    password = input("Password: ")
    res = requests.post(
        f"{API_BASE}/login",
        json={"username": username, "password": password},
        verify=False
    )

    try:
        data = res.json()
        if data.get("status") == "success":
            session["token"] = data["token"]
            session["user_id"] = data["user_id"]

            # Fetch secret_key_OTP from the database to ensure sync
            conn = get_db_connection()
            result = execute_query(conn, "SELECT user_id, secret_key_OTP FROM users WHERE user_id = %s", (session["user_id"],))
            if result:
                user_id, secret_key_OTP = result[0]
            else:
                return

            # Update OTPData.json with user_id and secret_key_OTP
            otp_path = os.path.join(os.path.dirname(__file__), "OTPApp", "OTPData.json")
            try:
                if not os.path.exists(os.path.dirname(otp_path)):
                    return

                if os.path.exists(otp_path):
                    with open(otp_path, "r", encoding="utf-8") as f:
                        otp_data = json.load(f)
                else:
                    otp_data = {"deviceID": ""}

                otp_data["user_id"] = user_id
                otp_data["secret_key"] = secret_key_OTP

                with open(otp_path, "w", encoding="utf-8") as f:
                    json.dump(otp_data, f, indent=4)

                # Update device_ID and session_token in the database
                device_id = otp_data.get("deviceID", "")
                execute_insert(conn, 
                    "UPDATE users SET device_ID = %s, session_token = %s WHERE user_id = %s",
                    (device_id, session["token"], user_id))
            except Exception:
                pass
            finally:
                if conn:
                    conn.close()
            print("[System meessage] Login successful!")
        else:
            print("[System meessage] Login failed:", data.get("message"))
    except Exception:
        pass

def reset_password():
    if not session["token"]:
        print("[System meessage] Please login first!")
        return

    old_password = input("Old password: ")
    new_password = input("New password: ")

    res = requests.post(f"{API_BASE}/reset_password", json={
        "user_id": session["user_id"],
        "token": session["token"],
        "old_password": old_password,
        "new_password": new_password
    }, verify=False)

    try:
        print(res.json())
    except Exception:
        pass

def logout():
    if not session["token"]:
        print("[System meessage] You are not logged in.")
        return
    res = requests.post(f"{API_BASE}/logout", json={"user_id": session["user_id"], "token": session["token"]}, verify=False)
    print(res.json())
    session["token"] = None
    session["user_id"] = None

def otp_menu():
    if not otp_interface.is_otp_available():
        print("[System meessage] OTP system is not integrated.")
        return

    print("\n=== OTP Menu ===")
    print("1. Bind to Device")
    print("2. Generate OTP")
    print("3. Verify OTP")
    option = input("Choose: ")

    if option == "1":
        otp_interface.bind_device()
    elif option == "2":
        otp = otp_interface.generate_otp()
        print("Your OTP:", otp)
    elif option == "3":
        user_input = input("Enter OTP: ")
        if otp_interface.verify_otp(user_input):
            print("[System meessage] OTP verified!")
        else:
            print("[System meessage] OTP invalid!")

def upload():
    if not session["token"]:
        print("[System meessage] You are not logged in.")
        return
    file_path = input("File path > ")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Get filename from path
    filename = os.path.basename(file_path)
    enc_filename = "enc_"+filename
    
    try:
        key, iv = encryption_algo.skc_generatekey()
        encryption_algo.save_iv_to_file(iv, filename+"iv.txt")
        encryption_algo.save_key_to_file(key,filename+"key.txt")
        encryption_algo.skc_encrypt(file_path,enc_filename,key,iv)
        with open(enc_filename, 'rb') as f:
            files = {'file': (enc_filename, f)}

            res = requests.post(f"{API_BASE}/upload", json={
                    "user_id": session["user_id"],
                    "token": session["token"],
                }, files=files, verify=False)
        
        if res.status_code == 200:
            return f"Success: {res.text}"
        else:
            return f"Error {res.status_code}: {res.text}"
    
    except Exception as e:
        return f"Upload failed: {str(e)}"
    
def download():
    if not session["token"]:
        print("[System meessage] You are not logged in.")
        return
    
    key_res = requests.post(f"{API_BASE}/keylist", json={
        "user_id": session["user_id"],
        "token": session["token"],
    }, verify=False)

    user_id=session["user_id"]
    private_key=encryption_algo.load_key_from_file(user_id+"private_key.txt")
    for filename,key in key_res:
        keycombine=encryption_algo.pkc_decrypt(key,private_key)
        key,iv=keycombine.split("||")
        encryption_algo.save_key_to_file(key,filename.split("_")[1]+"key.txt")
        encryption_algo.save_key_to_file(iv,filename.split("_")[1]+"key.txt")

    res = requests.post(f"{API_BASE}/filelist", json={
        "user_id": session["user_id"],
        "token": session["token"],
    }, verify=False)
    
    print(res.json())

    # headers = ["File_ID", "File name", "Upload Time"]
    # d=res.files
    # print(tabulate(d.items(), headers = headers))

    full_file_name = input("Download File Name >")
    file_name= full_file_name.split('_', 1 )[1]
    res = requests.post(f"{API_BASE}/download", json={
        "user_id": session["user_id"],
        "token": session["token"],
        "file_name": full_file_name,
    }, verify=False)
    encryption_algo.skc_decrypt(
        full_file_name, "dec_"+file_name, 
        encryption_algo.load_key_from_file(file_name+"key.txt"), 
        encryption_algo.load_iv_from_file(file_name+"iv.txt")
    )

def share_file():
    if not session["token"]:
        print("[System meessage] You are not logged in.")
        return
    res = requests.post(f"{API_BASE}/filelist", json={
        "user_id": session["user_id"],
        "token": session["token"],
    }, verify=False)
    
    print(res.json())
    file_name = input("Share File Name >")
    target=input("Share Target user id: ")

    target_public_key=requests.post(f"{API_BASE}/get_public_key", json={
        "user_id": session["user_id"],
        "token": session["token"],
        "target": target,
    }, verify=False)
    
    ori_file_name= file_name.split('_', 1 )[1]
    key=encryption_algo.load_key_from_file(ori_file_name+"key.txt"), 
    iv=encryption_algo.load_iv_from_file(ori_file_name+"iv.txt")

    keycombine=key+"||"+iv

    share_key=encryption_algo.pkc_encrypt(keycombine,target_public_key)

    res = requests.post(f"{API_BASE}/share/", json={
        "user_id": session["user_id"],
        "token": session["token"],
        "target": target,
        "file_name": file_name,
        "share_key":share_key,
    }, verify=False)
    return

def cli_loop():
    while True:
        option = main_menu()
        if option == "1":
            register()
        elif option == "2":
            login()
        elif option == "3":
            upload()
        elif option == "4":
            download()
        elif option == "5":
            share_file()
        elif option == "6":
            print("[System meessage] View Logs feature not implemented yet.")
        elif option == "7":
            reset_password()
        elif option == "8":
            logout()
        elif option == "9":
            otp_menu()
        elif option == "0":
            print("Bye!")
            break
        else:
            print("[System meessage] Invalid option. Please try again.")

if __name__ == "__main__":
    cli_loop()