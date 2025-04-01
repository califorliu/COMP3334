import os
import requests
import urllib3
import otp_interface
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import base64

API_BASE = "https://localhost:5050"
cert_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "cert.pem"))

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
    return input("Choose an option (0-8): ")

def otp_menu():
    if not otp_interface.is_otp_available():
        print("❌ OTP system is not integrated.")
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
            print("✅ OTP verified!")
        else:
            print("❌ OTP invalid!")

def register():
    username = input("Username: ")
    password = input("Password: ")

    res = requests.post(f"{API_BASE}/register", json={"username": username, "password": password}, verify=False)
    data = res.json()

    if data.get("status") == "success":
        private_key_bytes = base64.b64decode(data["private_key"])
        public_key_bytes = base64.b64decode(data["public_key"])

        user_dir = os.path.join(os.path.dirname(__file__), "user_keys", username)
        os.makedirs(user_dir, exist_ok=True)

        with open(os.path.join(user_dir, "private.pem"), "wb") as f:
            f.write(private_key_bytes)

        with open(os.path.join(user_dir, "public.pem"), "wb") as f:
            f.write(public_key_bytes)

        print(f"✅ RSA key pair saved to: {user_dir}")
        print("🆔 One-time binding code:", data["bind_code"])
    else:
        print("❌ Registration failed:", data.get("message"))
        
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
        print(data)
    except Exception as e:
        print("❌ Failed to parse JSON:", e)


def reset_password():
    if not session["token"]:
        print("❌ Please login first!")
        return

    old_password = input("Old password: ")
    new_password = input("New password: ")

    res = requests.post(f"{API_BASE}/reset_password", json={
        "user_id": session["user_id"],
        "token": session["token"],
        "old_password": old_password,
        "new_password": new_password
    }
    ,verify=False)

    try:
        print(res.json())
    except Exception as e:
        print("❌ Error parsing server response:", e)
        print("📥 Response content:", res.text)



def logout():
    if not session["token"]:
        print("❌ You are not logged in.")
        return
    res = requests.post(f"{API_BASE}/logout", json={"user_id": session["user_id"], "token": session["token"]} ,verify=False)
    print(res.json())
    session["token"] = None
    session["user_id"] = None

def cli_loop():
    while True:
        option = main_menu()
        if option == "1":
            register()
        elif option == "2":
            login()
        elif option == "3":
            print("[Upload File] feature not implemented yet.")
        elif option == "4":
            print("[Download File] feature not implemented yet.")
        elif option == "5":
            print("[Share File] feature not implemented yet.")
        elif option == "6":
            print("[View Logs] feature not implemented yet.")
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
            print("Invalid option. Please try again.")
if __name__ == "__main__":
    cli_loop()
