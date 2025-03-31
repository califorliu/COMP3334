import requests

API_BASE = "http://localhost:5050"

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
    print("0. Exit")
    return input("Choose an option (0-8): ")

def register():
    username = input("Username: ")
    password = input("Password: ")
    res = requests.post(f"{API_BASE}/register", json={"username": username, "password": password})
    print(res.json())

def login():
    username = input("Username: ")
    password = input("Password: ")
    res = requests.post(f"{API_BASE}/login", json={"username": username, "password": password})

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
    })

    try:
        print(res.json())
    except Exception as e:
        print("❌ Error parsing server response:", e)
        print("📥 Response content:", res.text)



def logout():
    if not session["token"]:
        print("❌ You are not logged in.")
        return
    res = requests.post(f"{API_BASE}/logout", json={"user_id": session["user_id"], "token": session["token"]})
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
        elif option == "0":
            print("Bye!")
            break
        else:
            print("Invalid option. Please try again.")
if __name__ == "__main__":
    cli_loop()
