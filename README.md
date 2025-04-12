```bash
├── Encrypt.py
├── Main.py
├── README
├── requirements.txt
├── server.py    
├── certs
│   ├── cert.pem
│   └── key.pem
├── openssl-localhost.cnf
├── public_class
│   ├── Config_mysql.py
│   ├── OTPApp
│   │   ├── OTPApplication.py
│   │   └── OTPData.json
│   ├── SQL_method.py
│   ├── cli_menu.py
│   ├── otp_interface.py
│   └── user_keys
│       └── UserX
│           ├── private.pem
│           └── public.pem
```
User Management Overview
The user management system provides secure functionality for registration, login, logout, and password reset using a RESTful API and token-based authentication.

Registration
Users can register by submitting a unique username and password. The password is hashed before being stored in the database for security. If the username already exists, the server will reject the request.

Login
Users provide their username and password to authenticate. If the credentials are correct, the server generates a session token, which is stored in memory and returned to the client along with the user ID.

Logout
To log out, the client sends their user ID and token. The server validates the token and, if valid, removes the session data, effectively logging the user out.

Password Reset
Password reset is only allowed for logged-in users. The client must provide their session token, current password, and a new password. The server validates the session and the original password before securely updating the new hashed password in the database.

#Debugging Workflow

## ⚙️ Setup Instructions
### 1. Install Requirements
```bash
pip install -r requirements.txt
```

### 2. Start the Server

```bash
python3 server.py
```
This will run the Flask server at https://127.0.0.1:5050 with SSL enabled.

### 3. Run the CLI Client
```bash
cd public_class
python3 -m public_class.cli_menu
```
Create account and login in

### 4. Run the OTP Application
```bash
python3 OTPApplication.py
```
enter y to complete OTP login
Check CLI client

### Example Usage
Run server.py

Open CLI (cli_menu.py)

Register new user

Run OTPApplication.py

Enter one-time code from CLI to bind

App generates OTPs

Use CLI to verify OTP and log in

## Security Features
✅ Hashed passwords using SHA-256

✅ OTP-based login via HOTP (RFC 4226)

✅ RSA encryption support (2048-bit)

✅ Zero-Knowledge Architecture:

RSA private keys are stored only on the client (in public_class/user_keys/{username}/)

OTP secrets saved only in OTPData.json on OTP device

##Module Descriptions
server.py	        Secure HTTPS/WebSocket server with API routes and OTP device binding
Main.py	HOTP        manager with singleton queue for OTPs and binding codes
Encrypt.py	        Crypto tools: HOTP generation, RSA key generation, key file handling
cli_menu.py	        CLI interface for register/login/OTP actions and RSA key storage
OTPApplication.py	OTP generator app that connects via WebSocket, binds device, generates OTP
SQL_method.py	    MySQL query handlers
Config_mysql.py 	MySQL connection setup