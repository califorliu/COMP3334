import mysql.connector


DB_CONFIG = {
    "host": "42.3.154.23",
    "user": "admin",
    "password": "abcd123456789",
    "database": "comp3334",
    "port": 3306
}


def get_db_connection():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        if conn.is_connected():
            #print("[System meessage]database connect success")
            return conn
    except mysql.connector.Error as err:
        #print(f"[System meessage] failed:{err}")
        return None  # Returning None means that the connection failed.
