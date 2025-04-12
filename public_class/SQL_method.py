import mysql.connector

from .Config_mysql import get_db_connection

def getUserByName(username):
    conn = get_db_connection()
    if conn is None:
        return None

    try:
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        print(result)
        return result
    except mysql.connector.Error as err:
        print(f"❌ Query failed: {err}")
        return None
    finally:
        cursor.close()
        conn.close()

def getUserSecretByID(userID):
    conn = get_db_connection()
    if conn is None:
        return None

    try:
        cursor = conn.cursor()
        query = "SELECT secret_key_OTP FROM users WHERE user_id = %s"
        cursor.execute(query, (userID,))
        result = cursor.fetchone()
        return result
    except mysql.connector.Error as err:
        print(f"❌ Query failed: {err}")
        return None
    finally:
        cursor.close()
        conn.close()

def bindDeviceByUserID(deviceID, user_id):
    conn = get_db_connection()
    if conn is None:
        return False

    try:
        cursor = conn.cursor()
        query = "UPDATE users SET device_ID = %s WHERE user_id = %s"
        cursor.execute(query, (deviceID, user_id))
        conn.commit()

        if cursor.rowcount > 0:
            return True
        else:
            print(f"No user found with user_id: {user_id}")
            return False
    finally:
        cursor.close()
        conn.close()

def get_user_and_increaseOTPCounter(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        update_query = "UPDATE users SET OTP_counter = IFNULL(OTP_counter, 0) + 1 WHERE user_id = %s"
        cursor.execute(update_query, (user_id,))
        conn.commit()

        select_query = "SELECT secret_key_OTP, OTP_counter FROM users WHERE user_id = %s"
        cursor.execute(select_query, (user_id,))
        row = cursor.fetchone()

        if row:
            secret_key, counter = row[0], row[1]
            return secret_key, counter
        else:
            print("❌ No user found after update.")
            return None
    except Exception as e:
        print(f"❌ SQL error: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def execute_query(conn, query, params=None):
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()
    except Exception as e:
        print(f"❌ Query error: {e}")
        return None

def execute_insert(conn, query, params=None):
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            conn.commit()
    except Exception as e:
        print(f"❌ Insert error: {e}")
        conn.rollback()