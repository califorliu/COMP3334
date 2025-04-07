import mysql

from .Config_mysql import get_db_connection


def getUserByName(username):
    conn = get_db_connection()

    if conn is None:#database fail to connect
        return None


    try:
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE username = %s"  # Use parameterized query
        cursor.execute(query, (username,))  # Note that the second parameter needs to be tuple.
        result = cursor.fetchone()  # Take only one row
        print(result)
        return result

    except mysql.connector.Error as err:
        print(f"❌ Query failed: {err}")
        return None
    finally:
        cursor.close()
        conn.close()  # Make sure to close the connection

def getUserSecretByID(userID):
    conn = get_db_connection()

    if conn is None:#database fail to connect
        return None

    try:
        cursor = conn.cursor()
        query = "SELECT secret_key FROM users WHERE user_id = %s"  # Use parameterized query
        cursor.execute(query, (userID,))  # Note that the second parameter needs to be tuple.
        result = cursor.fetchone()  # Take only one row
        return result

    except mysql.connector.Error as err:
        print(f"❌ Query failed: {err}")
        return None

    finally:
        cursor.close()
        conn.close()  # Make sure to close the connection



def bindDeviceByUserID(deviceID,user_id):
    conn = get_db_connection()
    
    if conn is None: #database fail to connect
        return False

    try:
        cursor = conn.cursor()
        query = "UPDATE users SET device_ID = %s WHERE user_id = %s"
        cursor.execute(query, (deviceID,user_id,))
        conn.commit()

        if cursor.rowcount > 0:
            return True # indicate successful update
        else:
            print(f" No user found with user_id: {user_id}")
            return False 

    finally:
        cursor.close()
        conn.close()


#this method has been abandoned.
def get_user_and_increaseOTPCounter(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        update_query = """
            UPDATE users 
            SET OTP_counter = OTP_counter + 1 
            WHERE user_id = %s
        """
        cursor.execute(update_query, (user_id,))
        conn.commit()

        select_query = """
            SELECT * FROM users WHERE user_id = %s
        """
        cursor.execute(select_query, (user_id,))
        user = cursor.fetchone()

        if user:
            return user
        else:
            print("❌ No user found after update.")
            return None

    except mysql.connector.Error as err:
        print(f"❌ SQL error: {err}")
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
