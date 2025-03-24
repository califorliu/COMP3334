import mysql

from Config_mysql import get_db_connection


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

def increaseOTPCounter(username):
    conn = get_db_connection()
    
    if conn is None: #database fail to connect
        return False

    try:
        cursor = conn.cursor()
        query = "UPDATE users SET counter = counter + 1 WHERE username = %s"
        cursor.execute(query, (username,))
        conn.commit()

        if cursor.rowcount > 0:
            print(f"Counter increased for {username}")
            return True # indicate successful update
        else:
            print(f" No user found with username: {username}")
            return False  # no user is found

    finally:
        cursor.close()
        conn.close()

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

   # A SQL statement completes query and increment counter
    query = """
        UPDATE users 
        SET counter = counter + 1 
        WHERE user_id = %s
        RETURNING *;
    """
    cursor.execute(query, (user_id,))
    user = cursor.fetchone() # take only one row
    conn.commit() # save result to database

    newTuple = ()
    if user:  # if user is not null or empty

        #get secret_key and counter
        newTuple = (user[5],user[6]) 
    else:
        print("❌ No user found!")

    cursor.close()
    conn.close()
    
    return newTuple

