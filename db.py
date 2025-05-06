import mysql.connector
from mysql.connector import Error
import logging

def get_db_connection():
    connection = None
    try:
        connection = mysql.connector.connect(
            host='localhost',
            database='intrusion_detection',
            user='root',
            password=''
        )
        
        if connection.is_connected():
            cursor = connection.cursor()
        
            create_table_query = """
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                attack_type VARCHAR(255),
                confidence FLOAT,
                interface VARCHAR(45),
                timestamp DATETIME
            )
            """
            
            cursor.execute(create_table_query)
            cursor.close()
            return connection
    except Error as e:
        logging.error(f"Error connecting to MySQL: {e}")
        if connection and connection.is_connected():
            connection.close()
        return None

def store_attack_details(connection, attack_type, confidence, interface, timestamp): 
    """Store attack details in MySQL database"""
    cursor = None
    try:
        cursor = connection.cursor()
        logging.info("Storing attack details in MySQL database")
        
        insert_query = """
        INSERT INTO attack_logs (attack_type, confidence, interface, timestamp)
        VALUES (%s, %s, %s, %s)
        """
        cursor.execute(insert_query, (attack_type, confidence, interface, timestamp))
        connection.commit()
        
    except mysql.connector.Error as e:
        logging.error(f"Database error: {e}")
        if connection.is_connected():
            connection.rollback()
        raise e  # Re-raise the caught error
    finally:
        if cursor:
            cursor.close()

def get_latest_attack_logs(connection):
    """Retrieve the latest 10 attack logs from MySQL database"""
    cursor = None
    try:
        cursor = connection.cursor()

        select_query = """
        SELECT * FROM attack_logs
        ORDER BY timestamp DESC
        LIMIT 10
        """
        cursor.execute(select_query)
        logs = cursor.fetchall()

        return logs
    except mysql.connector.Error as e:
        logging.error(f"Database error: {e}")
        return []
    finally:
        if cursor:
            cursor.close()


if __name__ == "__main__":
    db_connection = get_db_connection()
    if db_connection:
        logging.info("Connected to MySQL database")
        db_connection.close()
    else:
        logging.error("Failed to connect to MySQL database")