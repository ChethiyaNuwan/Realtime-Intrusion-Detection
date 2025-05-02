import mysql.connector
from mysql.connector import Error

def get_db_connection():
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
                timestamp DATETIME,
                source_ip VARCHAR(45),
                dest_ip VARCHAR(45)
            )
            """
            cursor.execute(create_table_query)
            return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

def store_attack_details(connection, attack_type, confidence, interface, timestamp, source_ip, dest_ip): 
    """Store attack details in MySQL database"""
    try:
        cursor = connection.cursor()
        
        insert_query = """
        INSERT INTO attack_logs (attack_type, confidence, interface, timestamp, source_ip, dest_ip)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (attack_type, confidence, interface, timestamp, source_ip, dest_ip))
        connection.commit()
        
    except mysql.connector.Error as e:
        logging.error(f"Database error: {e}")


def get_latest_attack_logs(connection):
    """Retrieve the latest 10 attack logs from MySQL database"""
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
