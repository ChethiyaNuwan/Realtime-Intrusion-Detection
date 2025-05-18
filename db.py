import mysql.connector
from mysql.connector import Error as MySQLError
import psycopg2
from psycopg2 import Error as PostgresError
import logging

# --- Database Configuration ---
# Set DB_TYPE to 'mysql' or 'postgresql'
DB_TYPE = 'postgresql'

# MySQL Configuration
MYSQL_HOST = 'localhost'
MYSQL_DATABASE = 'intrusion_detection'
MYSQL_USER = 'root'
MYSQL_PASSWORD = ''

# PostgreSQL Configuration
POSTGRES_URL = 'postgresql://postgres.cspdpdojquukbwzyhtvv:rtid1234@aws-0-ap-south-1.pooler.supabase.com:6543/postgres'

def get_db_connection():
    connection = None
    cursor = None
    try:
        if DB_TYPE == 'mysql':
            logging.info("Connecting to MySQL database...")
            connection = mysql.connector.connect(
                host=MYSQL_HOST,
                database=MYSQL_DATABASE,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD
            )
        elif DB_TYPE == 'postgresql':
            logging.info("Connecting to PostgreSQL database...")
            connection = psycopg2.connect(POSTGRES_URL)
        else:
            logging.error(f"Unsupported DB_TYPE: {DB_TYPE}")
            return None

        if connection:
            is_connected = False
            if DB_TYPE == 'mysql' and connection.is_connected():
                is_connected = True
            elif DB_TYPE == 'postgresql':
                is_connected = True


            if is_connected:
                cursor = connection.cursor()
            
                create_table_query = """
                CREATE TABLE IF NOT EXISTS attack_logs (
                    id SERIAL PRIMARY KEY,
                    attack_type VARCHAR(255),
                    confidence FLOAT,
                    interface VARCHAR(45),
                    timestamp TIMESTAMP
                )
                """

                if DB_TYPE == 'mysql':
                    create_table_query = create_table_query.replace("SERIAL PRIMARY KEY", "INT AUTO_INCREMENT PRIMARY KEY")
                    create_table_query = create_table_query.replace("timestamp TIMESTAMP", "timestamp DATETIME")


                cursor.execute(create_table_query)
                connection.commit()
                logging.info(f"Successfully connected to {DB_TYPE} and ensured table exists.")
                return connection
            else:
                logging.error(f"Failed to establish a connection with {DB_TYPE}.")
                return None

    except MySQLError as e:
        logging.error(f"Error connecting to MySQL: {e}")
        if connection and DB_TYPE == 'mysql' and connection.is_connected():
            connection.close()
        return None
    except PostgresError as e:
        logging.error(f"Error connecting to PostgreSQL: {e}")
        if connection: # For psycopg2, connection object might exist even if connect failed partially
            connection.close()
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during DB connection: {e}")
        if connection:
            connection.close()
        return None
    finally:
        if cursor:
            cursor.close()

def store_attack_details(connection, attack_type, confidence, interface, timestamp): 
    """Store attack details in the database"""
    cursor = None
    try:
        cursor = connection.cursor()
        # logging.info(f"Storing attack details in {DB_TYPE} database")
        
        insert_query = """
        INSERT INTO attack_logs (attack_type, confidence, interface, timestamp)
        VALUES (%s, %s, %s, %s)
        """

        cursor.execute(insert_query, (attack_type, confidence, interface, timestamp))
        connection.commit()
        
    except (MySQLError, PostgresError) as e:
        logging.error(f"Database error during store: {e}")

        try:
            if connection:
                connection.rollback()
        except Exception as rb_e:
            logging.error(f"Error during rollback: {rb_e}")
        raise e
    finally:
        if cursor:
            cursor.close()

def get_latest_attack_logs(connection):
    """Retrieve the latest 10 attack logs from the database"""
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
    except (MySQLError, PostgresError) as e: 
        logging.error(f"Database error during fetch: {e}")
        return []
    finally:
        if cursor:
            cursor.close()


if __name__ == "__main__":    
    logging.basicConfig(level=logging.INFO) # Setup basic logging for the test
    
    print(f"Attempting to connect to: {DB_TYPE}")
    if DB_TYPE == 'postgresql':
        print(f"PostgreSQL URL: {POSTGRES_URL}")
    
    db_connection = get_db_connection()
    if db_connection:
        logging.info(f"Successfully connected to the {DB_TYPE} database for testing.")
        
        # Test storing data
        try:
            current_ts_for_test = None
            if DB_TYPE == 'mysql':
                from datetime import datetime
                current_ts_for_test = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            else: # PostgreSQL can handle datetime objects directly
                from datetime import datetime
                current_ts_for_test = datetime.now()

            store_attack_details(db_connection, "Test Attack", 99.9, "eth0_test", current_ts_for_test)
            logging.info("Test data stored.")
            
            latest_logs = get_latest_attack_logs(db_connection)
            logging.info(f"Latest logs: {latest_logs}")
            
        except Exception as e:
            logging.error(f"Error during test operations: {e}")
        finally:
            db_connection.close()
            logging.info(f"Connection to {DB_TYPE} closed.")
    else:
        logging.error(f"Failed to connect to the {DB_TYPE} database for testing.")