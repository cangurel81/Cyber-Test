import pymysql
import re
import socket
import hashlib
import time

class DatabaseServerTest:
    def __init__(self, host, user=None, password=None, db_name=None, port=3306, db_type='mysql'):
        self.host = host
        self.user = user
        self.password = password
        self.db_name = db_name
        self.port = port
        self.db_type = db_type.lower()
        self.connection = None
        self.common_usernames = ['root', 'admin', 'user', 'test', 'guest', 'mysql', 'postgres', 'sa']
        self.common_passwords = ['', 'password', '123456', 'admin', 'root', 'pass', 'test', 'guest', self.db_name]

    def connect_to_database(self):
        try:
            if self.db_type == 'mysql':
                connection = pymysql.connect(
                    host=self.host,
                    user=self.user,
                    password=self.password,
                    database=self.db_name,
                    port=self.port,
                    connect_timeout=5
                )
                self.connection = connection
                return connection, None
            elif self.db_type == 'postgresql':
                try:
                    import psycopg2
                    connection = psycopg2.connect(
                        host=self.host,
                        user=self.user,
                        password=self.password,
                        dbname=self.db_name,
                        port=self.port,
                        connect_timeout=5
                    )
                    self.connection = connection
                    return connection, None
                except ImportError:
                    return None, "psycopg2 module is not installed for PostgreSQL connection."
                except Exception as e:
                    return None, f"PostgreSQL connection error: {e}"
            elif self.db_type == 'mssql':
                try:
                    import pyodbc
                    connection_string = f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={self.host},{self.port};DATABASE={self.db_name};UID={self.user};PWD={self.password};Connection Timeout=5"
                    connection = pyodbc.connect(connection_string)
                    self.connection = connection
                    return connection, None
                except ImportError:
                    return None, "pyodbc module is not installed for MSSQL connection."
                except Exception as e:
                    return None, f"MSSQL connection error: {e}"
            else:
                return None, f"Unsupported database type: {self.db_type}"
        except Exception as e:
            return None, f"Database connection error: {e}"
    
    def test_database_connection(self):
        connection, error = self.connect_to_database()
        if error:
            return f"{self.db_type.upper()} Connection", False, error
        
        if connection:
            try:
                cursor = connection.cursor()
                if self.db_type == 'mysql':
                    cursor.execute("SELECT VERSION()")
                elif self.db_type == 'postgresql':
                    cursor.execute("SELECT version()")
                elif self.db_type == 'mssql':
                    cursor.execute("SELECT @@VERSION")
                
                version = cursor.fetchone()[0]
                cursor.close()
                connection.close()
                return f"{self.db_type.upper()} Connection", True, f"Successfully connected to the database. Version: {version}"
            except Exception as e:
                if connection:
                    connection.close()
                return f"{self.db_type.upper()} Connection", False, f"Database query failed: {e}"
        else:
            return f"{self.db_type.upper()} Connection", False, "Could not connect to the database."
    
    def test_user_privileges(self):
        connection, error = self.connect_to_database()
        if error:
            return "User Privileges", False, f"Connection error: {error}"
        
        privileges = []
        try:
            cursor = connection.cursor()
            
            if self.db_type == 'mysql':
                cursor.execute("SHOW GRANTS FOR CURRENT_USER()")
                for grant in cursor.fetchall():
                    privileges.append(grant[0])
                
                dangerous_privileges = []
                for priv in privileges:
                    if "ALL PRIVILEGES" in priv:
                        dangerous_privileges.append("ALL PRIVILEGES")
                    if "SUPER" in priv:
                        dangerous_privileges.append("SUPER")
                    if "FILE" in priv:
                        dangerous_privileges.append("FILE")
                    if "PROCESS" in priv:
                        dangerous_privileges.append("PROCESS")
                    if "SHUTDOWN" in priv:
                        dangerous_privileges.append("SHUTDOWN")
                
                cursor.close()
                connection.close()
                
                if dangerous_privileges:
                    return "User Privileges", False, f"User has dangerous privileges: {', '.join(dangerous_privileges)}. Privileges: {'; '.join(privileges)}"
                else:
                    return "User Privileges", True, f"User privileges appear to be secure. Privileges: {'; '.join(privileges)}"
            
            elif self.db_type == 'postgresql':
                cursor.execute("SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin FROM pg_roles WHERE rolname = current_user;")
                role = cursor.fetchone()
                if role:
                    rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin = role
                    privileges = []
                    if rolsuper:
                        privileges.append("SUPERUSER")
                    if rolcreaterole:
                        privileges.append("CREATEROLE")
                    if rolcreatedb:
                        privileges.append("CREATEDB")
                    if rolcanlogin:
                        privileges.append("LOGIN")
                    
                    cursor.close()
                    connection.close()
                    
                    if rolsuper:
                        return "User Privileges", False, f"User has dangerous privileges: SUPERUSER. Privileges: {', '.join(privileges)}"
                    else:
                        return "User Privileges", True, f"User privileges appear to be secure. Privileges: {', '.join(privileges)}"
                else:
                    cursor.close()
                    connection.close()
                    return "User Privileges", False, "Could not retrieve user information."
            
            elif self.db_type == 'mssql':
                cursor.execute("SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin, IS_SRVROLEMEMBER('dbcreator') AS is_dbcreator, IS_SRVROLEMEMBER('bulkadmin') AS is_bulkadmin")
                role = cursor.fetchone()
                if role:
                    is_sysadmin, is_dbcreator, is_bulkadmin = role
                    privileges = []
                    if is_sysadmin:
                        privileges.append("sysadmin")
                    if is_dbcreator:
                        privileges.append("dbcreator")
                    if is_bulkadmin:
                        privileges.append("bulkadmin")
                    
                    cursor.close()
                    connection.close()
                    
                    if is_sysadmin:
                        return "User Privileges", False, f"User has dangerous privileges: sysadmin. Privileges: {', '.join(privileges)}"
                    else:
                        return "User Privileges", True, f"User privileges appear to be secure. Privileges: {', '.join(privileges)}"
                else:
                    cursor.close()
                    connection.close()
                    return "User Privileges", False, "Could not retrieve user information."
            else:
                cursor.close()
                connection.close()
                return "User Privileges", False, f"Unsupported database type: {self.db_type}"
        except Exception as e:
            if connection:
                connection.close()
            return "User Privileges", False, f"Error during privilege check: {e}"
    
    def test_password_strength(self):
        # Password length check
        if len(self.password) < 8:
            return "Password Security", False, f"Password is too short ({len(self.password)} characters). It should be at least 8 characters."
        
        score = 0
        if re.search(r'[A-Z]', self.password):
            score += 1  # Uppercase letter
        if re.search(r'[a-z]', self.password):
            score += 1  # Lowercase letter
        if re.search(r'[0-9]', self.password):
            score += 1  # Number
        if re.search(r'[^A-Za-z0-9]', self.password):
            score += 1  # Special character
        
        if self.password.lower() in self.common_passwords or self.password == self.user:
            return "Password Security", False, "Password is too common or same as username. Use a stronger password."
        
        if score < 3:
            return "Password Security", False, f"Password is not complex enough (Score: {score}/4). It should contain uppercase/lowercase letters, numbers, and special characters."
        else:
            return "Password Security", True, f"Password security is sufficient (Score: {score}/4)."
    
    def test_brute_force_protection(self):
        # Test connection speed
        connection_times = []
        for _ in range(3):
            start_time = time.time()
            connection, _ = self.connect_to_database()
            if connection:
                connection.close()
                connection_times.append(time.time() - start_time)
            time.sleep(0.5)  # Short wait
        
        if not connection_times:
            return "Brute Force Protection", False, "Connection speed could not be tested."
        
        avg_connection_time = sum(connection_times) / len(connection_times)
        
        # Try connecting with wrong password
        wrong_password = self.password + "_wrong"
        start_time = time.time()
        try:
            if self.db_type == 'mysql':
                pymysql.connect(
                    host=self.host,
                    user=self.user,
                    password=wrong_password,
                    database=self.db_name,
                    port=self.port,
                    connect_timeout=5
                )
        except:
            pass  # Error expected
        
        wrong_connection_time = time.time() - start_time
        
        if wrong_connection_time > (avg_connection_time * 2):
            return "Brute Force Protection", True, f"Wrong password attempt delay mechanism detected. Delay: {wrong_connection_time:.2f}s vs {avg_connection_time:.2f}s"
        else:
            return "Brute Force Protection", False, "No delay mechanism detected for wrong password attempts. May be vulnerable to brute force attacks."

    def test_exposed_database_port(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            is_local = self.host in ['localhost', '127.0.0.1', local_ip, '::1']
            
            if not is_local:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((self.host, self.port))
                s.close()
                
                if result == 0:
                    return "Database Port Security", False, f"Database port ({self.port}) is accessible from outside. It should be protected with a firewall."
                else:
                    return "Database Port Security", True, f"Database port ({self.port}) is not accessible from outside."
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.bind(('0.0.0.0', 0))  # Get temporary port
                temp_port = s.getsockname()[1]
                s.close()
                
                return "Database Port Security", True, f"Database server is running on the local machine. Low risk of external access."
        except Exception as e:
            return "Database Port Security", False, f"Port security could not be tested: {e}"
    
    def run_all_tests(self):
        results = []
        results.append(self.test_database_connection())
        results.append(self.test_user_privileges())
        results.append(self.test_password_strength())
        results.append(self.test_brute_force_protection())
        results.append(self.test_exposed_database_port())
        return results