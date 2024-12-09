from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse, parse_qs
from argon2 import PasswordHasher # install w/ pip
import uuid
import os
import base64
import json
import jwt
import datetime
import sqlite3

# First, it is necessary to setup an environent variable for this code to function for project 3
# This environment variable ("NOT_MY_KEY") must be setup so you can get the AES key from the environment
try: 
    # We're gonna try to get the key and encode it
    AES_KEY = os.getenv("NOT_MY_KEY")
    
    if AES_KEY is None:
        raise ValueError("Environment variable NOT_MY_KEY is not properly set or does not exist")
    AES_KEY = AES_KEY.encode() # If exists, it will encode here
    print(f"AES_KEY size: {len(AES_KEY)} bytes")  # Should be 16, 24, or 32 bytes
    print("AES key encoded")
except ValueError as e:
    # If this doesn't work, make the user aware
    print(f"Error: {e}")
    AES_KEY = None 
except Exception as e:
    print (f"Unexpected error: {e}")
    AES_KEY = None

if AES_KEY is None:
    print("AES key does not exist. Exiting.")
    exit

# Database Connection
db_connection = sqlite3.connect("totally_not_my_privateKeys.db", check_same_thread=False)
db_cursor = db_connection.cursor()

# Create keys table if it doesn't exist
db_cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
''')
db_connection.commit()

# Create users table if it doesn't exist
db_cursor.execute('''
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP      
    )
''')
db_connection.commit()


# Server configurations
hostName = "localhost"
serverPort = 8080

def encrypt(key):
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_key = key + b' ' * (16 - len(key) % 16) # This pads to 16-bytes so it can be consistent with format
    final_encrypted_info = encryptor.update(padded_key) + encryptor.finalize()
    return final_encrypted_info

def decrypt(encrypted_info):
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_info = decryptor.update(encrypted_info) + decryptor.finalize()
    no_padding_decrypted_info = decrypted_info.rstrip(b' ')
    return no_padding_decrypted_info

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string."""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def jwks_response():
    """Generate JWKS JSON from unexpired keys."""
    print("jwks_response called", flush=True)
    all_keys = get_valid_keys_for_jwks()
    keys = [
        {
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "kid": str(row[0]),
            "n": int_to_base64(serialization.load_pem_private_key(row[1], password=None).public_key().public_numbers().n),
            "e": int_to_base64(serialization.load_pem_private_key(row[1], password=None).public_key().public_numbers().e),
        }
        for row in all_keys
    ]
    print("JWKS Response Keys:", keys, flush=True)
    return json.dumps({"keys": keys})

def save_key_to_db(key, expiry, fixed_kid=None):
    """Saves key to db, encrypted"""
    pem_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    encrypted_key = encrypt(pem_key)
    if fixed_kid is None:
        db_cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_key, expiry)) # pem_key changed to encrypted key so it only stores encrypted info
    else:
        db_cursor.execute("INSERT OR REPLACE INTO keys (kid, key, exp) VALUES (?, ?, ?)", (fixed_kid, encrypted_key, expiry)) # Same thing here
    db_connection.commit()

def get_key_from_db(expired=False):
    """Gets key from db then decrypts it"""
    current_time = int(datetime.datetime.utcnow().timestamp())
    db_cursor.execute(
        "SELECT kid, key FROM keys WHERE exp {} ? ORDER BY exp {} LIMIT 1".format(
            "<=" if expired else ">", "DESC" if expired else "ASC"
        ),
        (current_time,)
    )
    result = db_cursor.fetchone()
    if result: 
        kid, encrypted_key = result
        decrypted_key = decrypt(encrypted_key)
        return kid, decrypted_key
    return None, None

def get_valid_keys_for_jwks():
    """Retrieve all unexpired keys for JWKS."""
    current_time = int(datetime.datetime.utcnow().timestamp())
    db_cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (current_time,))
    result = db_cursor.fetchall()
    print("All valid keys for JWKS:", result, flush=True)
    return result

def initialize_starter_keys():
    """Initialize one expired and one valid key in the database."""
    print("Initializing starter keys...", flush=True)
    current_time = int(datetime.datetime.utcnow().timestamp())
    expired_time = current_time - 3600  # Expired an hour ago
    valid_time = current_time + 3600    # Valid for an hour

    # Insert an expired key with a fixed ID
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    save_key_to_db(expired_key, expired_time, fixed_kid=1)
    print("Expired key inserted", flush=True)

    # Insert a valid key with a fixed ID
    valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    save_key_to_db(valid_key, valid_time, fixed_kid=2)
    print("Valid key inserted", flush=True)

def reset_database():
    """Reset the database by dropping and recreating the keys table."""
    print("Resetting database...", flush=True)
    db_cursor.execute("DROP TABLE IF EXISTS keys")
    db_cursor.execute('''
        CREATE TABLE keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    db_connection.commit()
    initialize_starter_keys()  # Re-initialize after reset
    
PassHasher = PasswordHasher()

class MyServer(BaseHTTPRequestHandler):
    
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            expired = 'expired' in params
            kid, pem_key = get_key_from_db(expired)
            
            if pem_key is None:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Key not found")
                return
            
            private_key = serialization.load_pem_private_key(pem_key, password=None)
            expiry_time = datetime.datetime.utcnow() + (datetime.timedelta(hours=1) if not expired else datetime.timedelta(hours=-1))
            
            headers = {"kid": str(kid)}
            token_payload = {
                "user": "username",
                "exp": expiry_time.timestamp()
            }
            encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"token": encoded_jwt}).encode("utf-8"))
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(jwks_response(), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

# Initialize database and start server
reset_database()

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        print(f"Server started at http://{hostName}:{serverPort}")
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()




# Following guidelines in the syllabus, I used AI/an LLM (ChatGPT) to help explain the process for AES encryption as well as debugging any errors thrown.
# I asked it to break down the encryption process in python and what libraries I might need
# Prompts included:
"""
- Can you explain how to approach encryption of private keys with symmetric AES encryption? Tell me the libraries needed and break this down in parts and explain each part and why it is necessary.
- What is the difference between this method of encryption and using Cryptography.Fernet? 



"""
