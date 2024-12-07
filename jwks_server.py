# JWKS server
# By: Bakr Alkhalid
# Bma0152
# csce 3550.001

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import sqlite3
import base64
import json
import jwt
import datetime
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, request, jsonify
import uuid
from argon2 import PasswordHasher
from time import time
import binascii
from collections import deque  # updated the import

# server config
hostName = "localhost"
serverPort = 8080

# SQLite DB file
db_file = "totally_not_my_privateKeys.db"

# initialize Flask app
app = Flask(__name__)
ph = PasswordHasher()

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = str(uuid.uuid4())  # generate the UUIDv4 password
    password_hash = ph.hash(password)  # hash the password

    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)', (username, password_hash, email))
        conn.commit()
        return jsonify({"password": password}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "User already exists"}), 400
    finally:
        conn.close()

# create the SQLite table if it doesnt exist
def init_db():
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

# save private key to the database
def save_key_to_db(key_pem, exp_timestamp):
    encrypted_key = encrypt_key(key_pem)  # cncrypt the key
    print(f"Encrypted key: {encrypted_key}")  # cebug statement
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (encrypted_key, exp_timestamp))
    conn.commit()
    conn.close()

# get a key from the database exp or valid
def get_key_from_db(expired=False):
    conn = sqlite3.connect(db_file)
    c = conn.cursor()

    # retrieve expired or valid key based on the flag
    current_time = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    if expired:
        c.execute('SELECT key FROM keys WHERE exp <= ? ORDER BY exp LIMIT 1', (current_time,))
        print(f"Querying for expired keys before: {current_time}")
    else:
        c.execute('SELECT key FROM keys WHERE exp > ? ORDER BY exp LIMIT 1', (current_time,))
        print(f"Querying for valid keys after: {current_time}")

    row = c.fetchone()
    conn.close()

    # return the key if found, otherwise none
    return decrypt_key(row[0]) if row else None  # Decrypt the key

# get all valid keys
def get_all_valid_keys():
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute('SELECT key FROM keys WHERE exp > ?', (int(datetime.datetime.now(datetime.timezone.utc).timestamp()),))
    rows = c.fetchall()
    conn.close()
    return [row[0] for row in rows]

# convert an integer to a Base64URL-encoded string
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

# serialize the private key to PEM format
def serialize_key(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

# deserialize a private key from PEM format
def deserialize_key(key_pem):
    return serialization.load_pem_private_key(key_pem, password=None)

# initialize the database and add keys
def initialize_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # save valid key
    valid_key_expiration = int((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).timestamp())
    save_key_to_db(serialize_key(private_key), valid_key_expiration)

    # save expired key
    expired_key_expiration = int((datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).timestamp())
    save_key_to_db(serialize_key(expired_key), expired_key_expiration)

    # debugging prints to verify correct insertion of keys
    print("Inserted valid key with exp:", valid_key_expiration)
    print("Inserted expired key with exp:", expired_key_expiration)

# func to encrypt a private key
def encrypt_key(key_pem):
    key = os.environ.get('NOT_MY_KEY')
    if key is None or len(key) not in [16, 24, 32]:
        raise ValueError("Encryption key must be 16, 24, or 32 bytes long")
    key = key.encode()  # Ensure the key is encoded to bytes
    iv = os.urandom(16)  # Generate a random initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    if isinstance(key_pem, str):
        key_pem = key_pem.encode('utf-8')  # Ensure key_pem is bytes
    encrypted_key = encryptor.update(key_pem) + encryptor.finalize()
    encoded_key = base64.b64encode(iv + encrypted_key).decode('utf-8')
    return encoded_key

# Func to decrypt a private key
def decrypt_key(encrypted_key):
    try:
        encrypted_key = base64.b64decode(encrypted_key)
    except binascii.Error as e:
        print(f"Base64 decoding error: {e}")
        return None
    iv = encrypted_key[:16]  # extract the IV
    key = os.environ.get('NOT_MY_KEY').encode()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_key[16:]) + decryptor.finalize()

def log_auth_request(user_id):
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    try:
        # simplified insert statement without the timestamp (it will use DEFAULT)
        c.execute('''
            INSERT INTO auth_logs (request_ip, user_id) 
            VALUES (?, ?)
        ''', (request.remote_addr, user_id))
        conn.commit()
        print(f"Logged auth request for user {user_id} from IP {request.remote_addr}")  # debug print
    except sqlite3.Error as e:
        print(f"Database error in log_auth_request: {e}")
    finally:
        conn.close()

class RateLimiter:
    def __init__(self, rate, per):
        self.rate = rate
        self.per = per
        self.allowance = rate
        self.last_check = time()
        self.requests = {}  # dictionary to store request counts per IP

    def is_allowed(self, ip):
        current = time()
        
        # initialize request count for new IPs
        if ip not in self.requests:
            self.requests[ip] = {'count': 0, 'last_check': current}
        
        # calculate time passed since last request
        time_passed = current - self.requests[ip]['last_check']
        self.requests[ip]['last_check'] = current
        
        # reset count if more than 'per' seconds have passed
        if time_passed > self.per:
            self.requests[ip]['count'] = 0
        
        # heck if request should be allowed
        if self.requests[ip]['count'] >= self.rate:
            return False
        
        # increment request count
        self.requests[ip]['count'] += 1
        return True

# initialize rate limiter with 10 requests per second
rate_limiter = RateLimiter(10, 1)

@app.route('/auth', methods=['POST'])
def auth():
    # get client IP address
    client_ip = request.remote_addr
    
    # check rate limit
    if not rate_limiter.is_allowed(client_ip):
        return jsonify({"error": "Too Many Requests"}), 429

    expired = request.args.get('expired', 'false').lower() == 'true'
    key_pem = get_key_from_db(expired)

    if key_pem:
        try:
            private_key = deserialize_key(key_pem)
            headers = {
                "kid": "expiredKID" if expired else "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
                if not expired else datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
            }
            encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)
            
            # log successful request before returning response
            user_id = 1  # this should be the actual user ID
            log_auth_request(user_id)
            print("Successfully logged auth request")  # debug print
            
            return jsonify({"token": encoded_jwt}), 200
        except Exception as e:
            print(f"Error in auth endpoint: {e}")  # Debug print
            return jsonify({"error": "Internal server error"}), 500
    else:
        return jsonify({"error": "No valid key found."}), 404

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    valid_keys = get_all_valid_keys()
    keys = []

    for key_pem in valid_keys:
        private_key = deserialize_key(key_pem)
        numbers = private_key.private_numbers()
        jwk = {
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "kid": "goodKID",
            "n": int_to_base64(numbers.public_numbers.n),
            "e": int_to_base64(numbers.public_numbers.e),
        }
        keys.append(jwk)

    return jsonify({"keys": keys}), 200

if __name__ == "__main__":
    init_db()  # initialize the SQLite database
    initialize_keys()  # insert initial keys
    app.run(host=hostName, port=serverPort)  # start Flask app