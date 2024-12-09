import unittest
import datetime
import json
import jwt
import requests
import sqlite3
from threading import Thread
from http.server import HTTPServer
from cryptography.hazmat.primitives.asymmetric import rsa
from project3 import MyServer, reset_database, save_key_to_db, get_key_from_db, jwks_response, log_auth_request

HOST = "http://localhost:8080"
DB_PATH = "totally_not_my_privateKeys.db"

class TestProject3Server(unittest.TestCase):
    
    def setUp(self):
        reset_database()
        self.server = HTTPServer(("localhost", 8080), MyServer)
        self.server_thread = Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join()

    def test_register_endpoint(self):
        response = requests.post(f"{HOST}/register", json={
            "username": "testuser",
            "email": "testuser@example.com"
        })
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertIn("password", data)

        # Validate user was added to the database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", ("testuser",))
        user = cursor.fetchone()
        conn.close()
        self.assertIsNotNone(user, "User was not added to the database.")

    def test_auth_endpoint_jwt_valid(self):
        # First register the user
        requests.post(f"{HOST}/register", json={
            "username": "testuser",
            "email": "testuser@example.com"
        })
        response = requests.post(f"{HOST}/auth", json={
            "username": "testuser"
        })
        self.assertEqual(response.status_code, 200)
        token = response.json()["token"]
        decoded = jwt.decode(token, options={"verify_signature": False})
        self.assertEqual(decoded["user"], "username")
        self.assertGreater(decoded["exp"], datetime.datetime.utcnow().timestamp())

    def test_auth_logging(self):
        # First register the user
        requests.post(f"{HOST}/register", json={
            "username": "testuser",
            "email": "testuser@example.com"
        })
        requests.post(f"{HOST}/auth", json={
            "username": "testuser"
        })

        # Check logs in the database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM auth_logs")
        logs = cursor.fetchall()
        conn.close()
        self.assertGreater(len(logs), 0, "Auth requests were not logged.")

    def test_jwks_json_endpoint(self):
        response = requests.get(f"{HOST}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        keys = response.json()["keys"]
        self.assertGreater(len(keys), 0, "No keys returned in JWKS")
        for key in keys:
            self.assertIn("kid", key)
            self.assertIn("n", key)
            self.assertIn("e", key)
            self.assertEqual(key["alg"], "RS256")
            self.assertEqual(key["kty"], "RSA")
            self.assertEqual(key["use"], "sig")

    def test_database_key_insertion_and_retrieval(self):
        expiry_time = int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp())
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        save_key_to_db(private_key, expiry_time, fixed_kid=99)

        kid, pem_key = get_key_from_db(expired=False)
        self.assertEqual(kid, 99, "Retrieved key ID does not match saved key ID.")
        self.assertIsNotNone(pem_key, "No key was retrieved from the database.")

if __name__ == "__main__":
    unittest.main()
