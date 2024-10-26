import unittest
import datetime
import json
import jwt
import requests
import sqlite3
from threading import Thread
from http.server import HTTPServer
from cryptography.hazmat.primitives.asymmetric import rsa
from project2 import MyServer, reset_database, save_key_to_db, get_key_from_db, jwks_response

HOST = "http://localhost:8080"
DB_PATH = "totally_not_my_privateKeys.db"

class TestProject2Server(unittest.TestCase):
    
    def setUp(self):
        reset_database()
        self.server = HTTPServer(("localhost", 8080), MyServer)
        self.server_thread = Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        print("Server started for testing...")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join()
        print("Server stopped after testing.")

    def test_auth_endpoint_jwt_valid(self):
        """Test JWT generation for a valid (non-expired) token."""
        response = requests.post(f"{HOST}/auth")
        self.assertEqual(response.status_code, 200)
        token = json.loads(response.text)["token"]
        decoded = jwt.decode(token, options={"verify_signature": False})
        self.assertEqual(decoded["user"], "username")
        self.assertGreater(decoded["exp"], datetime.datetime.utcnow().timestamp())

    def test_auth_endpoint_jwt_expired(self):
        """Test JWT generation for an expired token."""
        response = requests.post(f"{HOST}/auth?expired=true")
        self.assertEqual(response.status_code, 200)
        token = json.loads(response.text)["token"]
        decoded = jwt.decode(token, options={"verify_signature": False})
        self.assertEqual(decoded["user"], "username")
        self.assertLess(decoded["exp"], datetime.datetime.utcnow().timestamp())

    def test_jwks_json_endpoint(self):
        """Test that the JWKS endpoint returns valid JSON Web Key data."""
        response = requests.get(f"{HOST}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        keys = json.loads(response.text)["keys"]
        self.assertGreater(len(keys), 0, "No keys returned in JWKS")
        for key in keys:
            self.assertIn("kid", key)
            self.assertIn("n", key)
            self.assertIn("e", key)
            self.assertEqual(key["alg"], "RS256")
            self.assertEqual(key["kty"], "RSA")
            self.assertEqual(key["use"], "sig")

    def test_database_key_insertion_and_retrieval(self):
        """Test saving and retrieving keys from the database."""
        expiry_time = int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp())
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        kid = save_key_to_db(private_key, expiry_time, fixed_kid=99)  # Example fixed_kid provided
        
        retrieved_kid, retrieved_key = get_key_from_db(expired=False)
        self.assertEqual(kid, retrieved_kid, "Retrieved key ID does not match saved key ID.")
        self.assertIsNotNone(retrieved_key, "No key was retrieved from the database.")

    def test_jwks_response_only_unexpired(self):
        """Test that only unexpired keys appear in the JWKS response."""
        expired_time = int((datetime.datetime.utcnow() - datetime.timedelta(hours=1)).timestamp())
        unexpired_time = int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp())
        
        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        unexpired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        save_key_to_db(expired_key, expired_time, fixed_kid=101)
        save_key_to_db(unexpired_key, unexpired_time, fixed_kid=102)

        jwks = json.loads(jwks_response())["keys"]
        self.assertTrue(any(key["kid"] == "102" for key in jwks), "No unexpired keys found in JWKS")
        self.assertFalse(any(key["kid"] == "101" for key in jwks), "Expired keys should not appear in JWKS")

    def test_unsupported_methods(self):
        """Ensure unsupported HTTP methods return 405 or 501 status."""
        for method in [requests.put, requests.delete, requests.patch, requests.head]:
            response = method(f"{HOST}/auth")
            self.assertIn(response.status_code, [405, 501], "Unexpected status for unsupported method")

    def test_database_cleared_between_tests(self):
        """Verify that the database resets between tests."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys")
        row_count = cursor.fetchone()[0]
        conn.close()
        self.assertEqual(row_count, 0, "Database should be empty between tests")

    def test_jwks_response_structure(self):
        """Verify JWKS response format and contents."""
        response = requests.get(f"{HOST}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.text)
        self.assertIn("keys", data, "JWKS response missing 'keys' field")
        self.assertIsInstance(data["keys"], list, "'keys' field should be a list")
        if data["keys"]:
            first_key = data["keys"][0]
            self.assertIn("alg", first_key)
            self.assertIn("kty", first_key)
            self.assertIn("use", first_key)
            self.assertIn("kid", first_key)
            self.assertIn("n", first_key)
            self.assertIn("e", first_key)

    def test_save_key_with_fixed_kid(self):
        """Test saving a key with a specified fixed_kid."""
        expiry_time = int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp())
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        save_key_to_db(private_key, expiry_time, fixed_kid=42)
        
        # Verify that the key was saved with the specified kid
        cursor = sqlite3.connect(DB_PATH).cursor()
        cursor.execute("SELECT kid FROM keys WHERE kid = ?", (42,))
        result = cursor.fetchone()
        self.assertIsNotNone(result, "Key with specified kid=42 was not found in the database")
        self.assertEqual(result[0], 42, "Retrieved kid does not match the specified fixed_kid")

if __name__ == "__main__":
    unittest.main()
