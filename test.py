import unittest
import datetime
import json
import jwt
import requests
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from threading import Thread
from project1 import MyServer, valid_keys, add_valid_key, jwks_response

HOST = "http://localhost:8080"

class TestProject1(unittest.TestCase):
    
    def setUp(self):
        # Starts up the server in a different thread
        self.server = HTTPServer(("localhost", 8080), MyServer)
        self.server_thread = Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        
    def tearDown(self):
        # Takes down the server after each test
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join()
        
        
    def test_auth_endpoint_jwt_valid(self):
        """Test JWT generation on POST /auth endpoint."""
        response = requests.post(f"{HOST}/auth")
        self.assertEqual(response.status_code, 200)

        # Check JWT payload
        token = response.text
        decoded = jwt.decode(token, options={"verify_signature": False})
        self.assertEqual(decoded["user"], "username")

        # Allow a small time buffer (e.g., 5 seconds) for processing delays
        buffer = 5
        self.assertGreater(decoded["exp"], datetime.datetime.utcnow().timestamp() - buffer)
        
    def test_auth_endpoint_jwt_expired(self):
        """Test expired JWT generation on POST /auth?expired=true."""
        response = requests.post(f"{HOST}/auth?expired=true")
        self.assertEqual(response.status_code, 200)
        
        # Check JWT payload
        token = response.text
        decoded = jwt.decode(token, options={"verify_signature": False})
        self.assertEqual(decoded["user"], "username")
        self.assertLess(decoded["exp"], datetime.datetime.utcnow().timestamp())

    def test_jwks_json_endpoint(self):
        """Test GET /.well-known/jwks.json returns valid JWK response."""
        response = requests.get(f"{HOST}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        
        # Validate JWKS structure
        keys = json.loads(response.text)["keys"]
        for key in keys:
            self.assertIn("kid", key)
            self.assertIn("n", key)
            self.assertIn("e", key)
            self.assertEqual(key["alg"], "RS256")
            self.assertEqual(key["kty"], "RSA")
            self.assertEqual(key["use"], "sig")

    def test_unsupported_methods(self):
        """Ensure unsupported HTTP methods return 405 status."""
        for method in [requests.put, requests.delete, requests.patch, requests.head]:
            response = method(f"{HOST}/auth")
            self.assertEqual(response.status_code, 405)


class TestKeyFunctions(unittest.TestCase):

    def setUp(self):
        valid_keys.clear()

    def test_add_valid_key(self):
        """Test add_valid_key function adds a new key."""
        kid = "test_kid"
        expiry = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        public_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()

        add_valid_key(kid, expiry, public_key)
        self.assertTrue(any(key["kid"] == kid for key in valid_keys))

    def test_jwks_response_only_unexpired(self):
        """Verify jwks_response returns only unexpired keys."""
        expired_time = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
        unexpired_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        
        expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        unexpired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()

        add_valid_key("expired_kid", expired_time, expired_key)
        add_valid_key("unexpired_kid", unexpired_time, unexpired_key)

        jwks = json.loads(jwks_response())["keys"]
        self.assertTrue(any(key["kid"] == "unexpired_kid" for key in jwks))
        self.assertFalse(any(key["kid"] == "expired_kid" for key in jwks))


if __name__ == "__main__":
    unittest.main()