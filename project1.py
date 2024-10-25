from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import uuid

valid_keys = []

def add_valid_key(kid, expiry, public_key):
    valid_keys.append({
        "kid": kid,
        "expiry": expiry,
        "public_key": public_key
    })

hostName = "localhost"
serverPort = 8080

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def jwks_response():
    current_time = datetime.datetime.utcnow()
    keys = [
        {
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "kid": key["kid"],
            "n": int_to_base64(key["public_key"].public_numbers().n),
            "e": int_to_base64(key["public_key"].public_numbers().e),
        }
        for key in valid_keys if key["expiry"] > current_time
    ]
    return json.dumps({"keys": keys})


class MyServer(BaseHTTPRequestHandler):
    

    
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            # Generates unique ID and sets the expiration time
            kid = str(uuid.uuid4())
            expiry_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            
            # Handles expired param for expired tokens
            if 'expired' in params:
                kid = "expiredKID"
                expiry_time = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            
            # Adds key to valid_keys
            add_valid_key(kid, expiry_time, private_key.public_key())
            
            #JWT payload plus headers
            headers = {"kid": kid}
            token_payload = {
                "user": "username",
                "exp": expiry_time
            }
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        time = datetime.datetime.utcnow()
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(jwks_response(), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
