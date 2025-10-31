#!/usr/bin/env python3
"""
Utility script for generating RSA key pairs and saving them to files for our principals (Alice, Bob, and Relay)
Run this before starting the main application to ensure RSA keys are available for everyone
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

PRINCIPALS = ['alice', 'bob', 'relay']
KEY_SIZE = 2048

def generate_keys():
    for principal in PRINCIPALS:
        private_key_file = f"{principal}_private_key.pem"
        public_key_file = f"{principal}_public_key.pem"

        print(f"Generating RSA key pair for {principal}...")

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=KEY_SIZE,
        )
        public_key = private_key.public_key()

        # Write private key file for this principal
        with open(private_key_file, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
        # Write public key file for this principal
        with open(public_key_file, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

    print("All keys should be generated now! You can start the main application.")

if __name__ == "__main__":
    generate_keys()
