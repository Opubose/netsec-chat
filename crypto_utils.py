import hmac
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import serialization
from typing import Tuple

HASH_FUNC = hashlib.sha256

"""
diffie-hellman params. these are intentionally small for demonstration purposes only. pls don't actually use these in real life LOL.
"""
p = 23
g = 5

def load_rsa_private_key(filepath: str) -> RSAPrivateKey:
    try:
        with open(filepath, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
        if isinstance(private_key, RSAPrivateKey):
            return private_key
        else:
            raise TypeError(f"Loaded private key is not an RSA private key: {type(private_key).__name__}")
    except FileNotFoundError:
        raise FileNotFoundError(f"Private key file not found: {filepath}")
    except Exception as e:
        raise RuntimeError(f"Error loading private key: {e}")

def load_rsa_public_key(filepath) -> RSAPublicKey:
    try:
        with open(filepath, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
            )
        if isinstance(public_key, RSAPublicKey):
            return public_key
        else:
            raise TypeError(f"Loaded public key is not an RSA public key: {type(public_key).__name__}")
    except FileNotFoundError:
        raise FileNotFoundError(f"Public key file not found: {filepath}")
    except Exception as e:
        raise RuntimeError(f"Error loading public key: {e}")

def sign_message(private_key: RSAPrivateKey, message: bytes) -> bytes:
    """Sign a message using RSA private key."""
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(public_key: RSAPublicKey, message: bytes, signature: bytes) -> bool:
    """Verify a message signature using RSA public key."""
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def keyed_hash_encrypt(key: bytes, plaintext: bytes, nonce: bytes) -> Tuple[bytes, bytes]:
    """Encrypt plaintext using keyed-hash HMAC with the given key and nonce."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    keystream = hmac.new(key, nonce, HASH_FUNC).digest()
    padded_keystream = (keystream * (len(plaintext) // len(keystream) + 1))[:len(plaintext)] # repeat the keystream to match plaintext length
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, padded_keystream))

    mac = hmac.new(key, ciphertext, HASH_FUNC).digest()

    return ciphertext, mac

def keyed_hash_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, received_mac: bytes) -> bytes:
    """Decrypt ciphertext using keyed-hash HMAC with the given key and nonce."""
    calculated_mac = hmac.new(key, ciphertext, HASH_FUNC).digest()
    if not hmac.compare_digest(calculated_mac, received_mac):
        raise ValueError("MAC integrity check failed! Decryption aborted.")

    keystream = hmac.new(key, nonce, HASH_FUNC).digest()
    padded_keystream = (keystream * (len(ciphertext) // len(keystream) + 1))[:len(ciphertext)] # repeat the keystream to match ciphertext length
    plaintext = bytes(c ^ k for c, k in zip(ciphertext, padded_keystream))

    return plaintext

def generate_dh_private_key() -> int:
    """Generate a private key for Diffie-Hellman key exchange"""
    import random
    return random.randint(5, 15)

def compute_dh_public_key(private_key: int) -> int:
    """Compute the Diffie-Hellman public key `g^private_key mod p`"""
    return pow(g, private_key, p)

def compute_dh_shared_secret(their_public_key: int, my_private_key: int) -> bytes:
    """Compute the Diffie-Hellman shared secret `their_public_key^my_private_key mod p`"""
    secret = pow(their_public_key, my_private_key, p)
    return HASH_FUNC(str(secret).encode('utf-8')).digest()
