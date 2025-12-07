import hmac
import hashlib
import base64
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import serialization
from typing import Tuple, Union

HASH_FUNC = hashlib.sha256

"""
diffie-hellman params taken from RFC 3526 group 14 (2048-bit)
> https://datatracker.ietf.org/doc/html/rfc3526#section-3
"""
p_hex = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
p = int(p_hex, 16)

g = 2


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
            raise TypeError(
                f"Loaded private key is not an RSA private key: {type(private_key).__name__}"
            )
    except FileNotFoundError:
        raise FileNotFoundError(f"Private key file not found: {filepath}")
    except Exception as e:
        raise RuntimeError(f"Error loading private key: {e}")


def load_rsa_public_key(filepath: str) -> RSAPublicKey:
    try:
        with open(filepath, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
            )
        if isinstance(public_key, RSAPublicKey):
            return public_key
        else:
            raise TypeError(
                f"Loaded public key is not an RSA public key: {type(public_key).__name__}"
            )
    except FileNotFoundError:
        raise FileNotFoundError(f"Public key file not found: {filepath}")
    except Exception as e:
        raise RuntimeError(f"Error loading public key: {e}")


def sign_message(private_key: RSAPrivateKey, message: Union[str, bytes]) -> str:
    """Sign a message using RSA private key"""
    if isinstance(message, str):
        message = message.encode("utf-8")

    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(
    public_key: RSAPublicKey, message: Union[str, bytes], signature: Union[str, bytes]
) -> bool:
    """Verify a message signature using RSA public key"""
    if isinstance(message, str):
        message = message.encode("utf-8")

    if isinstance(signature, str):
        sig_bytes = base64.b64decode(signature.encode("utf-8"))
    else:
        sig_bytes = base64.b64decode(signature)

    try:
        public_key.verify(
            sig_bytes,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def keyed_hash_encrypt(
    key: bytes, plaintext: bytes, nonce: bytes
) -> Tuple[bytes, bytes]:
    """Encrypt plaintext using keyed-hash HMAC with the given key and nonce"""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    keystream = hmac.new(key, nonce, HASH_FUNC).digest()
    padded_keystream = (keystream * (len(plaintext) // len(keystream) + 1))[
        : len(plaintext)
    ]  # repeat the keystream to match plaintext length
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, padded_keystream))

    mac = hmac.new(key, ciphertext, HASH_FUNC).digest()

    return ciphertext, mac


def keyed_hash_decrypt(
    key: bytes, ciphertext: bytes, nonce: bytes, received_mac: bytes
) -> bytes:
    """Decrypt ciphertext using keyed-hash HMAC with the given key and nonce"""
    calculated_mac = hmac.new(key, ciphertext, HASH_FUNC).digest()
    if not hmac.compare_digest(calculated_mac, received_mac):
        raise ValueError("MAC integrity check failed! Decryption aborted.")

    keystream = hmac.new(key, nonce, HASH_FUNC).digest()
    padded_keystream = (keystream * (len(ciphertext) // len(keystream) + 1))[
        : len(ciphertext)
    ]  # repeat the keystream to match ciphertext length
    plaintext = bytes(c ^ k for c, k in zip(ciphertext, padded_keystream))

    return plaintext


def generate_dh_private_key() -> int:
    """Generate a private key for Diffie-Hellman key exchange"""
    return secrets.randbits(256)


def compute_dh_public_key(private_key: int) -> int:
    """Compute the Diffie-Hellman public key `g^private_key mod p`"""
    return pow(g, private_key, p)


def compute_dh_shared_secret(their_public_key: int, my_private_key: int) -> bytes:
    """Compute the Diffie-Hellman shared secret `their_public_key^my_private_key mod p`"""
    secret = pow(their_public_key, my_private_key, p)
    return HASH_FUNC(str(secret).encode("utf-8")).digest()
