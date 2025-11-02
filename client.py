import json
import time
import socket
import threading
from crypto_utils import *
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from typing import Dict

SERVER_IP = '127.0.0.1'
SERVER_PORT = 8080
HOSTS = ['alice', 'bob', 'relay']  # assumption: client "knows" everyone's identifiers (names in this case) 

class RelayClient:
    def __init__(self, name: str):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.name = name

        print(f"[{name}] Loading my private key")
        self.private_key = load_rsa_private_key(f'{name}_private_key.pem')
        if not self.private_key:
            raise RuntimeError(f"Failed to load {name}'s private key!")
        
        print(f"[{name}] Loading everyone's public keys")
        self.known_public_keys = self.load_public_keys()

        print(f"[{name}] Connecting to relay at {SERVER_IP}:{SERVER_PORT}")
        self.client_socket.connect((SERVER_IP, SERVER_PORT))

        print(f"[{name}] Starting registration protocol")
        if (not self.register()):
             raise RuntimeError(f"Failed to authenticate server to host!")
        print(f"[{name}] Registration complete\n")

    def load_public_keys(self)  -> Dict[str, RSAPublicKey]:
        public_keys = {}
        # it does not matter if they have their own public key tbh
        for host in HOSTS:
            try:
                public_key = load_rsa_public_key(f"{host}_public_key.pem")
                public_keys[host] = public_key
            except Exception as e:
                print(f"[{self.name}] Error loading public key for {host}: {e}")
        return public_keys
    
    def register(self) -> bool:
        registration_data = { 
            "sender": self.name, 
            "timestamp": time.time(),
        }

        print(f"[{self.name}] Signing registration request with my private key")
        msg = json.dumps({
            "type": "registration",
            "payload": registration_data,
            "signature": sign_message(self.private_key, json.dumps(registration_data).encode())
        }).encode('utf-8')

        print(f"[{self.name}] Sending registration request to relay")
        self.client_socket.sendall(msg)

        print(f"[{self.name}] Waiting for relay authentication response")
        msg = json.loads(self.client_socket.recv(1024).decode('utf-8'))

        print(f"[{self.name}] Verifying relay timestamp")
        if (round(time.time(), -1) != round(msg['payload']['timestamp'], -1)):
            print(f"[{self.name}] Stale timestamp from relay detected!")
            return False
        
        # verify the signature
        print(f"[{self.name}] Verifying relay signature")
        if (not verify_signature(self.known_public_keys['relay'],  json.dumps(msg['payload']).encode(), msg['signature'])):
            print(f"[{self.name}] Signature verification failed")
            return False
        
        print(f"[{self.name}] Relay authenticated successfully")
        return True

    def send_message(self, payload: dict):
        payload["timestamp"] = time.time()

        msg = json.dumps({
            "sender": self.name,
            "recipient": self.recipient,
            "type": "message",
            "payload": payload,
            "signature": sign_message(self.private_key, json.dumps(payload).encode())
        }).encode('utf-8')

        self.client_socket.sendall(msg)

    

class Alice(RelayClient): 
    def __init__(self):
        super().__init__("alice")
        
    
    def start(self, recipient):
        self.recipient = recipient
        clienthandler = threading.Thread(target=self.start_messages, args=())
        clienthandler.start()

    def start_messages(self):
        """  exchange messages with Bob """
        print(f"[{self.name}] Starting session establishment with {self.recipient}")
        
        # start by setting up Diffie-Hellman
        print(f"[{self.name}] Generating my DH private key")
        priv_key = generate_dh_private_key()

        pub_key = compute_dh_public_key(priv_key)
        print(f"[{self.name}] Computed my DH public key g^a mod p = {pub_key}")

        print(f"[{self.name}] Sending DH public key to {self.recipient}")
        self.send_message({ "pubkey": pub_key })

        print(f"[{self.name}] Waiting for {self.recipient}'s DH public key...")
        msg = json.loads(self.client_socket.recv(1024).decode('utf-8'))
        bob_pubkey = msg['payload']['pubkey']
        print(f"[{self.name}] Received Bob's DH public key = {bob_pubkey}")

        print(f"[{self.name}] Computing shared session key")
        session_key = compute_dh_shared_secret(bob_pubkey, priv_key)
        print(f"[{self.name}] Session key established\n")

        # now that that's established, can send messages
        print(f"[{self.name}] Sending message: 'Hi Bob ^w^'")
        self.send_message({"message": "Hi Bob ^w^"})

        print(f"[{self.name}] Waiting for {self.recipient}'s response...")
        msg = json.loads(self.client_socket.recv(1024).decode('utf-8'))['payload']
        print(f"[{self.name}] Received: '{msg['message']}'\n")


class Bob(RelayClient):
    def __init__(self):
        super().__init__("bob")  

    def start(self):
        clienthandler = threading.Thread(target=self.start_messages, args=())
        clienthandler.start()
    
    def start_messages(self):
        """ exchange messages with Alice """
        print(f"[{self.name}] Waiting for session establishment request")

        # start by setting up Diffie-Hellman
        print(f"[{self.name}] Generating my DH private key")
        priv_key = generate_dh_private_key()

        print(f"[{self.name}] Waiting for DH public key from peer")
        msg = json.loads(self.client_socket.recv(1024).decode('utf-8'))
        self.recipient = msg['sender']  # received message's sender will be my recipient
        peer_pubkey = msg['payload']['pubkey']
        print(f"[{self.name}] peer {self.recipient} has DH public key {peer_pubkey}")

        print(f"[{self.name}] Computing shared session key from DH")
        session_key = compute_dh_shared_secret(peer_pubkey, priv_key)

        pub_key = compute_dh_public_key(priv_key)
        print(f"[{self.name}] computed my DH public key g^b mod p = {pub_key}")

        print(f"[{self.name}] Sending my DH public key to {self.recipient}")
        self.send_message({ "pubkey": pub_key })
        print(f"[{self.name}] Session key established\n")

        # now can send regular messages
        print(f"[{self.name}] Waiting for message from {self.recipient}")
        msg = json.loads(self.client_socket.recv(1024).decode('utf-8'))['payload']
        print(f"[{self.name}] Received: '{msg['message']}'")

        print(f"[{self.name}] Sending message: 'Hi Alice ^_^'")
        self.send_message({ "message": "Hi Alice ^_^" })
        
        print()


if __name__ == "__main__":
    alice = Alice()
    bob = Bob()

    alice.start("bob")
    bob.start()