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

        self.private_key = load_rsa_private_key(f'{name}_private_key.pem')
        if not self.private_key:
            raise RuntimeError(f"Failed to load {name}'s private key!")
        
        self.known_public_keys = self.load_public_keys()
        self.client_socket.connect((SERVER_IP, SERVER_PORT))
        if (not self.register()):
             raise RuntimeError(f"Failed to authenticate server to host!")


    def load_public_keys(self)  -> Dict[str, RSAPublicKey]:
        public_keys = {}
        # it does not matter if they have their own public key tbh
        for host in HOSTS:
            try:
                public_key = load_rsa_public_key(f"{host}_public_key.pem")
                public_keys[host] = public_key
            except Exception as e:
                print(f"Error loading public key for {host}: {e}")
        return public_keys
    
    def register(self) -> bool:
        registration_data = { 
            "sender": self.name, 
            "timestamp": time.time(),
        }

        msg = json.dumps({
            "type": "registration",
            "payload": registration_data,
            "signature": sign_message(self.private_key, json.dumps(registration_data))
        }).encode('utf-8')

        self.client_socket.sendall(msg)

        msg = json.loads(self.client_socket.recv(1024).decode('utf-8'))

        if (round(time.time(), -1) != round(msg['payload']['timestamp'], -1)):
            print(f"Timestamp of server is wrong.")
            return False
        
        # verify the signature
        if (not verify_signature(self.known_public_keys['relay'],  json.dumps(msg['payload']), msg['signature'])):
            print(f"Message is not from relay.")
            return False
        
        return True

    def send_message(self, payload: dict):
        payload["timestamp"] = time.time()

        msg = json.dumps({
            "sender": self.name,
            "recipient": self.recipient,
            "type": "message",
            "payload": payload,
            "signature": sign_message(self.private_key, json.dumps(payload))
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

        # start by setting up Diffie-Hellman
        priv_key = generate_dh_private_key()
    
        self.send_message({"pubkey": compute_dh_public_key(priv_key) })

        msg = json.loads(self.client_socket.recv(1024).decode('utf-8'))

        session_key = compute_dh_shared_secret(msg['payload']['pubkey'], priv_key)

        # now that that's established, can send messages
        self.send_message({"message": "Hi Bob ^w^"})

        msg = json.loads(self.client_socket.recv(1024).decode('utf-8'))['payload']

        print(f"Bob says: {msg['message']}")
        



class Bob(RelayClient):
    def __init__(self):
        super().__init__("bob")  

    def start(self):
        clienthandler = threading.Thread(target=self.start_messages, args=())
        clienthandler.start()
    
    def start_messages(self):
        """ exchange messages with Alice """

        # start by setting up Diffie-Hellman
        priv_key = generate_dh_private_key()

        msg = json.loads(self.client_socket.recv(1024).decode('utf-8'))
        self.recipient = msg['sender']

        session_key = compute_dh_shared_secret(msg['payload']['pubkey'], priv_key)

        self.send_message({ "pubkey": compute_dh_public_key(priv_key) })

        # now can send regular messages
        msg = json.loads(self.client_socket.recv(1024).decode('utf-8'))['payload']

        print(f"Alice says: {msg['message']}")

        self.send_message({ "message": "Hi Alice!" })
        
        time.sleep(30)



if __name__ == "__main__":
    alice = Alice()
    bob = Bob()

    alice.start("bob")
    bob.start()


