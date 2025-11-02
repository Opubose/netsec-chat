import json
import time
import queue
import socket
import threading
from crypto_utils import load_rsa_private_key, load_rsa_public_key, verify_signature, sign_message
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from typing import Dict

SERVER_IP = '127.0.0.1'
SERVER_PORT = 8080
CLIENTS = ['alice', 'bob']  # assumption: server "knows" the clients' identifiers (names in this case)

"""
Proposed message format in json:
{
    "sender": "alice",                  // or "bob"
    "recipient": "bob",                 // or "alice"
    "timestamp": 1696543200,            // unix epoch time
    "type": "message",                  // or "registration"
    "payload": {"whatever": "data"},
    "counter": 0,                       // keep incrementing
    "signature": "base64-encoded-signature"
}
"""

class RelayServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.private_key = load_rsa_private_key('relay_private_key.pem')
        if not self.private_key:
            raise RuntimeError("Failed to load relay's private key!")
        
        self.known_public_keys = self.load_client_public_keys()
        self.active_connections = {}
        self.connection_lock = threading.Lock()
    
    def load_client_public_keys(self) -> Dict[str, RSAPublicKey]:
        """Load public keys for all known clients from files"""
        public_keys = {}
        for client in CLIENTS:
            try:
                public_key = load_rsa_public_key(f"{client}_public_key.pem")
                public_keys[client] = public_key
            except Exception as e:
                print(f"Error loading public key for {client}: {e}")
        return public_keys
    
    def start(self):
        """Binds server to host/port and starts listening for incoming connections"""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Relay server listening on {self.host}:{self.port}...")
        
        try:
            while True:
                client_socket, addr = self.server_socket.accept()
                print(f"Client joined from {addr}")
                clienthandler = threading.Thread(target=self.handle_client, args=(client_socket,))
                clienthandler.daemon = True
                clienthandler.start()

        except KeyboardInterrupt:
            print("Shutting down server...")
        finally:
            self.server_socket.close()
    
    def handle_client(self, client_socket: socket.socket) -> None:
        """Handles communication with a connected client"""

        ## registration protocol
        msg = json.loads(client_socket.recv(1024).decode('utf-8'))

        client_id = msg['payload']['sender']
        
        # verify against replay with timestamp
        if (round(time.time(), -1) != round(msg['payload']['timestamp'], -1)):
            print(f"Timestamp of client {client_id} is wrong - this message is old.")
            return
        
        # verify the signature
        if (not verify_signature(self.known_public_keys[client_id],  json.dumps(msg['payload']), msg['signature'])):
            print(f"Message cannot be verified to be from {client_id}.")
            return

        # once tests are passed, send auth to client
        data = { "recipient": client_id, "timestamp": time.time() }

        msg = json.dumps({
            "type": "registration",
            "payload": data,
            "signature": sign_message(self.private_key, json.dumps(data))
        }).encode('utf-8')

        client_socket.sendall(msg)

        # create queue for relaying messages
        self.active_connections[client_id] = queue.Queue()

        # stop waiting to recieve messages
        client_socket.setblocking(0)
        
        # now relay messages
        while True: 
            try:
                msg = client_socket.recv(1024)
                recipient = json.loads(msg.decode('utf-8'))['recipient']
                # lock before accessing queue
                with self.connection_lock:
                    self.active_connections[recipient].put(msg)
            except: 
                continue
            finally:
                # lock before accessing queue
                with self.connection_lock:
                    if (not self.active_connections[client_id].empty()):
                        self.relay_message(client_socket, self.active_connections[client_id].get())

       
         
        
    def relay_message(self, client_socket, data: bytes) -> None:
        client_socket.sendall(data)
        

if __name__ == "__main__":
    relay_server = RelayServer(SERVER_IP, SERVER_PORT)
    relay_server.start()
