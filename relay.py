import socket
import threading
from crypto_utils import load_rsa_private_key, load_rsa_public_key, verify_signature
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from typing import Dict
import json

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
        # TODO: implement registration protocol with signed timestamp challenge-response auth
        # TODO: everything else
        pass
        
    def relay_message(self, data: bytes) -> None:
        # TODO: implement message relaying
        pass

if __name__ == "__main__":
    relay_server = RelayServer(SERVER_IP, SERVER_PORT)
    relay_server.start()
