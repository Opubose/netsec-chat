import json
import time
import queue
import socket
import threading
import sys
from crypto_utils import (
    load_rsa_private_key,
    load_rsa_public_key,
    verify_signature,
    sign_message,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from typing import Dict, Any

SERVER_IP = "127.0.0.1"
SERVER_PORT = 8080
CLIENTS = [
    "alice",
    "bob",
]  # assumption: server "knows" the clients' identifiers (names in this case)


class RelayServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        print("[relay] Loading private key")
        self.private_key: RSAPrivateKey = load_rsa_private_key("relay_private_key.pem")
        if not self.private_key:
            raise RuntimeError("Failed to load relay's private key!")

        print("[relay] Loading clients' public keys")
        self.known_public_keys: Dict[str, RSAPublicKey] = self.load_client_public_keys()

        self.active_connections = {}
        self.connection_lock = threading.Lock()

    def load_client_public_keys(self) -> Dict[str, RSAPublicKey]:
        """Load public keys for all known clients from files"""
        public_keys = {}
        for client in CLIENTS:
            try:
                public_key: RSAPublicKey = load_rsa_public_key(
                    f"{client}_public_key.pem"
                )
                public_keys[client] = public_key
            except Exception as e:
                print(f"[relay] Error loading public key for {client}: {e}")
        return public_keys

    def start(self):
        """Binds server to host/port and starts listening for incoming connections"""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"[relay] Server listening on {self.host}:{self.port}...")

        try:
            while True:
                client_socket, addr = self.server_socket.accept()
                print(f"[relay] New connection from {addr}")
                clienthandler = threading.Thread(
                    target=self.handle_client, args=(client_socket,)
                )
                clienthandler.daemon = True
                clienthandler.start()

        except KeyboardInterrupt:
            print("\n[relay] Shutting down server...")
        finally:
            self.server_socket.close()

    def handle_client(self, client_socket: socket.socket) -> None:
        """Handles communication with a connected client"""

        """ registration protocol """
        print("[relay] Receiving registration request")
        msg: Dict[str, Any] = json.loads(client_socket.recv(4096).decode("utf-8"))

        client_id: str = msg["payload"]["sender"]
        print(f"[relay] Registration request from client: {client_id}")

        # verify against replay with timestamp
        print("[relay] Verifying timestamp...")
        if round(time.time(), -1) != round(msg["payload"]["timestamp"], -1):
            print("[relay] Stale timestamp detected! Rejecting connection...")
            return

        # verify the signature
        print(f"[relay] Verifying {client_id}'s signature")
        client_key: RSAPublicKey = self.known_public_keys[client_id]

        if not verify_signature(
            client_key,
            json.dumps(msg["payload"]).encode(),
            msg["signature"],
        ):
            print("[relay] Signature could not be verified! Rejecting connection...")
            return

        # once tests are passed, send auth to client
        print(f"[relay] Client {client_id} authenticated")
        print(f"[relay] Sending authentication response to {client_id}")
        data: Dict[str, Any] = {"recipient": client_id, "timestamp": time.time()}

        msg: bytes = json.dumps(
            {
                "type": "registration",
                "payload": data,
                "signature": sign_message(self.private_key, json.dumps(data).encode()),
            }
        ).encode("utf-8")

        client_socket.sendall(msg)
        print(f"[relay] Client {client_id} registration complete\n")

        # create queue for relaying messages
        self.active_connections[client_id] = queue.Queue()

        # stop waiting to recieve messages
        client_socket.setblocking(False)

        """ Relay between the clients """
        while True:
            try:
                raw_msg: bytes = client_socket.recv(4096)
                if not raw_msg:
                    print(f"[relay] Client {client_id} closed the connection.\n")
                    self.end_client_session(client_id)
                    break

                msg_data: Dict[str, Any] = json.loads(raw_msg.decode("utf-8"))
                recipient: str = msg_data["recipient"]
                sender: str = msg_data["sender"]

                """ authenticate the message before relaying. """
                """ replay attacks are handled in the client. """
                if (sender != client_id) or (
                    not verify_signature(
                        client_key,
                        json.dumps(msg_data["payload"]),
                        msg_data["signature"],
                    )
                ):
                    print(
                        f"[relay] Warning: message from {client_id} could not be authenticated! Rejecting..."
                    )
                    continue

                # lock before accessing queue to prevent thread issues
                print(f"[relay] Relaying message: {sender} -> {recipient}")
                
                ## Uncomment this during demo (confidentiality)
                # print(f"[relay] Message payload: {msg_data['payload']}")

                with self.connection_lock:
                    if recipient in self.active_connections:
                        ## Uncomment this during demo (tamper attack)
                        # data_dict = json.loads(raw_msg.decode('utf-8'))
                        # if 'ciphertext' in data_dict['payload']:
                        #     print("[relay] Tampering with ciphertext >:)")
                        #     ciphertext_content = data_dict['payload']['ciphertext']
                        #     tampered_cipher = ciphertext_content[::-1]  # simple tampering by reversing
                        #     data_dict['payload']['ciphertext'] = tampered_cipher
                        #     raw_msg = json.dumps(data_dict).encode('utf-8')

                        self.active_connections[recipient].put(raw_msg)

                        ## Uncomment this during demo (replay attack)
                        # print(f"[relay] Replaying message to {recipient} >:)")
                        # self.active_connections[recipient].put(raw_msg)

                    else:
                        print(
                            f"[relay] Warning: {recipient} is not connected but {sender} is trying to send them a message! Rejecting..."
                        )
                        # send error message to client
                        msg: Dict[str, str] = {
                            "message": "{recipient} is not connected.",
                            "timestamp": time.time(),
                        }
                        client_socket.sendall(
                            json.dumps(
                                {
                                    "sender": "relay",
                                    "recipient": client_id,
                                    "payload": msg,
                                    "signature": sign_message(
                                        self.private_key,
                                        json.dumps(msg).encode("utf-8"),
                                    ),
                                }
                            ).encode("utf-8")
                        )
            except BlockingIOError:
                # timeout error (no messages)
                pass
            except json.JSONDecodeError as e:
                print(
                    f"[relay] ERROR: Invalid JSON received from {client_id}: {e}\n",
                    file=sys.stderr,
                )
                self.end_client_session(client_id)
                break

            except ConnectionResetError:
                print(
                    f"[relay] ERROR: Connection lost to {client_id}.\n", file=sys.stderr
                )
                self.end_client_session(client_id)
                break

            """ get message from queue each round and send it """
            with self.connection_lock:
                if not self.active_connections[client_id].empty():
                    client_socket.sendall(self.active_connections[client_id].get())

    def relay_message(self, client_socket: socket.socket, data: bytes) -> None:
        client_socket.sendall(data)

    def end_client_session(self, client: str) -> None:
        """remove client from active connection list."""
        with self.connection_lock:
            del self.active_connections[client]


if __name__ == "__main__":
    relay_server = RelayServer(SERVER_IP, SERVER_PORT)
    relay_server.start()
