import json
import time
import socket
import threading
import sys
import os
from tempfile import gettempdir
from crypto_utils import (
    load_rsa_private_key,
    load_rsa_public_key,
    sign_message,
    verify_signature,
    keyed_hash_encrypt,
    keyed_hash_decrypt,
    generate_dh_private_key,
    compute_dh_public_key,
    compute_dh_shared_secret,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from typing import Dict, Any, Optional, List

SERVER_IP: str = "127.0.0.1"
SERVER_PORT: int = 8080
HOSTS: List[str] = [
    "alice",
    "bob",
    "relay",
]  # assumption: client "knows" everyone's identifiers (names in this case)

LOCK_FILE = os.path.join(
    gettempdir(), "netsec-chat.lock"
)  # lock file to prevent multiple instances of bob


class RelayClient:
    def __init__(self, name: str) -> None:
        self.client_socket: socket.socket = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        )
        self.name: str = name
        self.recipient: Optional[str] = None
        self.send_counter: int = 0
        self.receive_counter: int = 0
        self.session_key: Optional[bytes] = None
        self.running: bool = True

        print(f"[{name}] Loading my private key")
        self.private_key: RSAPrivateKey = load_rsa_private_key(
            f"{name}_private_key.pem"
        )
        if not self.private_key:
            raise RuntimeError(f"Failed to load {name}'s private key!")

        print(f"[{name}] Loading everyone's public keys")
        self.known_public_keys: Dict[str, RSAPublicKey] = self.load_public_keys()

        print(f"[{name}] Connecting to relay at {SERVER_IP}:{SERVER_PORT}")
        try:
            self.client_socket.connect((SERVER_IP, SERVER_PORT))
        except ConnectionRefusedError:
            print(
                f"[{self.name}] Failed to connect to relay. Are you sure it's running?"
            )
            sys.exit(1)

        print(f"[{name}] Starting registration protocol")
        if not self.register():
            raise RuntimeError(f"Failed to authenticate server to host!")
        print(f"[{name}] Registration complete\n")

    def load_public_keys(self) -> Dict[str, RSAPublicKey]:
        """Load public keys for all known hosts."""
        public_keys: Dict[str, RSAPublicKey] = {}
        for host in HOSTS:
            try:
                public_key: RSAPublicKey = load_rsa_public_key(f"{host}_public_key.pem")
                public_keys[host] = public_key
            except Exception as e:
                print(f"[{self.name}] Error loading public key for {host}: {e}")
        return public_keys

    def register(self) -> bool:
        """Register with the relay server and authenticate it."""
        registration_data: Dict[str, Any] = {
            "sender": self.name,
            "timestamp": time.time(),
        }

        print(f"[{self.name}] Signing registration request with my private key")
        signature: str = sign_message(
            self.private_key, json.dumps(registration_data).encode("utf-8")
        )
        msg: bytes = json.dumps(
            {
                "type": "registration",
                "payload": registration_data,
                "signature": signature,
            }
        ).encode("utf-8")

        print(f"[{self.name}] Sending registration request to relay")
        self.client_socket.sendall(msg)

        print(f"[{self.name}] Waiting for relay authentication response")
        try:
            response: Dict[str, Any] = json.loads(
                self.client_socket.recv(4096).decode("utf-8")
            )
        except Exception:
            print(f"[{self.name}] Registration failed (no response)")
            return False

        print(f"[{self.name}] Verifying relay timestamp")
        if round(time.time(), -1) != round(response["payload"]["timestamp"], -1):
            print(f"[{self.name}] Stale timestamp from relay detected!")
            return False

        # verify the signature
        print(f"[{self.name}] Verifying relay signature")
        if not verify_signature(
            self.known_public_keys["relay"],
            json.dumps(response["payload"]).encode("utf-8"),
            response["signature"],
        ):
            print(f"[{self.name}] Signature verification failed")
            return False

        print(f"[{self.name}] Relay authenticated successfully")
        return True

    def _send_json(
        self, payload: Dict[str, Any], recipient: str, msg_type: str = "message"
    ) -> None:
        """Helper function for making and sending jsons via relay."""
        packet: bytes = json.dumps(
            {
                "sender": self.name,
                "recipient": recipient,
                "type": msg_type,
                "payload": payload,
                "signature": sign_message(self.private_key, json.dumps(payload)),
            }
        ).encode("utf-8")

        self.client_socket.sendall(packet)

    def secure_send(self, message: str, recipient: str) -> None:
        """Encrypts and sends a message using the session key."""
        if not self.session_key:
            print(f"[{self.name}] Error: no session key established yet!")
            return

        nonce: bytes = str(self.send_counter).encode("utf-8")
        plaintext: bytes = f"{message}|{self.send_counter}".encode("utf-8")

        ciphertext: bytes
        mac: bytes
        ciphertext, mac = keyed_hash_encrypt(self.session_key, plaintext, nonce)

        payload: Dict[str, str] = {"ciphertext": ciphertext.hex(), "mac": mac.hex()}

        self._send_json(payload, recipient, msg_type="message")
        self.send_counter += 1

    def start_chat(self, recipient: str) -> None:
        """For the chat send loop."""
        self.recipient = recipient
        print(f"[{self.name}] Secure session established with {self.recipient}")
        print(
            f'[{self.name}] Enter your messages below :D, or type "exit chat" to quit :(\n'
        )

        receive_thread: threading.Thread = threading.Thread(target=self.receive_loop)
        receive_thread.daemon = True
        receive_thread.start()

        while self.running:
            try:
                msg: str = input()
                if not self.running:
                    break

                if msg.lower() == "exit chat":
                    print(f"[{self.name}] Leaving so soon? Good bye :(...")
                    self.running = False
                    self.client_socket.close()
                    break

                sys.stdout.write(f"\033[F\033[K")
                print(f"[Me]: {msg}")
                self.secure_send(msg, recipient)

            except KeyboardInterrupt:
                self.running = False
                break
            except Exception as e:
                print(f"[{self.name}] Error encountered while sending message: {e}")
                break

    def receive_loop(self) -> None:
        """Incoming message listener loop."""
        while self.running:
            try:
                incoming_data: bytes = self.client_socket.recv(4096)
                if not incoming_data:
                    break

                data: Dict[str, Any] = json.loads(incoming_data.decode("utf-8"))
                sender: str = data["sender"]
                payload: Dict[str, Any] = data["payload"]

                if "ciphertext" in payload:
                    if not self.session_key:
                        print(
                            f"[{self.name}] Error: Received encrypted message but no session key!"
                        )
                        continue

                    ciphertext: bytes = bytes.fromhex(payload["ciphertext"])
                    mac: bytes = bytes.fromhex(payload["mac"])
                    nonce: bytes = str(self.receive_counter).encode("utf-8")

                    try:
                        plaintext: str = keyed_hash_decrypt(
                            self.session_key, ciphertext, nonce, mac
                        ).decode("utf-8")

                        msg: str
                        counter_str: str
                        msg, counter_str = plaintext.rsplit("|", 1)

                        if int(counter_str) != self.receive_counter:
                            print(
                                f"[{self.name}] Warning!!! Replay or out-of-order attack detected :O",
                                file=sys.stderr,
                            )
                            print(
                                f"[{self.name}] Expected counter {self.receive_counter}, got {counter_str}",
                                file=sys.stderr,
                            )
                            print(
                                f"[{self.name}] Terminating this chat immediately for security. Sorry about that.",
                                file=sys.stderr,
                            )
                            self.running = False
                            self.client_socket.close()
                            break
                        else:
                            print(f"[{sender}]: {msg}")
                            self.receive_counter += 1

                    except ValueError as ve:
                        print(
                            f"[{self.name}] Warning!!! MAC integrity check failed from {sender}!",
                            file=sys.stderr,
                        )
                        print(
                            f"[{self.name}] Message may have been tampered with: {ve}",
                            file=sys.stderr,
                        )
                        print(
                            f"[{self.name}] Terminating this chat immediately for security. Sorry about that.",
                            file=sys.stderr,
                        )
                        self.running = False
                        self.client_socket.close()
                        break
                    except Exception as e:
                        print(
                            f"[{self.name}] ERROR: Decryption error: {e}",
                            file=sys.stderr,
                        )
                        break
                elif sender == "relay":
                    """if recipient disconnects, relay notifies the client."""
                    # re-authenticate server message
                    if not verify_signature(
                        self.known_public_keys["relay"],
                        json.dumps(payload).encode("utf-8"),
                        data["signature"],
                    ) or (round(time.time(), -1) != round(payload["timestamp"], -1)):
                        print(
                            f"[{self.name}] Status message from {sender} could not be authenticated!",
                            file=sys.stderr,
                        )
                        print(
                            f"[{self.name}] Terminating this chat immediately for security. Sorry about that.",
                            file=sys.stderr,
                        )
                        self.client_socket.close()
                    else:
                        print(f"[{self.name}] {self.recipient} has disconnected.")
                    self.running = False

                    break
            except ConnectionResetError:
                print(f"[{self.name}] ERROR: Connection lost.", file=sys.stderr)
                print(f"[{self.name}] Terminating session.", file=sys.stderr)
                self.running = False
                break
            except json.JSONDecodeError as e:
                print(
                    f"[{self.name}] ERROR: Invalid JSON received: {e}", file=sys.stderr
                )
                print(f"[{self.name}] Terminating session.", file=sys.stderr)
                self.running = False
                break
            except Exception as e:
                print(f"[{self.name}] ERROR: Encountered error: {e}", file=sys.stderr)
                self.running = False
                break


class Alice(RelayClient):
    def __init__(self) -> None:
        super().__init__("alice")

    def start(self, recipient: str) -> None:
        """Start communication with the specified recipient."""
        self.recipient = recipient
        self.start_messages()

    def start_messages(self) -> None:
        """Exchange messages with Bob using authenticated Diffie-Hellman."""
        if not self.recipient:
            raise RuntimeError("Recipient not specified")

        print(f"[{self.name}] Starting session establishment with {self.recipient}")

        print(f"[{self.name}] Generating my DH private key")
        priv_key: int = generate_dh_private_key()
        pub_key: int = compute_dh_public_key(priv_key)
        print(f"[{self.name}] Computed my DH public key g^a mod p = {hex(pub_key)}")

        # send message with verification (signature computed in sending)
        print(f"[{self.name}] Signing my DH public key with my RSA private key")
        print(f"[{self.name}] Sending authenticated DH public key to {self.recipient}")
        self._send_json(
            {"pubkey": pub_key},
            self.recipient,
            msg_type="handshake",
        )

        print(f"[{self.name}] Waiting for {self.recipient}'s DH public key...")
        msg: Dict[str, Any] = json.loads(self.client_socket.recv(4096).decode("utf-8"))
        # terminate if not connected

        if msg["sender"] == "relay":
            raise RuntimeError(
                f"[{self.name}] {self.recipient} is not currently connected.\n"
                "Ending session."
            )
        bob_pubkey: int = msg["payload"]["pubkey"]
        bob_signature: str = msg["signature"]
        print(f"[{self.name}] Received {self.recipient}'s DH public key = {hex(bob_pubkey)}")

        # i think we forgot to do this before..................... x2
        print(
            f"[{self.name}] Verifying {self.recipient}'s signature against their DH public key"
        )
        bob_pubkey_bytes: bytes = json.dumps(msg["payload"]).encode("utf-8")
        if not verify_signature(
            self.known_public_keys[self.recipient], bob_pubkey_bytes, bob_signature
        ):
            raise RuntimeError(
                f"[{self.name}] Warning!!! {self.recipient}'s DH public key signature verification failed!\n"
                "Potential MITM attack detected.\n"
                "Terminating this chat immediately for security. Sorry about that."
            )

        print(f"[{self.name}] {self.recipient}'s signature verified successfully")

        print(f"[{self.name}] Computing shared session key")
        self.session_key = compute_dh_shared_secret(bob_pubkey, priv_key)
        print(f"[{self.name}] Session key established: 0x{self.session_key.hex()}\n")

        # Now that session is established, can send messages
        self.start_chat(self.recipient)


class Bob(RelayClient):
    def __init__(self) -> None:
        super().__init__("bob")

    def start(self) -> None:
        """Start listening for incoming sessions."""
        self.start_messages()

    def start_messages(self) -> None:
        """Exchange messages with Alice using authenticated Diffie-Hellman."""
        print(f"[{self.name}] Waiting for session establishment request")

        msg: Dict[str, Any] = json.loads(self.client_socket.recv(4096).decode("utf-8"))
        sender: str = msg["sender"]
        peer_pubkey: int = msg["payload"]["pubkey"]
        peer_signature: str = msg["signature"]

        print(
            f"[{self.name}] Received connection request from {sender} with DH public key {hex(peer_pubkey)}"
        )

        print(
            f"[{self.name}] Verifying {sender}'s signature against their DH public key"
        )
        peer_pubkey_bytes: bytes = json.dumps(msg["payload"]).encode("utf-8")
        if not verify_signature(
            self.known_public_keys[sender], peer_pubkey_bytes, peer_signature
        ):
            raise RuntimeError(
                f"[{self.name}] Warning!!! {self.recipient}'s DH public key signature verification failed!\n"
                "Potential MITM attack detected.\n"
                "Terminating this chat immediately for security. Sorry about that."
            )

        print(f"[{self.name}] {sender}'s signature verified successfully")

        print(f"[{self.name}] Generating my DH private key")
        priv_key: int = generate_dh_private_key()
        pub_key: int = compute_dh_public_key(priv_key)
        print(f"[{self.name}] Computed my DH public key g^b mod p = {hex(pub_key)}")

        print(f"[{self.name}] Computing shared session key from DH")
        self.session_key = compute_dh_shared_secret(peer_pubkey, priv_key)
        print(f"[{self.name}] Session key established: 0x{self.session_key.hex()}\n")

        # signs in message
        print(f"[{self.name}] Signing my DH public key with my RSA private key")

        self.recipient = sender  # probably important step

        # i think we forgot to do this before..................... x4
        print(f"[{self.name}] Sending authenticated DH public key to {self.recipient}")
        self._send_json(
            {"pubkey": pub_key},
            self.recipient,
            msg_type="handshake",
        )

        # Now can send regular messages
        self.start_chat(self.recipient)


if __name__ == "__main__":
    if not os.path.exists(LOCK_FILE):
        print("Starting as Bob (waiting for connection)...")

        with open(LOCK_FILE, "w") as f:
            f.write("locked and running!")

        try:
            client_handler = Bob()
            client_handler.start()
        finally:
            if os.path.exists(LOCK_FILE):
                os.remove(LOCK_FILE)
            print("Bob has exited and lock file removed ^_^")
    else:
        print("Bob is already running. Starting as Alice (initiating connection)...")
        client_handler = Alice()
        client_handler.start("bob")
