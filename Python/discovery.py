import os
import socket
import select
import time
import json
from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import load_pem_public_key, PublicFormat, Encoding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import keygen as kg
import messaging
from storage import encrypt_data
from service import ServiceListener
import threading

class discovery:
    def __init__(self):
        self.dh = None
        self.aes_key = None
        self.socket = None
        self.pub_fp = None
        self.clients = []
        self.lock = threading.Lock()
        self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

    def publish(self):
        with Zeroconf() as zeroconf:
            service_type = "_http._tcp.local."
            service_name = "SecureMsgService._http._tcp.local."
            service_port = 3000
            service_info = ServiceInfo(service_type, service_name, addresses=[socket.inet_aton("127.0.0.1")], port=service_port, properties={})
            zeroconf.register_service(service_info)
            print('Service published. Awaiting connections...')
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(('', service_port))
                server_socket.listen()

                try:
                    self.accept_connections(server_socket)
                finally:
                    zeroconf.unregister_service(service_info)

    def accept_connections(self, server_socket):
        while True:
            ready_to_read, _, _ = select.select([server_socket], [], [], 10)
            if ready_to_read:
                client_socket, client_address = server_socket.accept()
                print(f'Accepted connection from {client_address}')
                client_thread = threading.Thread(target=self._handle_client_connection, args=(client_socket, client_address))
                client_thread.daemon = True
                client_thread.start()
                with self.lock:
                    self.clients.append(client_socket)

    def _handle_client_connection(self, socket, address):
        data_buffer = ''
        try:
            while True:
                data = socket.recv(4096).decode('utf-8')
                if not data:
                    break
                data_buffer += data
                while '\n' in data_buffer:
                    message, data_buffer = data_buffer.split('\n', 1)
                    try:
                        message_json = json.loads(message)
                        if message_json['action'] == 'keyExchange':
                            if self.key_exchange(message_json, socket):
                                print("Key exchange complete.")
                        elif message_json['action'] == 'sendMessage':
                            self.handle_message_reception(message_json)
                    except json.JSONDecodeError as error:
                        print(f'Failed to parse incoming message: {error}')
        except Exception as error:
            print(f'Connection to {address} closed with error: {error}')
            socket.close()
            self.clients.remove(socket)

    def key_exchange(self, message, client_socket):
        try:
            # Assuming `self.dh_parameters` is predefined and shared across server and client
            keys = kg.generate_dh_keys()
            server_private_key, server_public_key = keys['private_key'], keys['public_key']

            # Use the keygen instance correctly with 'self'
            fingerprint = kg.get_public_key_fingerprint(server_public_key)
            print("Fingerprint:", fingerprint)

            # Decode the client's public key
            print("From Message :", message['dhPublicKey'])
            client_public_key_bytes = bytes.fromhex(message['dhPublicKey'])
            client_public_key = load_pem_public_key(client_public_key_bytes, backend=default_backend())

            print("Exchanging keys...")
            # Compute the shared secret
            shared_secret = server_private_key.exchange(client_public_key)

            print("Deriving AES Key...")
            # Derive AES key from the shared secret
            self.aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_secret)

            print("preparing response...")
            # Prepare and send the response
            response = {
                'action': 'keyExchangeResponse',
                'dhPublicKey': server_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).hex(),
                'fingerprint': fingerprint
            }

            print("sending response...")
            client_socket.sendall(json.dumps(response).encode())
            return True

        except Exception as error:
            print(f'Failed in key exchange process with error: {error}')
            return False

    def handle_message_reception(self, message):
        if self.aes_key is None:
            print('AES key is not set. Unable to decrypt message.')
            return
        try:
            encrypted_data = json.loads(message['message'])
            decrypted_message = self._decrypt_(encrypted_data, self.aes_key).decode('utf-8')
            # Secure storage
            storage_path = os.path.join(os.path.dirname(__file__), 'messages.json')
            with open(storage_path, 'a') as file:
                encrypted_storage_data = encrypt_data(decrypted_message)
                file.write(json.dumps(encrypted_storage_data) + '\n')
            print('Decrypted Message:', decrypted_message)
        except Exception as error:
            print(f'Error during message reception: {error}')

    def _decrypt_(self, encrypted_data, aes_key):
        iv = bytes.fromhex(encrypted_data['iv'])
        ciphertext = bytes.fromhex(encrypted_data['content'])
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def discover(self):
        listener = ServiceListener(self)
        self.browser = ServiceBrowser(listener.conf, "_http._tcp.local.", listener)      

    def connect(self, service):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        host = service['host']  # The service's hostname or IP address
        port = service['port']  # The service's port number

        client_socket.connect((host, port))
        self.socket = client_socket

        # Generating Diffie-Hellman keys and getting the public key fingerprint
        print("Generating keys for exchange...")
        dh_keys = kg.generate_dh_keys()
        self.dh = dh_keys['private_key']
        fingerprint = kg.get_public_key_fingerprint(dh_keys['public_key'])

        # Preparing the key exchange message
        dh_public_key_pem = dh_keys['public_key'].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_exchange_message = {
            'action': 'keyExchange',
            'dhPublicKey': dh_public_key_pem.hex(),
            'fingerprint': fingerprint
        }

        print("Keys generated. Ready to send.")
        # Sending the key exchange message
        client_socket.sendall((json.dumps(key_exchange_message) + '\n').encode('utf-8'))
        print("Keys have been sent :", key_exchange_message)

        # Listen for a response to complete the key exchange process
        response_data = client_socket.recv(4096)
        print("Response recieved.")
        response = json.loads(response_data.decode('utf-8'))
        if response['action'] == 'keyExchangeResponse':
            print(f"Received Fingerprint: {response['fingerprint']}")
            # Complete the exchnage process. Derive the AES key using the received DH public key
            peer_public_key_pem = bytes.fromhex(response['dhPublicKey'])
            peer_public_key = kg.load_public_key(peer_public_key_pem, backend=default_backend())

            shared_secret = self.dh.exchange(peer_public_key)

            # Derive the AES key from the shared secret
            aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_secret)

            # Save the AES key
            self.aes_key = aes_key

    def send_message(self, message, is_file=False):
        if not self.socket or not self.aes_key:
            print('No active session for sending messages.')
            return

        if is_file:
            try:
                with open(message, 'r') as file:
                    message_content = file.read()
            except FileNotFoundError:
                print('File does not exist.')
                return
        else:
            message_content = message

        # Timestamp the message
        message_with_timestamp = {
            'content': message_content,
            'timestamp': int(time.time() * 1000)
        }

        # Encrypt the message
        encrypted_message = messaging.encrypt_message(message_with_timestamp, self.aes_key)

        # Send the encrypted message
        try:
            self.socket.sendall(json.dumps({
                'action': 'sendMessage',
                'message': json.dumps(encrypted_message),
                'isFile': is_file
            }).encode('utf-8'))
            print('Message sent.')
        except Exception as e:
            print(f'Failed to send message: {e}')

    def notify_key_update(self):
        # Regenerate and save the new keys
        kg.regenerate_and_save_keys()
        
        # Load the new public key
        new_public_key_pem = kg.load_public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Prepare the notification message
        notification_message = {
            'action': 'keyUpdate',
            'newPublicKey': new_public_key_pem
        }
        
        # Convert the message to a JSON string and encode it for transmission
        encoded_message = json.dumps(notification_message).encode('utf-8')
        
        # Send the notification to all connected clients
        for client_socket in self.clients:
            try:
                client_socket.sendall(encoded_message)
                print('Notified client of new public key.')
            except Exception as e:
                print(f'Failed to notify client: {e}')
                print(f'Error broadcasting new public key to a client: {e}')

def main():
    dsc = discovery()
    dsc.publish()


if __name__ == "__main__":
    main()