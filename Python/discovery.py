import os
import socket
import select
import time
import json
import traceback
from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import keygen as kg
from messaging import encrypt_message, decrypt_message
from storage import encrypt_data
from service import ServiceListener
import threading

class discovery:
    def __init__(self):
        self.aes_key = None
        self.socket = None
        self.pub_fp = None
        self.clients = []
        self.lock = threading.Lock()

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
                client_thread = threading.Thread(target=self.handle_client_connection, args=(client_socket, client_address))
                client_thread.daemon = True
                client_thread.start()
                with self.lock:
                    self.clients.append(client_socket)

    def handle_client_connection(self, client_socket, address):
        data_buffer = b''
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                data_buffer += data
                while b'\n' in data_buffer:
                    message, _, data_buffer = data_buffer.partition(b'\n')
                    try:
                        #decode THEN to json
                        message_json = json.loads(message.decode('utf-8'))
                        action = message_json.get('action')
                        if action == 'keyExchange' and self.key_exchange(message_json, client_socket):
                            print("Key exchange complete.")
                        elif action == 'sendMessage':
                            print("Message Recieved...")
                            self.handle_message_reception(message_json)
                    except json.JSONDecodeError as error:
                        print(f'Failed to parse incoming message: {error}')
        except Exception as error:
            print(f'Connection to {address} closed with error: {error}')
        finally:
            client_socket.close()
            self.clients.remove(client_socket)

    def key_exchange(self, message, client_socket):
        try:
            # Generate server DH keys based on predefined parameters
            dh_keys = kg.generate_dh_keys()
            server_private_key, server_public_key = dh_keys['private_key'], dh_keys['public_key']

            # Convert client's public key from received message
            client_public_numbers = dh.DHPublicNumbers(int(message['dhPublicKey'], 16), kg.get_dh_parameters().parameter_numbers())
            client_public_key = client_public_numbers.public_key(default_backend())

            # Derive shared secret
            shared_secret = server_private_key.exchange(client_public_key)

            # Logging for debug
            print(f"Shared secret: {shared_secret.hex()}")

            # Derive AES key from the shared secret
            self.aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_secret)

            print("AES Key :", self.aes_key.hex())

            # Send DH public key and fingerprint back to client
            response = {
                'action': 'keyExchangeResponse',
                'dhPublicKey': format(server_public_key.public_numbers().y, 'x'),
                'fingerprint': kg.get_public_key_fingerprint(server_public_key)
            }
            client_socket.send(json.dumps(response).encode())

            print("Key exchange successful, AES key derived.")
            return True
        except Exception as e:
            print(f"Error during key exchange: {e}")
            return False


    def handle_message_reception(self, message):
        print(message)
        # Decrypt the message
        try:
            decrypted_bytes = decrypt_message(message['message'], self.aes_key)
        except Exception as e:
            print(f"Failed to decrypt received message: {e}")
            return
        
        if decrypted_bytes is None:
                print("Failed to decrypt message.")
                return
            
        try:
            # Decode and print the decrypted message
            decrypted_message_json = decrypted_bytes.decode('utf-8')
            decrypted_message_dict = json.loads(decrypted_message_json)
            print("Decrypted Message Content:", decrypted_message_dict['content'])
            print("Message Timestamp:", decrypted_message_dict['timestamp'])
        except Exception as e:
            print(f"Failed to process received message: {e}")
            return

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

        key_exchange_message = {
            'action': 'keyExchange',
            'dhPublicKey': format(dh_keys['public_key'].public_numbers().y, 'x'),
            'fingerprint': kg.get_public_key_fingerprint(dh_keys['public_key'])
        }

        print("Keys generated. Ready to send.")
        #To json THEN encode
        client_socket.sendall((json.dumps(key_exchange_message) + '\n').encode('utf-8'))
        print("Sent Fingerprint :", key_exchange_message['fingerprint'])

        # Listen for a response to complete the key exchange process
        response_data = client_socket.recv(4096)
        response = json.loads(response_data.decode('utf-8'))
        if response['action'] == 'keyExchangeResponse':
            print(f"Received Fingerprint: {response['fingerprint']}")
            # Complete the exchnage process. Derive the AES key using the received DH public key
            peer_public_numbers = dh.DHPublicNumbers(int(response['dhPublicKey'], 16), kg.get_dh_parameters().parameter_numbers())
            peer_public_key = peer_public_numbers.public_key(default_backend())

            try:
                shared_secret = dh_keys['private_key'].exchange(peer_public_key)
                
                # Logging for debug
                print(f"Shared secret: {shared_secret.hex()}")
            except Exception as e:
                print(f"Failed in key exchange process with error: {e}")
                traceback.print_exc()

            # Derive the AES key from the shared secret
            self.aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_secret)

            print("AES Key :", self.aes_key.hex())

            print("Connection complete.")

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
        encrypted_message = encrypt_message(json.dumps(message_with_timestamp), self.aes_key)

        # Send the encrypted message
        try:
            self.socket.sendall((json.dumps({
                'action': 'sendMessage',
                'message': encrypted_message,
                'isFile': is_file
            }) + '\n').encode('utf-8'))
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