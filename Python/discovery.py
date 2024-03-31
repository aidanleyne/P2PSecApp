import os
import socket
import time
import json
import threading
from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser, ServiceStateChange
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from keygen import keygen
from messaging import encrypt_message
from storage import encrypt_data
from service import ServiceListener

class discovery:
    def __init__(self):
        self.kg = keygen()
        self.dh = None
        self.aes_key = None
        self.socket = None
        self.pub_fp = None
        self.clients = []

    def publish(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('', 3000))
        server_socket.listen()

        # Publish service using Zeroconf
        zeroconf = Zeroconf()
        service_type = "_http._tcp.local."
        service_name = "SecureMsgService._http._tcp.local."
        service_port = 3000
        service_info = ServiceInfo(service_type, service_name, addresses=[socket.inet_aton("127.0.0.1")], port=service_port, properties={})
        zeroconf.register_service(service_info)

        print('Service published and awaiting connections...')
        try:
            while True:
                client_socket, client_address = server_socket.accept()
                print(f'Accepted connection from {client_address}')
                self.clients.append(client_socket)
                client_thread = threading.Thread(target=self._handle_client_connection, args=(client_socket, client_address))  # Updated variable here
                client_thread.daemon = True
                client_thread.start()
        finally:
            zeroconf.unregister_service(service_info)
            zeroconf.close()
            server_socket.close()

    def _handle_client_connection(self, socket, address):
        try:
            while True:
                data = socket.recv(1024)
                if not data:
                    break  # Connection closed by the client
                try:
                    message = json.loads(data.decode('utf-8'))
                    if message['action'] == 'keyExchange':
                        self.key_exchange(message, socket)
                    elif message['action'] == 'sendMessage':
                        self.message_reception(message)
                except json.JSONDecodeError as error:
                    print(f'Failed to parse incoming message: {error}')
        finally:
            socket.close()
            self.clients.remove(socket)
            print(f'Connection to {address} closed.')

    def key_exchange(self, message, socket):
        try:
            dh_parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
            server_private_key = dh_parameters.generate_private_key()
            server_public_key = server_private_key.public_key()

            self.dh = server_private_key

            fingerprint = self.kg.get_public_key_fingerprint(server_public_key)
            print(f'DH Public Key: {server_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()}, Fingerprint: {fingerprint}')

            # Decode the received public key from the message
            client_public_key_pem = message['dhPublicKey']
            client_public_key = load_pem_public_key(bytes.fromhex(client_public_key_pem), backend=default_backend())

            # Compute shared secret
            shared_secret = server_private_key.exchange(client_public_key)

            # Derive AES key from shared secret
            self.aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                backend=default_backend()
            ).derive(shared_secret)

            # Send response back to client
            response = {
                'action': 'keyExchangeResponse',
                'dhPublicKey': server_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex(),
                'fingerprint': fingerprint
            }
            socket.sendall(json.dumps(response).encode())
        except Exception as error:
            print(f'Failed in key exchange process: {error}')

    def _decrypt_(self, encrypted_data, aes_key):
        iv = bytes.fromhex(encrypted_data['iv'])
        ciphertext = bytes.fromhex(encrypted_data['content'])
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

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

    def discover(self):
        listener = ServiceListener()
        browser = ServiceBrowser(listener.zeroconf, "_http._tcp.local.", listener)

        try:
            # Keep the main thread alive, or else the discovery will stop
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass
        finally:
            listener.zeroconf.close()

    """@TODO : finish this implementation"""
    def connect(self, service):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        host = service['host']  # The service's hostname or IP address
        port = service['port']  # The service's port number

        client_socket.connect((host, port))
        self.socket = client_socket

        # Generating Diffie-Hellman keys and getting the public key fingerprint
        dh_keys = self.kg.generate_dh_keysgenerate_dh_keys()
        self.dh = dh_keys['private_key']
        fingerprint = self.kg.get_public_key_fingerprint(dh_keys['public_key'])

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

        # Sending the key exchange message
        client_socket.sendall(json.dumps(key_exchange_message).encode('utf-8'))

        # Listen for a response to complete the key exchange process
        response_data = client_socket.recv(4096)
        response = json.loads(response_data.decode('utf-8'))
        if response['action'] == 'keyExchangeResponse':
            print(f"Received Fingerprint: {response['fingerprint']}")
            # COMPLETE THE EXCHANGE PROCESS
            # Derive the AES key using the received DH public key

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

        # Prepare the message with a timestamp
        message_with_timestamp = {
            'content': message_content,
            'timestamp': int(time.time() * 1000)  # Current time in milliseconds
        }

        # Encrypt the message
        encrypted_message = encrypt_message(message_with_timestamp, self.aes_key)

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
        self.kg.regenerate_and_save_keys()
        
        # Load the new public key
        new_public_key_pem = self.kg.load_public_key().public_bytes(
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

    def braodcast(self, new_key):
        message = {
            'action': 'keyUpdate',
            'newPublicKey': new_key.decode('utf-8')  # Assuming the key is in bytes, decode to string
        }
        
        # Convert the message to a JSON string and encode it for transmission
        encoded_message = json.dumps(message).encode('utf-8')
        
        # Iterate over all connected clients and send them the new public key
        for client_socket in self.clients:
            try:
                client_socket.sendall(encoded_message)
                print('Broadcasted new public key to a connected client.')
            except Exception as e:
                print(f'Error broadcasting new public key to a client: {e}')

def main():
    dsc = discovery()
    dsc.publish()


if __name__ == "__main__":
    main()