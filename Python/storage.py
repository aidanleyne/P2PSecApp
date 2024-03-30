from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os

class SecureStorage:
    def __init__(self):
        self.algo = 'aes-256-cbc'
        self.path = os.path.join(os.path.dirname(__file__), 'encryptionKey.bin')

    def generate_and_save_key(self):
        try:
            if not os.path.exists(self.path):
                key = os.urandom(32)
                with open(self.path, 'wb') as key_file:
                    key_file.write(key)
                print('Encryption key generated and saved.')
        except Exception as error:
            print(f'Failed to generate or save encryption key: {error}')

    def load_key(self):
        try:
            with open(self.path, 'rb') as key_file:
                return key_file.read()
        except Exception as error:
            print(f'Failed to load encryption key: {error}')
            raise error  # Rethrow to handle upstream

    def encrypt_data(self, data):
        try:
            key = self.load_key()
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
            return {'iv': iv.hex(), 'encrypted': encrypted.hex()}
        except Exception as error:
            print(f'Encryption failed: {error}')
            raise error  # Rethrow to handle upstream

    def decrypt_data(self, encrypted_object):
        try:
            key = self.load_key()
            iv = bytes.fromhex(encrypted_object['iv'])
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(bytes.fromhex(encrypted_object['encrypted'])) + decryptor.finalize()
            return decrypted.decode('utf-8')
        except Exception as error:
            print(f'Decryption failed: {error}')
            raise error  # Rethrow to handle upstream
