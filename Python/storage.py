from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

algo = 'aes-256-cbc'
PATH = os.path.join(os.path.dirname(__file__), 'encryptionKey.bin')

def generate_and_save_keys():
    try:
        if not os.path.exists(PATH):
            key = os.urandom(32)
            with open(PATH, 'wb') as key_file:
                key_file.write(key)
            print('Encryption key generated and saved.')
    except Exception as error:
        print(f'Failed to generate or save encryption key: {error}')

def load_key():
    try:
        with open(PATH, 'rb') as key_file:
            return key_file.read()
    except Exception as error:
        print(f'Failed to load encryption key: {error}')
        raise error  # Rethrow to handle upstream

def encrypt_data(data):
    try:
        key = load_key()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
        return {'iv': iv.hex(), 'encrypted': encrypted.hex()}
    except Exception as error:
        print(f'Encryption failed: {error}')
        raise error  # Rethrow to handle upstream

def decrypt_data(encrypted_object):
    try:
        key = load_key()
        iv = bytes.fromhex(encrypted_object['iv'])
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(bytes.fromhex(encrypted_object['encrypted'])) + decryptor.finalize()
        return decrypted.decode('utf-8')
    except Exception as error:
        print(f'Decryption failed: {error}')
        raise error  # Rethrow to handle upstream
