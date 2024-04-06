from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import json
import base64
from datetime import datetime, timedelta

def encrypt_with_public_key(public_key_pem, data):
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        encrypted = public_key.encrypt(
            data.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()
    except Exception as error:
        print(f'Encryption with public key failed: {error}')
        return None

def decrypt_with_private_key(private_key_pem, encrypted_data):
    try:
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        decrypted = private_key.decrypt(
            base64.b64decode(encrypted_data),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()
    except Exception as error:
        print(f'Decryption with private key failed: {error}')
        return None

def encrypt_message(message, aes_key):
    try:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        return {'iv': iv.hex(), 'content': encrypted.hex()}
    except Exception as error:
        print(f'Message encryption failed: {error}')
        return None

def decrypt_message(encrypted_message, aes_key):
    try:
        iv = bytes.fromhex(encrypted_message['iv'])
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(bytes.fromhex(encrypted_message['content'])) + decryptor.finalize()
        decrypted_message = json.loads(decrypted.decode('utf-8'))
        content, timestamp = decrypted_message['content'], decrypted_message['timestamp']
        if datetime.now() - datetime.fromtimestamp(timestamp / 1000) > timedelta(minutes=5):
            print('Message timestamp is outside the acceptable range. Possible replay attack.')
            return None
        return content
    except Exception as error:
        print(f'Decryption error: {error}')
        return None
