from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os

def generate_dh_parameters():
    return dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

def generate_dh_keys(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_aes_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(peer_public_key)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)
    return aes_key

parameters = generate_dh_parameters()

# Simulate server
server_private_key, server_public_key = generate_dh_keys(parameters)

# Simulate client
client_private_key, client_public_key = generate_dh_keys(parameters)

# Derive AES key on server side using server's private key and client's public key
server_aes_key = derive_aes_key(server_private_key, client_public_key)

# Derive AES key on client side using client's private key and server's public key
client_aes_key = derive_aes_key(client_private_key, server_public_key)

print("Server AES Key:", server_aes_key.hex())
print("Client AES Key:", client_aes_key.hex())
if server_aes_key == client_aes_key:
    print("Success: The AES keys match.")
else:
    print("Error: The AES keys do not match.")

