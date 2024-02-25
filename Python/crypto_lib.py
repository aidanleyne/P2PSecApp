import rsa

"""
Cryto implementation for the project using RSA
"""
class crypto:
    def __init__(self):
        return
    
    """
    Generates user's privatr and public key using
    Requires: None
        Optional: len - legth of key, passwd - password as key seed
    Returns: pub - public key (hex), priv - private key (hex)
    """
    def key_gen(self, len=2048, passwd=''):
        return rsa.newkeys(len)
    
    """
    Creates ciphertext using RSA protocol
    Requires: msg - plaintext (str), key - (hex)
    Returns: ciphertext (str)
    """
    def encrypt(self, msg, key):
        return rsa.encrypt(msg.encode('utf8'), key).hex()
    
    """
    Decrypts and checks message using RSA protocol
    Requires: ctext - ciphertext (str)
    Returns: msg - plaintext (str)
    """
    def decrypt(self, ctext, key):
        return rsa.decrypt(bytes.fromhex(ctext), key).decode('utf8')
    

def main():
    c = crypto()
    (pub, priv) = c.key_gen()
    message = 'Hello World!'
    ciphertext = c.encrypt(message, pub)
    print('ciphertext :', ciphertext)
    plaintext = c.decrypt(ciphertext, priv)
    print('decrypted plaintext:', plaintext)
    return

if __name__ == "__main__":
    main()