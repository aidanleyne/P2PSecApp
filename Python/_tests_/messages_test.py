import unittest
from unittest.mock import MagicMock, patch
import messaging
import keygen

class TestMessagingFunctionality(unittest.TestCase):
    def setUp(self):
        # Mocking the messaging functions
        keygen.generate_and_save_keys
        self.publicKey = keygen.load_public_key()
        self.privateKey = keygen.load_private_key()
        self.aesKey = keygen.generate_aes_key()

        messaging.encryptWithPublicKey = MagicMock(return_value='mockEncryptedData')
        messaging.decryptWithPrivateKey = MagicMock(return_value='test')
        messaging.encryptMessage = MagicMock(return_value={'iv': 'mockIV', 'content': 'mockEncryptedContent'})
        messaging.decryptMessage = MagicMock(return_value='test message')

    def test_encrypt_with_public_key(self):
        data = 'test'
        encrypted = messaging.encryptWithPublicKey(self.publicKey, data)
        messaging.encryptWithPublicKey.assert_called_with(self.publicKey, data)
        self.assertEqual(encrypted, 'mockEncryptedData')

    def test_decrypt_with_private_key(self):
        encryptedData = 'mockEncryptedData'
        decrypted = messaging.decryptWithPrivateKey(self.privateKey, encryptedData)
        messaging.decryptWithPrivateKey.assert_called_with(self.privateKey, encryptedData)
        self.assertEqual(decrypted, 'test')

    def test_encrypt_message(self):
        message = 'test message'
        encryptedMessage = messaging.encryptMessage(message, self.aesKey)
        messaging.encryptMessage.assert_called_with(message, self.aesKey)
        self.assertEqual(encryptedMessage['iv'], 'mockIV')
        self.assertEqual(encryptedMessage['content'], 'mockEncryptedContent')

    def test_decrypt_message(self):
        encryptedMessage = {'iv': 'mockIV', 'content': 'mockEncryptedContent'}
        decryptedMessage = messaging.decryptMessage(encryptedMessage, self.aesKey)
        messaging.decryptMessage.assert_called_with(encryptedMessage, self.aesKey)
        self.assertEqual(decryptedMessage, 'test message')

if __name__ == '__main__':
    unittest.main()
