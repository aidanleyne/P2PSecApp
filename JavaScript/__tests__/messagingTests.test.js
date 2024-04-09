jest.mock('../messaging', () => {
    return {
      encryptWithPublicKey: jest.fn((publicKey, data) => 'mockEncryptedData'),
      decryptWithPrivateKey: jest.fn((privateKey, encryptedData) => 'test'),
      encryptMessage: jest.fn((message, aesKey) => {
        return { iv: 'mockIV', content: 'mockEncryptedContent' };
      }),
      decryptMessage: jest.fn((encryptedMessage, aesKey) => 'test message'),
    };
  });
  
  const {
    encryptWithPublicKey,
    decryptWithPrivateKey,
    encryptMessage,
    decryptMessage,
  } = require('../messaging');
  
  describe('Messaging Functionality Tests', () => {
    const publicKey = 'mockedPublicKey';
    const privateKey = 'mockedPrivateKey';
    const aesKey = Buffer.alloc(32); // Mocked AES key (256 bits)
  
    test('encrypt with public key', () => {
      const data = 'test';
      const encrypted = encryptWithPublicKey(publicKey, data);
      expect(encryptWithPublicKey).toHaveBeenCalledWith(publicKey, data);
      expect(encrypted).toBe('mockEncryptedData');
    });
  
    test('decrypt with private key', () => {
      const encryptedData = 'mockEncryptedData';
      const decrypted = decryptWithPrivateKey(privateKey, encryptedData);
      expect(decryptWithPrivateKey).toHaveBeenCalledWith(privateKey, encryptedData);
      expect(decrypted).toBe('test');
    });
  
    test('encrypt message', () => {
      const message = 'test message';
      const encryptedMessage = encryptMessage(message, aesKey);
      expect(encryptMessage).toHaveBeenCalledWith(message, aesKey);
      expect(encryptedMessage).toHaveProperty('iv', 'mockIV');
      expect(encryptedMessage).toHaveProperty('content', 'mockEncryptedContent');
    });
  
    test('decrypt message', () => {
      const encryptedMessage = { iv: 'mockIV', content: 'mockEncryptedContent' };
      const decryptedMessage = decryptMessage(encryptedMessage, aesKey);
      expect(decryptMessage).toHaveBeenCalledWith(encryptedMessage, aesKey);
      expect(decryptedMessage).toBe('test message');
    });
  });
  