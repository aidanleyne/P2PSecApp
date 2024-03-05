const crypto = require('crypto');

// Function to encrypt data with the recipient's public key (RSA)
function encryptWithPublicKey(publicKey, data) {
    return crypto.publicEncrypt(publicKey, Buffer.from(data)).toString('base64');
}

// Function to decrypt data with the private key (RSA)
function decryptWithPrivateKey(privateKey, encryptedData) {
    return crypto.privateDecrypt(privateKey, Buffer.from(encryptedData, 'base64')).toString();
}

// Function to encrypt messages using AES
function encryptMessage(message, aesKey) {
    const iv = crypto.randomBytes(16); // AES block size for IV
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(aesKey, 'hex'), iv);
    let encrypted = cipher.update(message, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { iv: iv.toString('hex'), content: encrypted };
}

// Function to decrypt messages using AES
function decryptMessage(encryptedMessage, aesKey) {
    const iv = Buffer.from(encryptedMessage.iv, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(aesKey, 'hex'), iv);
    let decrypted = decipher.update(encryptedMessage.content, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

module.exports = { encryptWithPublicKey, decryptWithPrivateKey, encryptMessage, decryptMessage };
