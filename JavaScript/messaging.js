const crypto = require('crypto');

function encryptWithPublicKey(publicKey, data) {
    try {
        return crypto.publicEncrypt(publicKey, Buffer.from(data)).toString('base64');
    } catch (error) {
        console.error('Encryption with public key failed:', error);
        return null; 
    }
}

function decryptWithPrivateKey(privateKey, encryptedData) {
    try {
        return crypto.privateDecrypt(privateKey, Buffer.from(encryptedData, 'base64')).toString();
    } catch (error) {
        console.error('Decryption with private key failed:', error);
        return null;
    }
}

function encryptMessage(message, aesKey) {
    try {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
        let encrypted = cipher.update(message, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return { iv: iv.toString('hex'), content: encrypted };
    } catch (error) {
        console.error('Message encryption failed:', error);
        return null;
    }
}

function decryptMessage(encryptedMessage, aesKey) {
    try {
        const iv = Buffer.from(encryptedMessage.iv, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
        let decrypted = decipher.update(encryptedMessage.content, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        const { content, timestamp } = JSON.parse(decrypted);
        const currentTime = new Date().getTime();
        if (currentTime - timestamp > 5 * 60 * 1000) {
            console.error('Message timestamp is outside the acceptable range. Possible replay attack.');
            return null; 
        }
        return content;
    } catch (error) {
        console.error('Decryption error:', error);
        return null; 
    }
}

module.exports = { encryptWithPublicKey, decryptWithPrivateKey, encryptMessage, decryptMessage };
