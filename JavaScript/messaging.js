const crypto = require('crypto');

// Function to encrypt data with the recipient's public key (RSA)
function encryptWithPublicKey(publicKey, data) {
    return crypto.publicEncrypt(publicKey, Buffer.from(data)).toString('base64');
}

// Function to decrypt data with the private key (RSA)
function decryptWithPrivateKey(privateKey, encryptedData) {
    return crypto.privateDecrypt(privateKey, Buffer.from(encryptedData, 'base64')).toString();
}

// Function to encrypt a message using AES
function encryptMessage(message, aesKey) {
    console.log(`Encrypting with AES Key Length: ${aesKey.length}`);
    console.log(`AES Key (initial bytes): ${aesKey.slice(0, 4).toString('hex')}`);
    
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
    let encrypted = cipher.update(message, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return { iv: iv.toString('hex'), content: encrypted };
}

// Function to decrypt a message using AES
function decryptMessage(encryptedMessage, aesKey) {
    console.log(`Decrypting with AES Key Length: ${aesKey.length}`);
    console.log(`AES Key (initial bytes): ${aesKey.slice(0, 4).toString('hex')}`);
    
    const iv = Buffer.from(encryptedMessage.iv, 'hex');
    try {
        const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
        let decrypted = decipher.update(encryptedMessage.content, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    } catch (error) {
        console.error('Decryption error:', error);
        throw error; 
    }
}

module.exports = { encryptWithPublicKey, decryptWithPrivateKey, encryptMessage, decryptMessage };
