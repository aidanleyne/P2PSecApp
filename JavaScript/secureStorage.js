const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const algorithm = 'aes-256-cbc';
const keyPath = path.join(__dirname, 'encryptionKey.bin');

function generateAndSaveKey() {
    try {
        if (!fs.existsSync(keyPath)) {
            const key = crypto.randomBytes(32);
            fs.writeFileSync(keyPath, key);
            console.log('Encryption key generated and saved.');
        }
    } catch (error) {
        console.error('Failed to generate or save encryption key:', error);
    }
}

function loadKey() {
    try {
        return fs.readFileSync(keyPath);
    } catch (error) {
        console.error('Failed to load encryption key:', error);
        throw error; // Rethrow to handle upstream
    }
}

function encryptData(data) {
    try {
        const key = loadKey();
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(algorithm, key, iv);

        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        return { iv: iv.toString('hex'), encrypted };
    } catch (error) {
        console.error('Encryption failed:', error);
        throw error; // Rethrow to handle upstream
    }
}

function decryptData(encryptedObject) {
    try {
        const key = loadKey();
        const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(encryptedObject.iv, 'hex'));

        let decrypted = decipher.update(encryptedObject.encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } catch (error) {
        console.error('Decryption failed:', error);
        throw error; // Rethrow to handle upstream
    }
}

module.exports = { generateAndSaveKey, encryptData, decryptData };
