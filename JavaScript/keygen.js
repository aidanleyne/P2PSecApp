const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function generateAndSaveKeys() {
    try {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        fs.writeFileSync(path.join(__dirname, 'publicKey.pem'), publicKey.export({ type: 'spki', format: 'pem' }));
        fs.writeFileSync(path.join(__dirname, 'privateKey.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }));
        console.log('RSA key pair generated and saved successfully.');
    } catch (error) {
        console.error('Failed to generate or save RSA key pair:', error);
    }
}

function loadPublicKey() {
    try {
        return fs.readFileSync(path.join(__dirname, 'publicKey.pem'), 'utf8');
    } catch (error) {
        console.error('Failed to load public key:', error);
        return null;
    }
}

function loadPrivateKey() {
    try {
        return fs.readFileSync(path.join(__dirname, 'privateKey.pem'), 'utf8');
    } catch (error) {
        console.error('Failed to load private key:', error);
        return null;
    }
}

function generateAESKey() {
    return crypto.randomBytes(32);
}

function generateDHKeys() {
    try {
        const dh = crypto.createDiffieHellmanGroup('modp14');
        return { publicKey: dh.generateKeys(), dh };
    } catch (error) {
        console.error('Failed to generate DH keys:', error);
        return null;
    }
}

function getPublicKeyFingerprint() {
    try {
        const publicKey = loadPublicKey();
        if (!publicKey) throw new Error('Public key is null.');
        return crypto.createHash('sha256').update(publicKey).digest('hex');
    } catch (error) {
        console.error('Failed to generate public key fingerprint:', error);
        return null;
    }
}

function regenerateAndSaveKeys() {
    try {
        generateAndSaveKeys();
        console.log('Keys have been regenerated and saved.');
    } catch (error) {
        console.error('Failed to regenerate keys:', error);
    }
}

module.exports = {
    generateAndSaveKeys,
    loadPublicKey,
    loadPrivateKey,
    generateAESKey,
    generateDHKeys,
    getPublicKeyFingerprint,
    regenerateAndSaveKeys
};
