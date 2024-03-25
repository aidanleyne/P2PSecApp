const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Function to generate RSA key pair and save to files
function generateAndSaveKeys() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,  // Standard key size for RSA
    });

    // Convert keys to PEM format (string)
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });

    fs.writeFileSync(path.join(__dirname, 'publicKey.pem'), publicKeyPem);
    fs.writeFileSync(path.join(__dirname, 'privateKey.pem'), privateKeyPem);

    console.log('RSA key pair generated and saved.');
}

// Function to load the public key from file
function loadPublicKey() {
    try {
        return fs.readFileSync(path.join(__dirname, 'publicKey.pem'), { encoding: 'utf8' });
    } catch (error) {
        console.error('Error loading the public key:', error.message);
        return null;
    }
}

// Function to load the private key from file
function loadPrivateKey() {
    try {
        return fs.readFileSync(path.join(__dirname, 'privateKey.pem'), { encoding: 'utf8' });
    } catch (error) {
        console.error('Error loading the private key:', error.message);
        return null;
    }
}

function generateAESKey() {
  return crypto.randomBytes(32); // AES-256 key
}

function generateDHKeys() {
    const dh = crypto.createDiffieHellmanGroup('modp14');
    const publicKey = dh.generateKeys();
    const privateKey = dh.getPrivateKey();

    return { publicKey, privateKey, dh };
}

function getPublicKeyFingerprint() {
    try {
        const publicKey = loadPublicKey();
        const hash = crypto.createHash('sha256').update(publicKey).digest('hex');
        return hash; // Returns the fingerprint
    } catch (error) {
        console.error('Error generating public key fingerprint:', error);
        return null;
    }
}

// Function to regenerate and save new keys
function regenerateAndSaveKeys() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    fs.writeFileSync(path.join(__dirname, 'publicKey.pem'), publicKeyPem);
    fs.writeFileSync(path.join(__dirname, 'privateKey.pem'), privateKeyPem);
    console.log('New RSA key pair generated and saved.');
}

module.exports = { generateAndSaveKeys, loadPublicKey, loadPrivateKey, generateAESKey, generateDHKeys, getPublicKeyFingerprint, regenerateAndSaveKeys};

