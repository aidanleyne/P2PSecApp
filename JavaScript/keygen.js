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

    // Save keys to files in the same directory as this script
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

module.exports = { generateAndSaveKeys, loadPublicKey, loadPrivateKey, generateAESKey };

