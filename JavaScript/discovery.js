const bonjour = require('bonjour')();
const net = require('net');
const fs = require('fs');
const path = require('path');
const { encryptWithPublicKey, decryptWithPrivateKey } = require('./messaging');
const { generateAESKey } = require('./keygen'); // Ensure this function exists in keygen.js

// Load keys from files
function loadPublicKey() {
    return fs.readFileSync(path.join(__dirname, 'publicKey.pem'), { encoding: 'utf8' });
}

function loadPrivateKey() {
    return fs.readFileSync(path.join(__dirname, 'privateKey.pem'), { encoding: 'utf8' });
}

// Function to publish a simple service and handle incoming connections for key exchange
function publishService() {
    const server = net.createServer(socket => {
        socket.on('data', data => {
            const message = JSON.parse(data.toString());
            if (message.action === 'keyExchange') {
                console.log('Received key exchange request...');
                // Respond with public key and encrypted AES key
                const myPublicKey = loadPublicKey();
                const aesKey = generateAESKey().toString('hex'); // Generate a new AES key for this session
                const encryptedAESKey = encryptWithPublicKey(message.publicKey, aesKey); // Encrypt AES key with peer's public key
                socket.write(JSON.stringify({ action: 'keyExchangeResponse', publicKey: myPublicKey, aesKey: encryptedAESKey }));
            }
        });
    });

    server.listen(3000, () => {
        console.log('Service published and awaiting connections...');
    });

    bonjour.publish({
        name: 'SecureMsgService',
        type: 'http',
        port: 3000
    });
    console.log('Bonjour service published');
}

// Function to discover services and initiate key exchange
function discoverServices() {
    const browser = bonjour.find({ type: 'http' });

    browser.on('up', service => {
        console.log('Found service:', service.name);

        const client = new net.Socket();
        client.connect(service.port, service.host, () => {
            console.log('Connected to service, initiating key exchange...');
            const myPublicKey = loadPublicKey();
            // Send public key to initiate exchange
            client.write(JSON.stringify({ action: 'keyExchange', publicKey: myPublicKey }));
        });

        client.on('data', data => {
            const message = JSON.parse(data.toString());
            if (message.action === 'keyExchangeResponse') {
                console.log('Received key exchange response...');
                // Decrypt received AES key with private key
                const myPrivateKey = loadPrivateKey();
                const decryptedAESKey = decryptWithPrivateKey(myPrivateKey, message.aesKey);
                console.log('Decrypted AES Key:', decryptedAESKey);
                // Store the decrypted AES key and public key of the peer for secure communication
            }
        });
    });
}

module.exports = { publishService, discoverServices };
