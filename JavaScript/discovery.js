const bonjour = require('bonjour')();
const fs = require('fs');
const net = require('net');
const crypto = require('crypto');
const { encryptWithPublicKey, decryptWithPrivateKey, encryptMessage, decryptMessage } = require('./messaging');
const { loadPublicKey, loadPrivateKey, generateDHKeys, getPublicKeyFingerprint } = require('./keygen');

let session = {
    dh: null,
    aesKey: null,
    socket: null,
    publicKeyFingerprint: null,
};

function publishService() {
    const server = net.createServer(socket => {
        socket.on('data', data => {
            const message = JSON.parse(data.toString());
            switch (message.action) {
                case 'keyExchange':
                    handleKeyExchange(message, socket);
                    break;
                case 'sendMessage':
                    handleMessageReception(message);
                    break;
            }
        });
    });

    server.listen(3000, () => console.log('Service published and awaiting connections...'));
    bonjour.publish({ name: 'SecureMsgService', type: 'http', port: 3000 });
}

function handleKeyExchange(message, socket) {
    console.log('Received key exchange request...');
    const { publicKey, dh } = generateDHKeys();
    session.dh = dh;
    const fingerprint = getPublicKeyFingerprint(); 
    console.log(`Sending DH Public Key: ${publicKey.toString('hex')}`);
    console.log(`Sending Fingerprint: ${fingerprint}`);
    const receivedPublicKey = Buffer.from(message.dhPublicKey, 'hex');
    session.aesKey = crypto.createHash('sha256').update(session.dh.computeSecret(receivedPublicKey)).digest();

    socket.write(JSON.stringify({
        action: 'keyExchangeResponse',
        dhPublicKey: publicKey.toString('hex'),
        fingerprint: fingerprint,
    }));
}

function handleMessageReception(message) {
    if (!session.aesKey) {
        console.error('AES key is not set. Unable to decrypt message.');
        return;
    }
    console.log('Received secure message...');
    try {
        const encryptedData = JSON.parse(message.message);
        const decryptedMessage = decryptMessage(encryptedData, session.aesKey);
        console.log('Decrypted Message:', decryptedMessage);
    } catch (error) {
        console.error('Error handling incoming message:', error);
    }
}

function discoverServices() {
    const browser = bonjour.find({ type: 'http' });
    browser.on('up', service => {
        if (service.name !== 'SecureMsgService') {
            console.log('Discovered non-messaging service:', service.name);
            return;
        }
        console.log('Found messaging service:', service.name);
        connectToService(service);
    });
}

function connectToService(service) {
    const client = new net.Socket();
    session.socket = client; 

    client.connect(service.port, service.host, () => {
        console.log('Connected to messaging service, initiating key exchange...');
        const { publicKey, dh } = generateDHKeys();
        session.dh = dh;
        const fingerprint = getPublicKeyFingerprint();
        console.log(`Sending DH Public Key: ${publicKey.toString('hex')}`);
        console.log(`Sending Fingerprint: ${fingerprint}`);
        client.write(JSON.stringify({
            action: 'keyExchange',
            dhPublicKey: publicKey.toString('hex'),
            fingerprint: fingerprint,
        }));
    });

    client.on('data', data => {
        const message = JSON.parse(data.toString());
        if (message.action === 'keyExchangeResponse') {
            console.log(`Received Fingerprint: ${message.fingerprint}`);
            const receivedPublicKey = Buffer.from(message.dhPublicKey, 'hex');
            session.aesKey = crypto.createHash('sha256').update(session.dh.computeSecret(receivedPublicKey)).digest();
            console.log('Secure channel established with messaging service.');
        }
    });
}

function sendMessage(message, isFile = false) {
    if (session.socket && session.aesKey) {
        console.log(isFile ? 'Sending file...' : 'Sending message...');

        // Attach a timestamp to the message
        const messageWithTimestamp = {
            content: isFile ? fs.readFileSync(message, 'utf8') : message,
            timestamp: new Date().getTime() // Current time in milliseconds
        };
        const messageString = JSON.stringify(messageWithTimestamp);
        const encryptedMessage = encryptMessage(messageString, session.aesKey);

        session.socket.write(JSON.stringify({ action: 'sendMessage', message: JSON.stringify(encryptedMessage), isFile }));
    } else {
        console.log('No active session for sending messages.');
    }
}

module.exports = { publishService, discoverServices, sendMessage };
