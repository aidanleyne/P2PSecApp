const bonjour = require('bonjour')();
const fs = require('fs');
const net = require('net');
const crypto = require('crypto');
const path = require('path');
const {encryptMessage, decryptMessage } = require('./messaging');
const { loadPublicKey, generateDHKeys, getPublicKeyFingerprint, regenerateAndSaveKeys } = require('./keygen');
const { encryptData } = require('./secureStorage');

let session = { dh: null, aesKey: null, socket: null, publicKeyFingerprint: null };
let connectedClients = [];

function publishService() {
    const server = net.createServer(socket => {
        connectedClients.push(socket);
        socket.on('data', data => {
            let message;
            try { message = JSON.parse(data.toString()); }
            catch (error) { console.error('Failed to parse incoming message:', error); return; }

            if (message.action === 'keyExchange') handleKeyExchange(message, socket);
            else if (message.action === 'sendMessage') handleMessageReception(message);
        });
        socket.on('close', () => { connectedClients = connectedClients.filter(client => client !== socket); });
    });
    server.listen(3000, () => console.log('Service published and awaiting connections...'));
    bonjour.publish({ name: 'SecureMsgService', type: 'http', port: 3000 });
}

function handleKeyExchange(message, socket) {
    try {
        const { publicKey, dh } = generateDHKeys();
        session.dh = dh;
        const fingerprint = getPublicKeyFingerprint();
        console.log(`DH Public Key: ${publicKey.toString('hex')}, Fingerprint: ${fingerprint}`);
        const receivedPublicKey = Buffer.from(message.dhPublicKey, 'hex');
        session.aesKey = crypto.createHash('sha256').update(dh.computeSecret(receivedPublicKey)).digest();
        socket.write(JSON.stringify({ action: 'keyExchangeResponse', dhPublicKey: publicKey.toString('hex'), fingerprint }));
    } catch (error) { console.error('Failed in key exchange process:', error); }
}

function handleMessageReception(message) {
    if (!session.aesKey) { console.error('AES key is not set. Unable to decrypt message.'); return; }
    try {
        const encryptedData = JSON.parse(message.message);
        const decryptedMessage = decryptMessage(encryptedData, session.aesKey);
        // Secure storage
        const storagePath = path.join(__dirname, 'messages.json');
        fs.appendFileSync(storagePath, JSON.stringify(encryptData(decryptedMessage)) + '\n');
        console.log('Decrypted Message:', decryptedMessage);
    } catch (error) { console.error('Error during message reception:', error); }
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

function notifyKeyUpdate() {
    regenerateAndSaveKeys(); 
    const newPublicKey = loadPublicKey(); 
    broadcastNewPublicKey(newPublicKey); 

    if (session.socket) {
        console.log('Notifying peers of new public key...');
        session.socket.write(JSON.stringify({
            action: 'keyUpdate',
            newPublicKey: newPublicKey
        }));
    } else {
        console.log('No active session. Unable to notify peers.');
    }
}

function broadcastNewPublicKey(newPublicKey) {
    const message = JSON.stringify({
        action: 'keyUpdate',
        newPublicKey: newPublicKey
    });
    connectedClients.forEach(client => {
        client.write(message);
    });
    console.log('Broadcasted new public key to all connected clients.');
}

module.exports = { publishService, discoverServices, sendMessage, notifyKeyUpdate };
