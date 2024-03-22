const bonjour = require('bonjour')();
const fs = require('fs');
const net = require('net');
const crypto = require('crypto');
const { encryptWithPublicKey, decryptWithPrivateKey, encryptMessage, decryptMessage } = require('./messaging');
const { loadPublicKey, loadPrivateKey, generateDHKeys } = require('./keygen');

let session = {
    dh: null,
    aesKey: null,
    socket: null
};

function publishService() {
    const server = net.createServer(socket => {
        socket.on('data', data => {
            const message = JSON.parse(data.toString());
            if (message.action === 'keyExchange') {
                console.log('Received key exchange request...');
                const { publicKey, dh } = generateDHKeys();
                session.dh = dh;
                console.log(`Sending DH Public Key: ${publicKey.toString('hex')}`);
                socket.write(JSON.stringify({ action: 'keyExchangeResponse', dhPublicKey: publicKey.toString('hex') }));

                const receivedPublicKey = Buffer.from(message.dhPublicKey, 'hex');
                const sharedSecret = session.dh.computeSecret(receivedPublicKey);
                session.aesKey = crypto.createHash('sha256').update(sharedSecret).digest();
            } else if (message.action === 'sendMessage') {
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
                    console.error('Error decrypting message:', error);
                }
            }
        });
    });

    server.listen(3000, () => console.log('Service published and awaiting connections...'));
    bonjour.publish({ name: 'SecureMsgService', type: 'http', port: 3000 });
}

function discoverServices() {
    const browser = bonjour.find({ type: 'http' }); 
    browser.on('up', service => {
        // Check if the discovered service is our messaging service
        if (service.name === 'SecureMsgService') { 
            console.log('Found messaging service:', service.name);

            const client = new net.Socket();
            client.connect(service.port, service.host, () => {
                console.log('Connected to messaging service, initiating key exchange...');
                const { publicKey, dh } = generateDHKeys();
                session.dh = dh;
                console.log(`Sending DH Public Key: ${publicKey.toString('hex')}`);
                client.write(JSON.stringify({ action: 'keyExchange', dhPublicKey: publicKey.toString('hex') }));
            });

            client.on('data', data => {
                const message = JSON.parse(data.toString());
                if (message.action === 'keyExchangeResponse') {
                    const receivedPublicKey = Buffer.from(message.dhPublicKey, 'hex');
                    const sharedSecret = session.dh.computeSecret(receivedPublicKey);
                    session.aesKey = crypto.createHash('sha256').update(sharedSecret).digest();
                    console.log('Secure channel established with messaging service.');
                    session.socket = client;
                }
            });
        } else {
            console.log('Discovered non-messaging service:', service.name);
        }
    });
}


// In discovery.js
function sendMessage(message, isFile = false) {
    if (session.socket && session.aesKey) {
        console.log(isFile ? 'Sending file...' : 'Sending message...');
        let encryptedMessage = {};
        if (isFile) {
            // Placeholder for file encryption logic
            const fileContent = fs.readFileSync(message, 'utf8'); // This is a simplification; binary files require different handling
            encryptedMessage = encryptMessage(fileContent, session.aesKey);
        } else {
            encryptedMessage = encryptMessage(message, session.aesKey);
        }
        session.socket.write(JSON.stringify({ action: 'sendMessage', message: JSON.stringify(encryptedMessage), isFile }));
    } else {
        console.log('No active session for sending messages.');
    }
}


module.exports = { publishService, discoverServices, sendMessage };
