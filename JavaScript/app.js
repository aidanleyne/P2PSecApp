const readline = require('readline');
const fs = require('fs');
const path = require('path');
const { generateAndSaveKeys } = require('./keygen');
const { publishService, discoverServices, sendMessage, notifyKeyUpdate } = require('./discovery');
const { generateAndSaveKey } = require('./secureStorage');

// Ensure the encryption key is generated on application start
generateAndSaveKey();

function init() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    function mainMenu() {
        rl.question('Choose an action (generate-keys, publish, discover, regenerate-keys, exit): ', action => {
            switch (action) {
                case 'generate-keys':
                    try {
                        generateAndSaveKeys();
                        console.log('Keys generated successfully.');
                    } catch (error) {
                        console.error('Failed to generate keys:', error);
                    }
                    mainMenu(); // Return to main menu after action
                    break;
                case 'publish':
                    try {
                        publishService();
                        console.log('Publish service started. You can now receive messages.');
                    } catch (error) {
                        console.error('Failed to publish service:', error);
                    }
                    waitForCommand(); // Enter command mode
                    break;
                case 'discover':
                    try {
                        discoverServices();
                        console.log('Discovery started. You can now send messages.');
                    } catch (error) {
                        console.error('Failed to discover services:', error);
                    }
                    waitForCommand(); // Enter command mode
                    break;
                case 'regenerate-keys':
                    try {
                        notifyKeyUpdate();
                        console.log('Key regeneration initiated.');
                    } catch (error) {
                        console.error('Failed to regenerate keys:', error);
                    }
                    mainMenu(); // Return to the main menu after action
                    break;
                case 'exit':
                    console.log('Exiting application...');
                    rl.close();
                    process.exit(0); 
                    break;
                default:
                    console.log('Invalid option. Please try again.');
                    mainMenu(); // Return to main menu for valid option
                    break;
            }
        });
    }

    function waitForCommand() {
        rl.question('Enter command (send-message <message>, send-file <file-path>, or back): ', command => {
            if (command.startsWith('send-message')) {
                const message = command.slice('send-message'.length).trim();
                sendMessage(message);
                console.log('Message sent.');
                waitForCommand(); // Wait for the next command
            } else if (command.startsWith('send-file')) {
                const filePath = command.slice('send-file'.length).trim();
                if (filePath && fs.existsSync(filePath)) {
                    sendMessage(filePath, true);
                    console.log('File sent.');
                } else {
                    console.log('File does not exist or path is incorrect. Please check and try again.');
                }
                waitForCommand(); // Wait for the next command
            } else if (command === 'back') {
                mainMenu(); // Return to the main menu
            } else {
                console.log('Unknown command. Please use "send-message <message>", "send-file <file-path>", or "back".');
                waitForCommand(); // Repeat for a valid command
            }
        });
    }

    mainMenu(); // Start the app with the main menu
}

init();
