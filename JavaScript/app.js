const readline = require('readline');
const fs = require('fs'); // Add this to read files
const { generateAndSaveKeys } = require('./keygen');
const { publishService, discoverServices, sendMessage } = require('./discovery');

function init() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    function mainMenu() {
        rl.question('Choose an action (generate-keys, publish, discover, exit): ', action => {
            switch (action) {
                case 'generate-keys':
                    generateAndSaveKeys();
                    console.log('Keys generated successfully.');
                    mainMenu(); // Return to main menu after action
                    break;
                case 'publish':
                    publishService();
                    console.log('Publish service started. You can now receive messages.');
                    waitForCommand(); // Enter command mode
                    break;
                case 'discover':
                    discoverServices();
                    console.log('Discovery started. You can now send messages.');
                    waitForCommand(); // Enter command mode
                    break;
                case 'exit':
                    console.log('Exiting application...');
                    rl.close();
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
                if (message) {
                    sendMessage(message); // Sends the encrypted message
                    console.log('Message sent.');
                } else {
                    console.log('No message provided.');
                }
                waitForCommand(); // Wait for the next command
            } else if (command.startsWith('send-file')) {
                const filePath = command.slice('send-file'.length).trim();
                if (fs.existsSync(filePath)) {
                    sendMessage(filePath, true); // Indicates this is a file
                    console.log('File sent.');
                } else {
                    console.log('File does not exist. Please check the path and try again.');
                }
                waitForCommand(); // Wait for the next command
            } else if (command === 'back') {
                mainMenu(); // Return to the main menu
            } else {
                console.log('Unknown command. Use "send-message <message>", "send-file <file-path>" to send or "back" to return to the main menu.');
                waitForCommand(); // Repeat for a valid command
            }
        });
    }

    mainMenu(); // Start the app with the main menu
}

init();
