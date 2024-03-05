const readline = require('readline');
const { generateAndSaveKeys } = require('./keygen'); // Assume this exists and matches the outline from previous steps
const { publishService, discoverServices } = require('./discovery');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.question('Choose an action (generate-keys, publish, discover): ', action => {
    switch (action) {
        case 'generate-keys':
            generateAndSaveKeys(); 
            break;
        case 'publish':
            publishService();
            break;
        case 'discover':
            discoverServices(); 
            break;
        default:
            console.log('Invalid option');
            break;
    }
    rl.close();
});
