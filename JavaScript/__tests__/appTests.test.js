const { publishService, discoverServices, sendMessage, notifyKeyUpdate } = require('../discovery');
const { generateAndSaveKeys } = require('../keygen');
const { generateAndSaveKey } = require('../secureStorage');

jest.mock('../secureStorage', () => ({
  generateAndSaveKey: jest.fn(),
}));

jest.mock('../keygen', () => ({
  generateAndSaveKeys: jest.fn().mockImplementation(() => {
    return true;
  }),
}));

jest.mock('../discovery', () => ({
  publishService: jest.fn().mockImplementation(() => {
  }),
  discoverServices: jest.fn().mockImplementation(() => {
  }),
  sendMessage: jest.fn().mockImplementation((message) => {
    console.log(`Mock send message: ${message}`);
  }),
  notifyKeyUpdate: jest.fn().mockImplementation(() => {
  }),
}));

describe('App Functionality Tests', () => {
  test('should call generateAndSaveKeys', () => {
    generateAndSaveKeys();
    expect(generateAndSaveKeys).toHaveBeenCalled();
  });
});
