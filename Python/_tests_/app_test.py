import unittest
from unittest.mock import patch
import discovery
import keygen

class TestAppFunctionality(unittest.TestCase):
    @patch('secureStorage.generateAndSaveKey')
    @patch('keygen.generateAndSaveKeys')
    @patch('discovery.publishService')
    @patch('discovery.discoverServices')
    @patch('discovery.sendMessage')
    @patch('discovery.notifyKeyUpdate')
    def test_should_call_generateAndSaveKeys(self, mock_notifyKeyUpdate, mock_sendMessage, 
                                             mock_discoverServices, mock_publishService, 
                                             mock_generateAndSaveKeys):
        
        mock_generateAndSaveKeys.return_value = True
        keygen.generateAndSaveKeys()
        mock_generateAndSaveKeys.assert_called_once()

        discovery.sendMessage("Test message")
        mock_sendMessage.assert_called_once_with("Test message")
        
        discovery.notifyKeyUpdate()
        mock_notifyKeyUpdate.assert_called_once()

        # Simulate discovery services
        discovery.discoverServices()
        mock_discoverServices.assert_called_once()
        discovery.publishService()
        mock_publishService.assert_called_once()

if __name__ == '__main__':
    unittest.main()
