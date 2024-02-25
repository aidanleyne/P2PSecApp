import datetime
from crypto_lib import crypto
import json

"""
Class for creating messages to be sent over the network
"""
class Message:
    def __init__(self, to='', frm=''):
        self.timestamp = datetime.datetime.now()
        self.reciever = to
        self.sender = frm

    """
    Prepares the plaintext message for the communication
    Requires: ms - plaintext (str)
    Returns: N/A
    """
    def set_message(self, msg, key):
        self.message = crypto.encrypt(str(len(msg) + ':' +  msg), key)

    """
    Creates the message (json) using specified data
    Require: N/A
    Returns: json
    """
    def make_message(self):
        #makes the message with appropriate headers in json format
        return
