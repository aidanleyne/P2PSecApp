# P2PSecApp
A P2P Secure Communication Application for W24 CISC 468.

## Members:
1. Aidan Leyne
2. Sean Liang


## Languages Chosen: 
1. Python
2. JavaSvcript

## About the project:
- Each user has a 2048-bit RSA key-pair for encyption and decryption
  - DHKE is used for initial key exhcnage
- With the RSA protocol, we can ensure that any changes to the ciphertext by an attacker, result in an obvious nonsense message to the reciever
  - Messages are encrypted and passed as ASCII ciphertext within JSON
- We allow for a peer discovery when on the same network
  - Once peers are connected, they are able to store one-another's information
  - Connected peers can also update their keys if needed
- Messages can be stored after they are recieved
  - It should be noted that messages are stored in ciphertext to ensure confidentiality and integrity
- Messages are not limited to plaintext. Various file-types can also be sent
  - For this, we convert the file to hexadecimal before encryption
- 
