# Jude Gibson - Dissertation Project

An Analysis of Post-Quantum Cryptographic Schemes for Real World Applications

## Running the Code
-To run the code, first run the file Server.py. Once the terminal reads 'Listening for keys on 127.0.0.1:8282.' you should run Client.py in a seperate terminal. This will cause the handshake to run.
-Once a shared key has been agreed upon, it will be displayed and the client terminal will ask for an input message. Type any message and press enter. The client will then encrypt the message and send it to the server where it will be decrypted. The original message will then be displayed in the server terminal. 
-To terminate the connection, simply type 'close' into the client terminal.

## Changing parameters
-You can change the encryption type by going into the file Node.py and changing the value of self.encryptionKeyType. This value should only ever be 'KYBER' or 'MCELIECE'.
-You can change the sifgnature type by going into the file Node.py and changing the value of self.signatureType. This value should only ever be 'DILITHIUM' or 'SPHINCS'
