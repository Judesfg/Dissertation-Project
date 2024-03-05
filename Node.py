"""
////////////////////////////////////////////////////////////////////////////////////////
This is the Node superclass for my dissertation project. This creates a template for the
server and client subclasses to be built from.
Much of this code is based on the datacamp socket tutorial: https://www.datacamp.com/tutorial/a-complete-guide-to-socket-programming-in-python

Dissertation Title: An Analysis Of Post-Quantum Cryptographic Schemes For Real World Use
Author: Jude Gibson
Supervisor: Bhagya Wimalasiri
Date Created: 13/02/2024
////////////////////////////////////////////////////////////////////////////////////////
"""

import socket
from Protocol import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

class Node():
    def __init__(self) -> None:
        """Initialises an instance of the Node class."""
        self.protocol = Protocol()
        self.ip = "127.0.0.1"
        self.handshakePort = 8282
        self.port = 8000
        self.symmetricKey = None
        self.peerPublicKey = None
        self.publicKeySize = 384
        self.generate_asymmetric_keys()

    def set_symmetric_key(self, key):
        """Setter method for symmetricKey."""
        self.symmetricKey = key

    def set_asymmetric_keys(self, sk, pk):
        """Setter method for privateKey and publicKey."""
        self.privateKey = sk
        self.publicKey = pk

    def set_peer_public_key(self, key):
        """Setter method for peerPublicKey."""
        self.peerPublicKey = key

    def get_symmetric_key(self):
        """Returns the variable symmetricKey."""
        return self.symmetricKey

    def get_private_key(self):
        """Returns the variable privateKey."""
        return self.privateKey
    
    def get_public_key(self):
        """Returns the variable publicKey."""
        return self.publicKey
    
    def get_peer_public_key(self):
        """Returns the variable peerPublicKey."""
        return self.peerPublicKey
    
    def generate_symmetric_key(self):
        """Derives a shared key with a peer, using the privateKey and publicKey instance 
        variables."""
        shared_key = self.privateKey.exchange(ec.ECDH(), self.get_peer_public_key())#Performs elliptic curve diffie-hellman (ECDH) using the peer public key and own private key
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(shared_key)#Uses a key derivation function (HKDF) to generate the final shared key
        self.set_symmetric_key(derived_key)#Sets the derived key as an instance variable
        print(f"Symmetric key successfully derived...\nKey: {derived_key}")

    def generate_asymmetric_keys(self):
        """Randomly generates a private key using diffie-hellman and derives its 
        corresponding public key."""
        privateKey = ec.generate_private_key(ec.SECP384R1())#Uses ECDH to generate a private key 384 bytes in size
        publicKey = privateKey.public_key()#Derives the corresponding public key
        self.set_asymmetric_keys(privateKey, publicKey)#Sets both the public and privates keys as instance variables
        print("Key pair successfully generated.")

    def recvall(self, size):
        result = b''
        remaining = size
        while remaining > 0:
            data = self.socket.recv(remaining)
            result += data
            remaining -= len(data)
        return result