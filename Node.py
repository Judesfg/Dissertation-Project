"""
////////////////////////////////////////////////////////////////////////////////////////
This is the Node superclass for my dissertation project. This creates a template for the
server and client subclasses to be built from.

Dissertation Title: An Analysis Of Post-Quantum Cryptographic Schemes For Real World Use
Author: Jude Gibson
Supervisor: Bhagya Wimalasiri
Date Created: 13/02/2024
////////////////////////////////////////////////////////////////////////////////////////
"""

from Protocol import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.pqcrypto.kem.kyber1024 import generate_keypair, encrypt, decrypt

class Node():
    def __init__(self) -> None:
        """Initialises an instance of the Node class."""
        self.protocol = Protocol()
        self.ip = "127.0.0.1"
        self.handshakePort = 8282
        self.port = 8000
        self.symmetricKey = None
        self.peerPublicKey = None
        self.cPublicKeySize = 384
        self.qPublicKeySize = 1024
        self.generate_asymmetric_keys()

    def set_symmetric_key(self, key):
        """Setter method for symmetricKey."""
        self.symmetricKey = key

    def set_classical_asymmetric_keys(self, sk, pk):
        """Setter method for cPrivateKey and cPublicKey."""
        self.cPrivateKey = sk
        self.cPublicKey = pk

    def set_quantum_asymmetric_keys(self, sk, pk):
        """Setter method for qPrivateKey and qPublicKey"""
        self.qPrivateKey = sk
        self.qPublicKey = pk

    def set_classical_peer_public_key(self, key):
        """Setter method for cPeerPublicKey."""
        self.cPeerPublicKey = key

    def set_quantum_peer_public_key(self, key):
        """Setter method for cPeerPublicKey."""
        self.qPeerPublicKey = key

    def get_symmetric_key(self):
        """Returns the variable symmetricKey."""
        return self.symmetricKey

    def get_classical_private_key(self):
        """Returns the variable cPrivateKey."""
        return self.cPrivateKey
    
    def get_quantum_private_key(self):
        """Returns the variable qPrivateKey."""
        return self.qPrivateKey
    
    def get_classical_public_key(self):
        """Returns the variable cPublicKey."""
        return self.cPublicKey
    
    def get_quantum_public_key(self):
        """Returns the variable qPublicKey."""
        return self.qPublicKey
    
    def get_classical_peer_public_key(self):
        """Returns the variable cPeerPublicKey."""
        return self.cPeerPublicKey
    
    def get_quantum_peer_public_key(self):
        """Returns the variable qPeerPublicKey."""
        return self.qPeerPublicKey
    
    def generate_symmetric_key(self):
        """Derives a shared key with a peer, using the privateKey and publicKey instance 
        variables."""
        cSharedKey = self.get_classical_private_key().exchange(ec.ECDH(), self.get_classical_peer_public_key())#Performs elliptic curve diffie-hellman (ECDH) using the peer public key and own private key
        #qSharedKey = self.get_quantum_private_key().exchange(ec.ECDH(), self.get_quantum_peer_public_key())
        derivedKey = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(cSharedKey)#Uses a key derivation function (HKDF) to generate the final shared key
        self.set_symmetric_key(derivedKey)#Sets the derived key as an instance variable
        print(f"Symmetric key successfully derived...\nKey: {derivedKey}")

    def generate_asymmetric_keys(self):
        """Randomly generates a private key using diffie-hellman and derives its 
        corresponding public key."""
        privateKey = ec.generate_private_key(ec.SECP384R1())#Uses ECDH to generate a private key 384 bytes in size
        publicKey = privateKey.public_key()#Derives the corresponding public key
        self.set_classical_asymmetric_keys(privateKey, publicKey)#Sets the classical public and private keys as instance variables
        print("Classical key pair successfully generated.")
        publicKey, privateKey = generate_keypair()#Generates a quantum key pair using Kyber1024
        self.set_quantum_asymmetric_keys(privateKey, publicKey)#Sets the quantum public and private keys as instance variablers
        print("Quantum key pair successfully generated.")

    def recvall(self, size):
        result = b''
        remaining = size
        while remaining > 0:
            data = self.socket.recv(remaining)
            result += data
            remaining -= len(data)
        return result