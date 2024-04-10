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
from pqcrypto.pqcrypto.kem.kyber1024 import generate_keypair as kyber_keypair
from pqcrypto.pqcrypto.kem.kyber1024 import  encrypt as kyber_encap
from pqcrypto.pqcrypto.kem.kyber1024 import  decrypt as kyber_decap
from pqcrypto.pqcrypto.kem.mceliece8192128 import generate_keypair as mceliece_keypair
from pqcrypto.pqcrypto.kem.mceliece8192128 import  encrypt as mceliece_encap
from pqcrypto.pqcrypto.kem.mceliece8192128 import  decrypt as mceliece_decap
from pqcrypto.pqcrypto.sign.dilithium4 import generate_keypair as dilithium_keypair
from pqcrypto.pqcrypto.sign.dilithium4 import sign as dilithium_sign
from pqcrypto.pqcrypto.sign.dilithium4 import verify as dilithium_verify

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
        self.serializedCKeySize = 215
        self.qPublicKeySize = 1568
        self.qSharedKeySize = 32
        self.dilithiumSignatureSize = 3366

    def set_symmetric_key(self, key):
        """Setter method for symmetricKey."""
        self.symmetricKey = key

    def set_classical_asymmetric_encryption_keys(self, sk, pk):
        """Setter method for cPrivateEncryptionKey and cPublicEncryptionKey."""
        self.cPrivateEncryptionKey = sk
        self.cPublicEncryptionKey = pk

    def set_quantum_asymmetric_encryption_keys(self, sk, pk):
        """Setter method for qPrivateEncryptionKey and qPublicEncryptionKey"""
        self.qPrivateEncryptionKey = sk
        self.qPublicEncryptionKey = pk

    def set_quantum_asymmetric_signature_keys(self, sk, pk):
        """Setter method for qPrivateSignatureKey and qPublicSignatureKey"""
        self.qPrivateSignatureKey = sk
        self.qPublicSignatureKey = pk

    def set_classical_peer_public_key(self, key):
        """Setter method for cPeerPublicKey."""
        self.cPeerPublicKey = key

    def set_quantum_peer_public_key(self, key):
        """Setter method for cPeerPublicKey."""
        self.qPeerPublicKey = key

    def set_peer_public_signature_key(self, key):
        """Setter method for peerPublicSignatureKey"""
        self.peerpublicSignatureKey = key

    def set_quantum_shared_key(self, key):
        """Setter method for qSharedKey."""
        self.qSharedKey = key

    def get_symmetric_key(self):
        """Returns the variable symmetricKey."""
        return self.symmetricKey

    def get_classical_private_encryption_key(self):
        """Returns the variable cPrivateKey."""
        return self.cPrivateEncryptionKey
    
    def get_quantum_private_encryption_key(self):
        """Returns the variable qPrivateKey."""
        return self.qPrivateEncryptionKey
    
    def get_classical_public_encryption_key(self):
        """Returns the variable cPublicKey."""
        return self.cPublicEncryptionKey
    
    def get_quantum_public_encryption_key(self):
        """Returns the variable qPublicKey."""
        return self.qPublicEncryptionKey
    
    def get_quantum_private_signature_key(self):
        """Returns the variable qPrivateSignatureKey"""
        return self.qPrivateSignatureKey
    
    def get_quantum_public_signature_key(self):
        """Returns the variable qPublicSignatureKey"""
        return self.qPublicSignatureKey
    
    def get_classical_peer_public_key(self):
        """Returns the variable cPeerPublicKey."""
        return self.cPeerPublicKey
    
    def get_quantum_peer_public_key(self):
        """Returns the variable qPeerPublicKey."""
        return self.qPeerPublicKey
    
    def get_peer_public_signature_key(self):
        """Returns the variable peerPublicSignatureKey"""
        return self.peerpublicSignatureKey
    
    def get_quantum_shared_key(self):
        """Returns the variable qSharedKey."""
        return self.qSharedKey
    
    def generate_symmetric_key(self):
        """Derives a shared key with a peer, using the privateKey and publicKey instance 
        variables."""
        peer_public_key = self.get_classical_peer_public_key()
        private_key = self.get_classical_private_encryption_key()
        cSharedKey = private_key.exchange(ec.ECDH(), peer_public_key)#Performs elliptic curve diffie-hellman (ECDH) using the peer public key and own private key
        qSharedKey = self.get_quantum_shared_key()
        derivedKey = HKDF(algorithm=hashes.SHA256(), length=32, salt=qSharedKey, info=b'handshake data').derive(cSharedKey)#Uses a key derivation function (HKDF) to generate the final shared key
        self.set_symmetric_key(derivedKey)#Sets the derived key as an instance variable
        print(f"Symmetric key successfully derived...\nKey: {derivedKey}\n")

    def generate_asymmetric_keys(self):
        """Randomly generates a private key using diffie-hellman and derives its 
        corresponding public key."""
        privateDHKey = ec.generate_private_key(ec.SECP384R1())#Uses ECDH to generate a private key 384 bytes in size
        publicDHKey = privateDHKey.public_key()#Derives the corresponding public key
        self.set_classical_asymmetric_encryption_keys(privateDHKey, publicDHKey)#Sets the classical public and private keys as instance variables
        print("Classical key pair successfully generated.")
        publicKyKey, privateKyKey = kyber_keypair()#Generates a quantum key pair using Kyber1024
        self.set_quantum_asymmetric_encryption_keys(privateKyKey, publicKyKey)#Sets the quantum public and private keys used for enryption as instance variables
        #self.setSignatureKeys()
        print("Quantum key pair successfully generated.")

    def setSignatureKeys(self):
        publicDiKey, privateDiKey = dilithium_keypair()
        print(f"Original Dilithium Public Key Length: {len(publicDiKey)}")
        print(f"Original Dilithium Private Key Length: {len(privateDiKey)}")
        if self.nodeType == 'SERVER':
            fPublic = open("serverPublicDilithiumKey.txt","w")
            fPrivate = open("serverPrivateDilithiumKey.txt","w")
        elif self.nodeType == 'CLIENT':
            fPublic = open("clientPublicDilithiumKey.txt","w")
            fPrivate = open("clientPrivateDilithiumKey.txt","w")
        fPublic.write(str(publicDiKey))
        fPrivate.write(str(privateDiKey))
        fPublic.close()
        fPrivate.close()

    def recvall(self, size):
        result = b''
        remaining = size
        while remaining > 0:
            data = self.socket.recv(remaining)
            result += data
            remaining -= len(data)
        return result