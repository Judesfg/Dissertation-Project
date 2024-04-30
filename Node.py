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
import tracemalloc
import linecache
import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.pqcrypto.kem.kyber1024 import generate_keypair as kyber_keypair
from pqcrypto.pqcrypto.kem.kyber1024 import  encrypt as kyber_encap
from pqcrypto.pqcrypto.kem.kyber1024 import  decrypt as kyber_decap
from pqcrypto.pqcrypto.kem.mceliece348864 import generate_keypair as mceliece_keypair
from pqcrypto.pqcrypto.kem.mceliece348864 import  encrypt as mceliece_encap
from pqcrypto.pqcrypto.kem.mceliece348864 import  decrypt as mceliece_decap
from pqcrypto.pqcrypto.sign.dilithium4 import generate_keypair as dilithium_keypair
from pqcrypto.pqcrypto.sign.dilithium4 import sign as dilithium_sign
from pqcrypto.pqcrypto.sign.dilithium4 import verify as dilithium_verify
from pqcrypto.pqcrypto.sign.sphincs_sha256_256f_robust import generate_keypair as sphincs_keypair
from pqcrypto.pqcrypto.sign.sphincs_sha256_256f_robust import sign as sphincs_sign
from pqcrypto.pqcrypto.sign.sphincs_sha256_256f_robust import verify as sphincs_verify

class Node():
    def __init__(self, encType, sigType, runNo) -> None:
        """Initialises an instance of the Node class."""
        self.protocol = Protocol()
        self.encryptionKeyType = encType #KYBER or MCELIECE
        self.signatureType = sigType #DILITHIUM or SPHINCS or ECDSA
        self.ip = "127.0.0.1"
        self.handshakePort = 8282 + runNo
        self.port = 8000 + runNo
        self.symmetricKey = None
        self.peerPublicKey = None
        self.cPublicKeySize = 384
        self.serializedCKeySize = 215
        if self.encryptionKeyType == 'KYBER':
            self.qPublicKeySize = 1568
            self.qEncapKeySize = 1568
        elif self.encryptionKeyType == 'MCELIECE':
            self.qPublicKeySize = 261120
            self.qEncapKeySize = 128
        if self.signatureType == 'DILITHIUM':
            self.signatureSize = 3366
        elif self.signatureType == 'SPHINCS':
            self.signatureSize = 49216
        elif self.signatureType == 'ECDSA':
            self.signatureSize = 104
        self.qSharedKeySize = 32

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

    def set_asymmetric_signature_keys(self, sk, pk):
        """Setter method for qPrivateSignatureKey and qPublicSignatureKey"""
        self.privateSignatureKey = sk
        self.publicSignatureKey = pk

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
    
    def get_private_signature_key(self):
        """Returns the variable privateSignatureKey"""
        return self.privateSignatureKey
    
    def get_public_signature_key(self):
        """Returns the variable publicSignatureKey"""
        return self.publicSignatureKey
    
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
        tracemalloc.start()
        start_time = time.time()
        derivedKey = HKDF(algorithm=hashes.SHA256(), length=32, salt=qSharedKey, info=b'handshake data').derive(cSharedKey)#Uses a key derivation function (HKDF) to generate the final shared key
        timeTaken = time.time() - start_time
        file = open("KDF-time.txt","a")
        file.write(f"\nE: {self.encryptionKeyType}, S: {self.signatureType}:: {timeTaken}")
        file.close()
        print("KDF time taken: %s seconds" % (timeTaken))
        snapshot = tracemalloc.take_snapshot()
        print("\n\nMemory data for symmetric key gen:")
        self.display_memory(snapshot)
        tracemalloc.stop()
        print("\n\n")
        self.set_symmetric_key(derivedKey)#Sets the derived key as an instance variable
        print(f"Symmetric key successfully derived...\nKey: {derivedKey}\n")

    def generate_asymmetric_keys(self):
        """Randomly generates a private key using diffie-hellman and derives its 
        corresponding public key. Then generates a keypair using a quantum
        primative."""
        start_time = time.time()
        privateDHKey = ec.generate_private_key(ec.SECP384R1())#Uses ECDH to generate a private key 384 bytes in size
        publicDHKey = privateDHKey.public_key()#Derives the corresponding public key
        timeTaken = time.time() - start_time
        file = open("diffie-hellman-time.txt","a")
        file.write(f"\n{str(timeTaken)}")
        file.close()
        print("Diffie-hellman keygen runtime: %s seconds" % (time.time() - start_time))
        self.set_classical_asymmetric_encryption_keys(privateDHKey, publicDHKey)#Sets the classical public and private keys as instance variables
        print("Classical key pair successfully generated.")
        tracemalloc.start()
        if self.encryptionKeyType == 'KYBER':
            start_time = time.time()
            publicKey, privateKey = kyber_keypair()#Generates a quantum key pair using Kyber1024
            timeTaken = time.time() - start_time
            file = open("kyber-keygen-time.txt","a")
            file.write(f"\n{str(timeTaken)}")
            file.close()
        elif self.encryptionKeyType == 'MCELIECE':
            start_time = time.time()
            publicKey, privateKey = mceliece_keypair()#Generates a quantum key pair using McEliece348864
            timeTaken = time.time() - start_time
            file = open("mceliece-keygen-time.txt","a")
            file.write(f"\n{str(timeTaken)}")
            file.close()
        print("Encryption keypair gen time taken: %s seconds" % (time.time() - start_time))
        snapshot = tracemalloc.take_snapshot()
        print("\n\nMemory data for asymmetric key gen:")
        self.display_memory(snapshot)
        tracemalloc.stop()
        print("\n\n")
        self.set_quantum_asymmetric_encryption_keys(privateKey, publicKey)#Sets the quantum public and private keys used for enryption as instance variables
        self.setSignatureKeys()
        print("Quantum key pair successfully generated.")

    def setSignatureKeys(self):
        if self.signatureType == 'DILITHIUM':
            tracemalloc.start()
            start_time = time.time()
            publicKey, privateKey = dilithium_keypair()
            timeTaken = time.time() - start_time
            file = open("dilithium-keygen-time.txt","a")
            file.write(f"\n{str(timeTaken)}")
            file.close()
            print("Signature keygen time taken: %s seconds" % (time.time() - start_time))
            snapshot = tracemalloc.take_snapshot()
            print("\n\nMemory data for signature keypair gen:")
            self.display_memory(snapshot)
            tracemalloc.stop()
            print("\n\n")
            if self.nodeType == 'SERVER':
                fPublic = open("serverPublicDilithiumKey.txt","w")
                fPrivate = open("serverPrivateDilithiumKey.txt","w")
            elif self.nodeType == 'CLIENT':
                fPublic = open("clientPublicDilithiumKey.txt","w")
                fPrivate = open("clientPrivateDilithiumKey.txt","w")
            fPublic.write(str(publicKey))
            fPrivate.write(str(privateKey))
        elif self.signatureType == 'SPHINCS':
            tracemalloc.start()
            start_time = time.time()
            publicKey, privateKey = sphincs_keypair()
            timeTaken = time.time() - start_time
            file = open("sphincs-keygen-time.txt","a")
            file.write(f"\n{str(timeTaken)}")
            file.close()
            print("Signature keygen time taken: %s seconds" % (time.time() - start_time))
            snapshot = tracemalloc.take_snapshot()
            print("\n\nMemory data for signature keypair gen:")
            self.display_memory(snapshot)
            tracemalloc.stop()
            print("\n\n")
            if self.nodeType == 'SERVER':
                fPublic = open("serverPublicSphincsKey.txt","w")
                fPrivate = open("serverPrivateSphincsKey.txt","w")
            elif self.nodeType == 'CLIENT':
                fPublic = open("clientPublicSphincsKey.txt","w")
                fPrivate = open("clientPrivateSphincsKey.txt","w")
            fPublic.write(str(publicKey))
            fPrivate.write(str(privateKey))
        elif self.signatureType == 'ECDSA':
            tracemalloc.start()
            start_time = time.time()
            privateKey = ec.generate_private_key(ec.SECP384R1())
            publicKey = privateKey.public_key()
            timeTaken = time.time() - start_time
            file = open("ECDSA-keygen-time.txt","a")
            file.write(f"\n{str(timeTaken)}")
            file.close()
            print("Signature keygen time taken: %s seconds" % (timeTaken))
            snapshot = tracemalloc.take_snapshot()
            print("\n\nMemory data for signature keypair gen:")
            self.display_memory(snapshot)
            tracemalloc.stop()
            print("\n\n")
            if self.nodeType == 'SERVER':
                fPublic = open("serverPublicECDSAKey.txt","w")
                fPrivate = open("serverPrivateECDSAKey.txt","w")
            elif self.nodeType == 'CLIENT':
                fPublic = open("clientPublicECDSAKey.txt","w")
                fPrivate = open("clientPrivateECDSAKey.txt","w")
            fPublic.write(str(self.protocol.serialize(publicKey)))
            fPrivate.write(str(self.protocol.serialize_private(privateKey)))
        #print(f"\n\nSig Public Key Size: {len(publicKey)}\nSig Private Key Size: {len(privateKey)}")
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
    
    def display_memory(self, snapshot, key_type='lineno', limit=5):
        snapshot = tracemalloc.take_snapshot()
        snapshot = snapshot.filter_traces((
            tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
            tracemalloc.Filter(False, "<frozen importlib._bootstrap_external>"),
            tracemalloc.Filter(False, "<frozen abc>"),
            tracemalloc.Filter(False, "<unknown>"),
        ))
        top_stats = snapshot.statistics(key_type)

        print("Top %s lines" % limit)
        for index, stat in enumerate(top_stats[:limit], 1):
            frame = stat.traceback[0]
            # replace "/path/to/module/file.py" with "module/file.py"
            filename = os.sep.join(frame.filename.split(os.sep)[-2:])
            print("#%s: %s:%s: %.1f KiB"
                % (index, filename, frame.lineno, stat.size / 1024))
            line = linecache.getline(frame.filename, frame.lineno).strip()
            if line:
                print('    %s' % line)

        other = top_stats[limit:]
        if other:
            size = sum(stat.size for stat in other)
            print("%s other: %.1f KiB" % (len(other), size / 1024))
        total = sum(stat.size for stat in top_stats)
        print("Total allocated size: %.1f KiB" % (total / 1024))