"""
////////////////////////////////////////////////////////////////////////////////////////
This is the client class for my dissertation project. It uses the node superclass to create 
a client object that can establish a connection with a server. This connection is then 
encrypted against attacks from a post-quantum adversary.
Much of this code is based on the datacamp socket tutorial: https://www.datacamp.com/tutorial/a-complete-guide-to-socket-programming-in-python

Dissertation Title: An Analysis Of Post-Quantum Cryptographic Schemes For Real World Use
Author: Jude Gibson
Supervisor: Bhagya Wimalasiri
Date Created: 13/02/2024
////////////////////////////////////////////////////////////////////////////////////////
"""

import tracemalloc
import linecache
import os
import socket
from Node import *
from SignatureKeys import *
from Protocol import *

class Client(Node):
    def __init__(self, encType, sigType) -> None:
        """Creates an instance of the Client class, inheriting from the Node superclass."""
        super().__init__(encType, sigType)
        self.start_of_runtime = time.time()
        self.nodeType = 'CLIENT' #Create an ENUM for this
        self.generate_asymmetric_keys()
        signatureKeys = SignatureKeys()
        if self.signatureType == 'DILITHIUM':
            self.set_asymmetric_signature_keys(signatureKeys.clientPrivateDilithiumKey, signatureKeys.clientPublicDilithiumKey)
            self.set_peer_public_signature_key(signatureKeys.serverPublicDilithiumKey)
        elif self.signatureType == 'SPHINCS':
            self.set_asymmetric_signature_keys(signatureKeys.clientPrivateSphincsKey, signatureKeys.clientPublicSphincsKey)
            self.set_peer_public_signature_key(signatureKeys.serverPublicSphincsKey)
        elif self.signatureType == 'ECDSA':
            self.set_asymmetric_signature_keys(self.protocol.deserialize_private(signatureKeys.clientPrivateECDSAKey), 
                                               self.protocol.deserialize(signatureKeys.clientPublicECDSAKey))
            self.set_peer_public_signature_key(self.protocol.deserialize(signatureKeys.serverPublicECDSAKey))
        self.send_key()
        self.generate_symmetric_key()
        self.run_client()

    def send_key(self):
        """Client side of the public key exchange. Sends a public key and then recieves the 
        public key from the server, saving it for later use."""
        try:
            """The following 3 lines could really do with being offloaded to their 
            own function."""
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)#Creates a new instance of the socket class
            self.socket.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#Allows the socket to use the same port more than once
            self.socket.connect((self.ip, self.handshakePort))#Binds the socket to the given ip address and port
            cKey = self.protocol.serialize(self.get_classical_public_encryption_key())#Serializes classical public key
            qKey = self.get_quantum_public_encryption_key()
            keys = cKey + qKey

            #Sign the key package
            tracemalloc.start()
            if self.signatureType == 'DILITHIUM':
                signature = dilithium_sign(self.get_private_signature_key(), keys)
            elif self.signatureType == 'SPHINCS':
                signature = sphincs_sign(self.get_private_signature_key(), keys)
            elif self.signatureType == 'ECDSA':
                signature = self.get_private_signature_key().sign(keys, ec.ECDSA(hashes.SHA256()))
            keys += signature

            print("Sending key")
            size = len(keys)
            print(size)
            self.socket.send(keys)#Sends the serialized public keys
            print("Key sent")

            packageSize = self.serializedCKeySize+self.qEncapKeySize+self.signatureSize
            serializedKey = self.recvall(packageSize)#Recieves the server's public key package
            print("Key successfully recieved")
            peerSignature = serializedKey[(packageSize-self.signatureSize):]
            keyPackage = serializedKey[:(packageSize-self.signatureSize)]

            if self.signatureType == 'DILITHIUM':
                assert dilithium_verify(self.get_peer_public_signature_key(), keyPackage, peerSignature)
            elif self.signatureType == 'SPHINCS':
                assert sphincs_verify(self.get_peer_public_signature_key(), keyPackage, peerSignature)
            elif self.signatureType == 'ECDSA':
                self.get_peer_public_signature_key().verify(signature, keyPackage, ec.ECDSA(hashes.SHA256()))
            keys += signature
            print("Digital signature valid!")

            encryptedQuantumKey = keyPackage[self.serializedCKeySize:]
            if self.encryptionKeyType == 'KYBER':
                quantumKey = kyber_decap(self.get_quantum_private_encryption_key(), encryptedQuantumKey)
            elif self.encryptionKeyType == 'MCELIECE':
                quantumKey = mceliece_decap(self.get_quantum_private_encryption_key(), encryptedQuantumKey)
            classicalKey = self.protocol.deserialize(keyPackage[:self.serializedCKeySize])
        except Exception as e:
            print(f"Error: {e}")
        finally:
            self.socket.close()#Closes connection to the server
            self.set_classical_peer_public_key(classicalKey)#Sets the server's classical public key as an instance variable
            self.set_quantum_shared_key(quantumKey)#Sets the server's quantum public key as an instance variable

    def run_client(self):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)#Creates a new instance of the socket class
        client.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#Allows the socket to use the same port more than once
        client.connect((self.ip, self.port))#Binds the socket to the given ip address and port
        timeTaken = time.time() - self.start_of_runtime
        file = open("handshake-time.txt","a")
        file.write(f"\nE: {self.encryptionKeyType}, S: {self.signatureType} :: {timeTaken}")
        file.close()
        print("Total runtime: %s seconds" % (time.time() - self.start_of_runtime))
        try:
            while True:
                message = input("Enter message: ")#Asks the user to enter a message
                encrypted = self.protocol.encrypt(message, self.get_symmetric_key())#Encrypts the message with the established shared key
                client.send(encrypted)#Sends the encrypted message
                response = client.recv(1024)#Recieves a response from the server
                decrypted = self.protocol.decrypt(response, self.get_symmetric_key())#Decrypts the response from the server
                if decrypted == "close":#If the response reads "close"...
                    break#...break loop
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client.close()#Close connection to server
            print("Connection to server terminated\n\n")

client = Client('KYBER', 'DILITHIUM')