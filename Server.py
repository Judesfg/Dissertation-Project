"""
////////////////////////////////////////////////////////////////////////////////////////
This is the server class for my dissertation project. It uses the node superclass to create 
a server object that can establish a connection with a client. This connection is then 
encrypted against attacks from a post-quantum adversary.
Much of this code is based on the datacamp socket tutorial: https://www.datacamp.com/tutorial/a-complete-guide-to-socket-programming-in-python
   
Dissertation Title: An Analysis Of Post-Quantum Cryptographic Schemes For Real World Use
Author: Jude Gibson
Supervisor: Bhagya Wimalasiri
Date Created: 13/02/2024
////////////////////////////////////////////////////////////////////////////////////////
"""

import socket
from Node import *
from SignatureKeys import *

class Server(Node):
    def __init__(self) -> None:
        """Creates an instance of the Server class, inheriting from the Node superclass"""
        super().__init__()
        self.nodeType = 'SERVER' #Create an ENUM for this
        self.generate_asymmetric_keys()
        signatureKeys = SignatureKeys()
        if self.signatureType == 'DILITHIUM':
            self.set_asymmetric_signature_keys(signatureKeys.serverPrivateDilithiumKey, 
                                               signatureKeys.serverPublicDilithiumKey)
            self.set_peer_public_signature_key(signatureKeys.clientPublicDilithiumKey)
        elif self.signatureType == 'SPHINCS':
            self.set_asymmetric_signature_keys(signatureKeys.serverPrivateSphincsKey, 
                                               signatureKeys.serverPublicSphincsKey)
            self.set_peer_public_signature_key(signatureKeys.clientPublicSphincsKey)
        elif self.signatureType == 'ECDSA':
            self.set_asymmetric_signature_keys(self.protocol.deserialize_private(signatureKeys.serverPrivateECDSAKey), 
                                               self.protocol.deserialize(signatureKeys.serverPublicECDSAKey))
            self.set_peer_public_signature_key(self.protocol.deserialize(signatureKeys.clientPublicECDSAKey))
        self.listen_for_key()
        self.generate_symmetric_key()
        self.run_server()

    def listen_for_key(self):
        """Server side of the public key exchange. Recieves a key and saves it for later 
        use, before sending its own public key in response."""
        try:
            serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)#Creates an instance of the socket class
            serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#Allows the socket to use the same port more than once
            serverSocket.bind((self.ip, self.handshakePort))#Binds the socket to the given ip address and port
            serverSocket.listen(0)#Server listens for activity on this port. The parameter 0 means there can be no backlog queue
            print(f"Listening for keys on {self.ip}:{self.handshakePort}.")

            #Once a client is detected, a new new instance of the socket class is created for it
            self.socket, bob_address = serverSocket.accept()
            print("Connection accepted...")

            #Allows the client socket to use the same port more than once
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            packageSize = self.serializedCKeySize+self.qPublicKeySize+self.signatureSize
            if self.signatureType == 'ECDSA':
                serializedKey = self.socket.recv(packageSize)#Recieves the public key from the client
            else:
                serializedKey = self.recvall(packageSize)#Recieves the public key from the client
            size = len(serializedKey)
            peerSignature = serializedKey[(size-self.signatureSize):]
            keyPackage = serializedKey[:(size-self.signatureSize)]
            size = len(keyPackage)
            if self.signatureType == 'DILITHIUM':
                assert dilithium_verify(self.get_peer_public_signature_key(), keyPackage, peerSignature)
            elif self.signatureType == 'SPHINCS':
                assert sphincs_verify(self.get_peer_public_signature_key(), keyPackage, peerSignature)
            elif self.signatureType == 'ECDSA':
                self.get_peer_public_signature_key().verify(peerSignature, keyPackage, ec.ECDSA(hashes.SHA256()))
            print("Digital signature valid!")
            quantumKey = keyPackage[(size-self.qPublicKeySize):]
            classicalKey = self.protocol.deserialize(keyPackage[:self.serializedCKeySize])
            print("Key recieved.")
            cSerializedKey = self.protocol.serialize(self.get_classical_public_encryption_key())#Serializes classical public key
            if self.encryptionKeyType == 'KYBER':
                encryptedQuantumKey, qSharedKey = kyber_encap(quantumKey)
            elif self.encryptionKeyType == 'MCELIECE':
                encryptedQuantumKey, qSharedKey = mceliece_encap(quantumKey)
            keys = cSerializedKey+encryptedQuantumKey
            if self.signatureType == 'DILITHIUM':
                signature = dilithium_sign(self.get_private_signature_key(), keys)
            elif self.signatureType == 'SPHINCS':
                signature = sphincs_sign(self.get_private_signature_key(), keys)
            elif self.signatureType == 'ECDSA':
                signature = self.get_private_signature_key().sign(keys, ec.ECDSA(hashes.SHA256()))
            keys += signature
            self.socket.send(keys)#Server responds to the client with its own public key
        except Exception as e:
            print(f"Error: {e}")
            key = None
        finally:
            serverSocket.close()#Closes connection
            self.socket.close()#Closes connection
            self.set_classical_peer_public_key(classicalKey)#Sets classical peer public key as an instance variable
            self.set_quantum_shared_key(qSharedKey)#Sets the shared quantum key as an instance variable

    def run_server(self):
        """Runs on a loop once the initial handshake has been performed. At this point
        the shared key is used to encrypt and decrypt messages."""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)#Creates an instance of the socket class
            server.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#Allows the socket to use the same port more than once
            server.bind((self.ip, self.port))#Binds the socket to the given ip address and port
            server.listen(0)#Server listens for activity on this port. The parameter 0 means there can be no backlog queue
            print(f"Listening for requests on {self.ip}:{self.port}.")

            #Once a client is detected, a new new instance of the socket class is created for it
            client_socket, client_address = server.accept()
            client_socket.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#Allows the socket to use the same port more than once
            print(f"Connected: {client_address[0]}:{client_address[1]}")
            while True:
                request = client_socket.recv(1024)#Recieves an encrypted message from the client
                decrypted = self.protocol.decrypt(request, self.get_symmetric_key())#Decrypts the message using its own shared key
                if decrypted == "close":#If the message reads "closed"...

                    #...encrypts a response to the client also reading "closed"...
                    encrypted = self.protocol.encrypt("close", self.get_symmetric_key())
                    client_socket.send(encrypted)#...and sends it
                    break

                #Encrypts an acknowledgment to the client
                encrypted = self.protocol.encrypt("Accepted", self.get_symmetric_key())
                client_socket.send(encrypted)#Sends a response to the client
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()#Closes connection to the client
            print("Connection with client terminated\n\n")
            server.close()#Shuts down the server

server = Server()