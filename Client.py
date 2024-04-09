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

import socket
from Node import *
from Protocol import *

class Client(Node):
    def __init__(self) -> None:
        """Creates an instance of the Client class, inheriting from the Node superclass."""
        super().__init__()
        self.nodeType = 'CLIENT' #Create an ENUM for this
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
            cKey = self.protocol.serialize(self.get_classical_public_key())#Serializes classical public key
            qKey = self.get_quantum_public_key()
            keys = cKey + qKey
            size = len(keys)
            print("Sending key")
            self.socket.send(keys)#Sends the serialized public keys
            #size = len(cKey) 
            serializedKey = self.socket.recv(size)#Recieves the server's public key
            encryptedQuantumKey = serializedKey[(size-self.qPublicKeySize):]
            quantumKey = kyber_decap(self.get_quantum_private_key(), encryptedQuantumKey)
            classicalKey = self.protocol.deserialize(serializedKey[:self.serializedCKeySize])
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
            print("Connection to server terminated")

client = Client()