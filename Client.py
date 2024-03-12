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
            print("Serializing public key")#Server listens for activity on this port. The parameter 0 means there can be no backlog queue
            cSerializedKey = self.protocol.serialize(self.get_classical_public_key())#Serializes classical public key
            qSerializedKey = self.get_quantum_public_key()#self.protocol.serialize(self.get_quantum_public_key())#Serializes quantum public key
            print("Sending key")
            self.socket.send(cSerializedKey+qSerializedKey)#Sends the serialized public keys
            print("Key sent.")
            serializedKey = self.socket.recv(self.cPublicKeySize+self.qPublicKeySize)#Recieves the server's public key
            #deserializedKey = self.protocol.deserialize(serializedKey)#Deserializes the recieved package
            classicalKey = self.protocol.deserialize(serializedKey[:self.cPublicKeySize])#Slices the package and deserializes to retrieve the classical key
            quantumKey = serializedKey[self.qPublicKeySize:]#self.protocol.deserialize(serializedKey[self.qPublicKeySize:])#Slices the  package and deserializes to retrieve the quantum key
        except Exception as e:
            print(f"Error: {e}")
        finally:
            self.socket.close()#Closes connection to the server
            self.set_classical_peer_public_key(classicalKey)#Sets the server's classical public key as an instance variable
            self.set_quantum_peer_public_key(quantumKey)#Sets the server's quantum public key as an instance variable

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