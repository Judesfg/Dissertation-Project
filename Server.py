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

class Server(Node):
    def __init__(self) -> None:
        """Creates an instance of the Server class, inheriting from the Node superclass"""
        super().__init__()
        self.nodeType = 'SERVER' #Create an ENUM for this
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
            self.socket, bob_address = serverSocket.accept()#Once a client is detected, a new new instance of the socket class is created for it
            print("Connection accepted...")
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#Allows the client socket to use the same port more than once
            serializedKey = self.socket.recv(self.serializedCKeySize)#Recieves the public key from the client
            size = len(serializedKey)
            print("Key recieved.")
            classicalKey = self.protocol.deserialize(serializedKey)
            cSerializedKey = self.protocol.serialize(self.get_classical_public_key())#Serializes classical public key
            encryptedKey, qSharedKey = encrypt(self.get_quantum_public_key())
            self.set_quantum_shared_key(qSharedKey)
            self.socket.send(cSerializedKey+qSharedKey)#Server responds to the client with its own public key
        except Exception as e:
            print(f"Error: {e}")
            key = None
        finally:
            serverSocket.close()#Closes connection
            self.socket.close()#Closes connection
            self.set_classical_peer_public_key(classicalKey)#Sets classical peer public key as an instance variable

    def run_server(self):
        """Runs on a loop once the initial handshake has been performed. At this point
        the shared key is used to encrypt and decrypt messages."""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)#Creates an instance of the socket class
            server.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#Allows the socket to use the same port more than once
            server.bind((self.ip, self.port))#Binds the socket to the given ip address and port
            server.listen(0)#Server listens for activity on this port. The parameter 0 means there can be no backlog queue
            print(f"Listening for requests on {self.ip}:{self.port}.")
            client_socket, client_address = server.accept()#Once a client is detected, a new new instance of the socket class is created for it
            client_socket.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#Allows the socket to use the same port more than once
            print(f"Connected: {client_address[0]}:{client_address[1]}")
            while True:
                request = client_socket.recv(1024)#Recieves an encrypted message from the client
                decrypted = self.protocol.decrypt(request, self.get_symmetric_key())#Decrypts the message using its own shared key
                if decrypted == "close":#If the message reads "closed"...
                    encrypted = self.protocol.encrypt("close", self.get_symmetric_key())#...encrypts a response to the client also reading "closed"...
                    client_socket.send(encrypted)#...and sends it
                    break
                encrypted = self.protocol.encrypt("Accepted", self.get_symmetric_key())#Encrypts an acknowledgment to the client
                client_socket.send(encrypted)#Sends a response to the client
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()#Closes connection to the client
            print("Connection with client terminated")
            server.close()#Shuts down the server