#////////////////////////////////////////////////////////////////////////////////////////
#   This is the server class for my dissertation project. It uses the node superclass to create 
#   a server object that can establish a connection with a client. This connection is then 
#   encrypted against attacks from a post-quantum adversary.
#   Much of this code is based on the datacamp socket tutorial: https://www.datacamp.com/tutorial/a-complete-guide-to-socket-programming-in-python
#   
#   Dissertation Title: An Analysis Of Post-Quantum Cryptographic Schemes For Real World Use
#   Author: Jude Gibson
#   Supervisor: Bhagya Wimalasiri
#   Date Created: 13/02/2024
#////////////////////////////////////////////////////////////////////////////////////////

import socket
from Node import *

class Server(Node):
    def __init__(self) -> None:
        super().__init__()
        self.listen_for_key()
        self.generate_symmetric_key()
        #print(f"Private key type: {type(self.get_private_key())}")
        #print(f"Opposite public key type: {type(self.get_opposite_public_key())}")
        self.run_server()

    def run_server(self):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.ip, self.port))
            server.listen(0) #No backlog queue
            print(f"Listening for requests on {self.ip}:{self.port}.")
            client_socket, client_address = server.accept()
            client_socket.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            print(f"Connected: {client_address[0]}:{client_address[1]}")
            while True:
                request = client_socket.recv(1024) #Recieves a message from the client and converts binary form to string
                decrypted = str(self.protocol.decrypt(request, self.get_symmetric_key()))
                if decrypted == "close":
                    encrypted = self.protocol.encrypt("close", self.get_symmetric_key())
                    client_socket.send(encrypted)
                    break
                encrypted = self.protocol.encrypt("Accepted", self.get_symmetric_key())
                client_socket.send(encrypted)
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()
            print("Connection with client terminated")
            server.close()
        
