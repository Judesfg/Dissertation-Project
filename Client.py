#////////////////////////////////////////////////////////////////////////////////////////
#   This is the client class for my dissertation project. It uses the node superclass to create 
#   a client object that can establish a connection with a server. This connection is then 
#   encrypted against attacks from a post-quantum adversary.
#   Much of this code is based on the datacamp socket tutorial: https://www.datacamp.com/tutorial/a-complete-guide-to-socket-programming-in-python
#
#   Dissertation Title: An Analysis Of Post-Quantum Cryptographic Schemes For Real World Use
#   Author: Jude Gibson
#   Supervisor: Bhagya Wimalasiri
#   Date Created: 13/02/2024
#////////////////////////////////////////////////////////////////////////////////////////

import socket
import time
from Node import *
from Protocol import *

class Client(Node):
    def __init__(self) -> None:
        super().__init__()
        self.send_key()
        self.generate_symmetric_key()
        #print(f"Private key type: {type(self.get_private_key())}")
        #print(f"Opposite public key type: {type(self.get_opposite_public_key())}")
        #lockbox = Box(self.privateKey, self.oppositePublicKey)
        #encryptedKey = lockbox.encrypt(self.symmetricKey)
        #self.send_key(encryptedKey, 'SYMMETRIC')
        self.run_client()


    def run_client(self):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client.connect((self.ip, self.port))
        try:
            while True:
                message = input("Enter message: ")
                encrypted = self.protocol.encrypt(message, self.get_symmetric_key())
                client.send(encrypted)#.encode("utf-8")[:1024])
                box = self.get_symmetric_key()
                time.sleep(0.1)
                response = client.recv(1024)
                decrypted = self.protocol.decrypt(response, self.get_symmetric_key())
                if decrypted == "close":
                    break
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client.close()
            print("Connection to server terminated")

    def establish_connection(self):
        self.send_key(self.get_public_key())


client = Client()