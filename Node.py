#////////////////////////////////////////////////////////////////////////////////////////
#   This is the Node superclass for my dissertation project. This creates a template for the
#   server and client subclasses to be built from.
#   Much of this code is based on the datacamp socket tutorial: https://www.datacamp.com/tutorial/a-complete-guide-to-socket-programming-in-python
#
#   Dissertation Title: An Analysis Of Post-Quantum Cryptographic Schemes For Real World Use
#   Author: Jude Gibson
#   Supervisor: Bhagya Wimalasiri
#   Date Created: 13/02/2024
#////////////////////////////////////////////////////////////////////////////////////////

import socket
import os
import nacl.secret
from nacl.secret import SecretBox
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
from Protocol import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

class Node():
    def __init__(self) -> None:
        self.protocol = Protocol()
        self.ip = "127.0.0.1"
        self.handshakePort = 8282
        self.port = 8000
        self.symmetricKey = None
        self.peerPublicKey = None
        self.publicKeySize = 384
        self.generate_asymmetric_keys()

    def set_symmetric_key(self, key):
        self.symmetricKey = key

    def set_asymmetric_keys(self, sk, pk):
        self.privateKey = sk
        self.publicKey = pk

    def set_peer_public_key(self, key):
        self.peerPublicKey = key

    def get_symmetric_key(self):
        return self.symmetricKey

    def get_private_key(self):
        return self.privateKey
    
    def get_public_key(self):
        return self.publicKey
    
    def get_peer_public_key(self):
        return self.peerPublicKey
    
    def generate_symmetric_key(self):
        shared_key = self.privateKey.exchange(ec.ECDH(), self.get_peer_public_key())
        derived_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data').derive(shared_key)
        #print(type(key))
        #box = nacl.secret.SecretBox(key)
        self.set_symmetric_key(derived_key)
        print(f"Symmetric key successfully derived...\nKey: {derived_key}")

    def generate_asymmetric_keys(self):
        #params = dh.generate_parameters(generator=2, key_size=self.keySize)
        privateKey = ec.generate_private_key(ec.SECP384R1())
        publicKey = privateKey.public_key()
        self.set_asymmetric_keys(privateKey, publicKey)
        print("Key pair successfully generated.")

    def send_key(self): #Half of the public key exchange - sends key first
        try:
            key = self.get_public_key()
            print(f"Key: {key}\nKey Type: {type(key)}")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.connect((self.ip, self.handshakePort))
            print("Serializing public key")
            serializedKey = self.get_public_key().public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            )
            print("Sending key")
            self.socket.send(serializedKey)
            print("Key sent.")
            serializedKey = self.socket.recv(self.publicKeySize)
            key = serialization.load_ssh_public_key(serializedKey)
        except Exception as e:
            print(f"Error: {e}")
        finally:
            self.socket.close()
            self.set_peer_public_key(key)

    def listen_for_key(self): #Half of the public key exchange - sends key second
        try:
            serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            serverSocket.bind((self.ip, self.handshakePort))
            serverSocket.listen(0) #No backlog queue
            print(f"Listening for keys on {self.ip}:{self.handshakePort}.")
            self.socket, bob_address = serverSocket.accept()
            print("Connection accepted...")
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            print("Recieving key...")
            serializedKey = self.socket.recv(self.publicKeySize)#.decode("utf-8")
            print("Key recieved.")
            key = serialization.load_ssh_public_key(serializedKey)
            print("Peer public key deserialized.")
            serializedKey = self.get_public_key().public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            )
            self.socket.send(serializedKey)
        except Exception as e:
            print(f"Error: {e}")
            key = None
        finally:
            serverSocket.close()
            self.socket.close()
            self.set_peer_public_key(key)
            

    def recvall(self, size):
        result = b''
        remaining = size
        while remaining > 0:
            data = self.socket.recv(remaining)
            result += data
            remaining -= len(data)
        return result