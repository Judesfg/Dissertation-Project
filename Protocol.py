#////////////////////////////////////////////////////////////////////////////////////////
#   This is the protocol class for my dissertation project. This is where much of the code for
#   encrypting the connection between between a client and a server will be written.
#   Guide: https://pynacl.readthedocs.io/en/latest/public/
#
#   Dissertation Title: An Analysis Of Post-Quantum Cryptographic Schemes For Real World Use
#   Author: Jude Gibson
#   Supervisor: Bhagya Wimalasiri
#   Date Created: 15/02/2024
#////////////////////////////////////////////////////////////////////////////////////////

#\x1eo*zxma0\xb7\xe8\xc5\xbe\xef\xbf\xf3,\xcf\x18\xad\x17\xdb\x1e\xdf\x19\xe1W\xa7Q\t\xcb\xa9\xf8
#\x1eo*zxma0\xb7\xe8\xc5\xbe\xef\xbf\xf3,\xcf\x18\xad\x17\xdb\x1e\xdf\x19\xe1W\xa7Q\t\xcb\xa9\xf8

import sys
import os
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding

class Protocol():
    def __init__(self):
        self.setNonce()

    def encrypt(self, plaintext, key):
        padder = padding.PKCS7(128).padder()
        paddedData = padder.update(plaintext.encode("utf-8")) + padder.finalize()
        iv = os.urandom(16)
        print(f"Key Size: {sys.getsizeof(paddedData)}")
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(paddedData) + encryptor.finalize()
        print(f"Base ciphertext: {encrypted}")
        encrypted += iv
        print(f"Ciphertext Size: {sys.getsizeof(encrypted)}")
        print(f"Actual Ciphertext: {encrypted}")
        print(f"Initial Vector: {iv}")
        return encrypted

    def decrypt(self, ciphertext, key):
        iv = ciphertext[-16:]
        print(f"Passed ciphertext: {ciphertext}")
        messageSize = len(ciphertext)-16
        print(f"Messsge Size: {messageSize}")
        ciphertext = ciphertext[0:messageSize]
        print(f"Actual Ciphertext: {ciphertext}")
        print(f"Initial Vector: {iv}")

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        paddedPlaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(paddedPlaintext) + unpadder.finalize()
        plaintext = plaintext.decode("utf-8")
        print(f"Plaintext: {plaintext}")
        
        return plaintext
    
    def setNonce(self):
        self.nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    

#   1. client generates a secret symmetric key
#   2. both nodes generate an asymmetric key pair
#   3. client encrypts symmetric key with server's public key and transmits ciphertext key to server
#   4. server decrypts shared key and uses this to encrypt further messages
#   5. repeat steps 1-4 with KYBER
#   6. retrieve post-quantum key from KDF