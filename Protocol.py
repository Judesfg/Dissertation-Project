"""
////////////////////////////////////////////////////////////////////////////////////////
This is the protocol class for my dissertation project. This is where much of the code for
encrypting the connection between between a client and a server will be written.
Guide: https://pynacl.readthedocs.io/en/latest/public/

Dissertation Title: An Analysis Of Post-Quantum Cryptographic Schemes For Real World Use
Author: Jude Gibson
Supervisor: Bhagya Wimalasiri
Date Created: 15/02/2024
////////////////////////////////////////////////////////////////////////////////////////
"""

import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding

class Protocol():
    def __init__(self):
        """Currently does nothing. Will remain here in case I need to add any instance 
        variables later."""
        pass

    def encrypt(self, plaintext, key):
        """Takes some plaintext and a key, and encrypts the plaintext using AES with CBC."""
        padder = padding.PKCS7(128).padder()#Creates a padder object
        paddedData = padder.update(plaintext.encode("utf-8")) + padder.finalize()#Pads the data to be used with a 128bit block cipher
        iv = os.urandom(16)#Generates a random 16byte initialisation vector
        print(f"Padded Message Size: {sys.getsizeof(paddedData)}")
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))#Creates a cipher using the advanced encryption scheme (AES) with cipher block chaining (CBC)
        encryptor = cipher.encryptor()#Creates an encryptor using the cipher
        encrypted = encryptor.update(paddedData) + encryptor.finalize()#Uses the encryptor to encrypt the padded message
        print(f"Base ciphertext: {encrypted}")
        encrypted += iv#Appends the initialisation vector to the encrypted message
        print(f"Ciphertext Size: {sys.getsizeof(encrypted)}\nActual Ciphertext: {encrypted}\nInitial Vector: {iv}")
        return encrypted#Returns the encrypted message

    def decrypt(self, ciphertext, key):
        """Given some ciphertext and a key, decrypts the ciphertext and returns plaintext."""
        iv = ciphertext[-16:]#Slices the ciphertext to retrieves the initialisation vector
        print(f"Passed ciphertext: {ciphertext}")
        messageSize = len(ciphertext)-16#Determines the size of the encrypted message without the IV
        print(f"Messsge Size: {messageSize}")
        ciphertext = ciphertext[0:messageSize]#Slices the ciphertext to retrieve just the encrypted message
        print(f"Actual Ciphertext: {ciphertext}")
        print(f"Initial Vector: {iv}")
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))#Recreates the cipher that was used to encrypt the message
        decryptor = cipher.decryptor()#Creates a decryptor using the cipher
        paddedPlaintext = decryptor.update(ciphertext) + decryptor.finalize()#Decrypts the ciphertext
        unpadder = padding.PKCS7(128).unpadder()#Creates an unpadder object
        plaintext = unpadder.update(paddedPlaintext) + unpadder.finalize()#Removes the padding from the message
        plaintext = plaintext.decode("utf-8")#Converts the message from a bytestring to a string
        print(f"Plaintext: {plaintext}")
        return plaintext#Returns the decrypted message
    
    def serialize(self, x):
        """Given some input, returns a serialized version using OpenSSH."""
        return x.public_bytes(
            encoding=serialization.Encoding.OpenSSH, 
            format=serialization.PublicFormat.OpenSSH
            )
    
    def deserialize(self, x):
        """Given some OpenSSH serialized input, returns a deserialized version."""
        return serialization.load_ssh_public_key(x)