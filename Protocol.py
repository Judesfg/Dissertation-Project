"""
////////////////////////////////////////////////////////////////////////////////////////
This is the protocol class for my dissertation project. This is where much of the code for
encrypting the connection between between a client and a server is written, alongside
the code for Message Authentication, digital signatures and serialisation.
Guide: https://pynacl.readthedocs.io/en/latest/public/

Dissertation Title: An Analysis Of Post-Quantum Cryptographic Schemes For Real World Use
Author: Jude Gibson
Supervisor: Bhagya Wimalasiri
Date Created: 15/02/2024
////////////////////////////////////////////////////////////////////////////////////////
"""

import sys
import tracemalloc
import linecache
import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class Protocol():
    def __init__(self):
        """Currently does nothing. Will remain here in case I need to add any instance 
        variables later."""
        pass

    def encrypt(self, plaintext, key):
        """Takes some plaintext and a key, and encrypts the plaintext using AES with CBC.
        The order of operations is as such:
            -Pad the plaintext
            -Generate the MAC
            -Generate the IV
            -Encrypt the padded plaintex using the IV
            -Append the MAC"""
        print(f"\n\nBeginning Encryption...\n\nPassed plaintext: {plaintext}")
        padder = padding.PKCS7(128).padder()#Creates a padder object
        paddedData = padder.update(plaintext.encode("utf-8")) + padder.finalize()#Pads the data to be used with a 128bit block cipher
        certificate = self.generate_mac(paddedData, key)#Generates a MAC from the padded plaintext
        iv = os.urandom(16)#Generates a random 16 byte initialisation vector
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))#Creates a cipher using the advanced encryption scheme (AES) with cipher block chaining (CBC)
        encryptor = cipher.encryptor()#Creates an encryptor using the cipher
        encrypted = encryptor.update(paddedData) + encryptor.finalize()#Uses the encryptor to encrypt the padded message
        print(f"Base ciphertext: {encrypted}")
        encrypted += iv#Appends the initialisation vector to the encrypted message
        encrypted += certificate
        print(f"Initial Vector: {iv}\nCertificate: {certificate}\nActual Ciphertext: {encrypted}")
        return encrypted#Returns the encrypted message

    def decrypt(self, ciphertext, key):
        """Given some ciphertext and a key, decrypts the ciphertext and returns plaintext.
        The order of operations is as such:
            -Strip the IV and the MAC
            -Decrypt the ciphertext
            -Verify MAC
            -Strip padding"""
        certificate = ciphertext[-32:]#Slices the ciphertext to retrieve the MAC
        iv = ciphertext[-48:-32]#Slices the ciphertext to retrieve the initialisation vector
        print(f"\n\nBeginning Decryption...\n\nPassed ciphertext: {ciphertext}")
        messageSize = len(ciphertext)-48#Determines the size of the encrypted message without the IV and MAC
        ciphertext = ciphertext[0:messageSize]#Slices the ciphertext to retrieve just the encrypted message
        print(f"Actual Ciphertext: {ciphertext}") 
        print(f"Initial Vector: {iv}")
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))#Recreates the cipher that was used to encrypt the message
        decryptor = cipher.decryptor()#Creates a decryptor using the cipher
        paddedPlaintext = decryptor.update(ciphertext) + decryptor.finalize()#Decrypts the ciphertext
        print(f"Decryption successful.")
        verified = self.verify_mac(key, paddedPlaintext, certificate)
        if verified == True:
            unpadder = padding.PKCS7(128).unpadder()#Creates an unpadder object
            plaintext = unpadder.update(paddedPlaintext) + unpadder.finalize()#Removes the padding from the message
            plaintext = plaintext.decode("utf-8")#Converts the message from a bytestring to a string
            print(f"Plaintext: {plaintext}")
            return plaintext#Returns the decrypted message
        else:
            return "ERROR: Invalid certificate was passed."

    def generate_mac(self, message, key):
        h = hmac.HMAC(key, hashes.SHA256())#Creates an HMAC object using the established hybrid key and SHA256
        h.update(message)#Updates the HMAC object with the message
        certificate = h.finalize()#Creates the final MAC using the HMAC object
        return certificate#Returns the certificate of the plaintext

    def verify_mac(self, key, message, certificate):
        try:
            print(f"Certificate: {certificate}")
            h = hmac.HMAC(key, hashes.SHA256())#Creates an HMAC object using the established hybrid key and SHA256
            h.update(message)#Updates the HMAC object with the message
            h.verify(certificate)#Verifies the passed certificate with the HMAC object
            return True
        except Exception as e:
            print(f"Error: {e}")
            return False

    def serialize(self, x):
        """Given some input, returns a serialized version using PEM."""
        return x.public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    
    def serialize_private(self, x):
        """Given some input, returns a serialized version using PEM."""
        return x.private_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
            )
    
    def deserialize(self, x):
        """Given some PEM serialized input, returns a deserialized version."""
        return serialization.load_pem_public_key(x, default_backend())
    
    def deserialize_private(self, x):
        """Given some PEM serialized input, returns a deserialized version."""
        return serialization.load_pem_private_key(x, None, default_backend())
    