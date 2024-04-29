"""
////////////////////////////////////////////////////////////////////////////////////////
This is the main file for my dissertation project. This creates a server object and a client
object and runs them both simulataneously. The connection between both nodes is encrypted 
against attacks from a post-quantum adversary.

Dissertation Title: An Analysis Of Post-Quantum Cryptographic Schemes For Real World Use
Author: Jude Gibson
Supervisor: Bhagya Wimalasiri
Date Created: 13/02/2024
////////////////////////////////////////////////////////////////////////////////////////
"""

from Server import *
from Client import *

for run in range(25):
    Server('KYBER', 'SPHINCS', run)

