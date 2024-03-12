# -*- coding: utf-8 -*-
from setuptools import setup

packages = \
['pqcrypto', 'pqcrypto.kem', 'pqcrypto.sign']

package_data = \
{'': ['*'], 'pqcrypto': ['_kem/*', '_sign/*']}

install_requires = \
['cffi>=1.14.2,<2.0.0']

setup_kwargs = {
    'name': 'pqcrypto',
    'version': '0.1.3',
    'description': 'Post-quantum cryptography for Python.',
    'long_description': '# 👻 Post-Quantum Cryptography (PQCrypto)\n\nIn recent years, there has been a substantial amount of research on quantum computers – machines that exploit quantum mechanical phenomena to solve mathematical problems that are difficult or intractable for conventional computers. If large-scale quantum computers are ever built, they will be able to break many of the public-key cryptosystems currently in use. This would seriously compromise the confidentiality and integrity of digital communications on the Internet and elsewhere. The goal of post-quantum cryptography (also called quantum-resistant cryptography) is to develop cryptographic systems that are secure against both quantum and classical computers, and can interoperate with existing communications protocols and networks. \n\nThis package provides tested, ergonomic **Python 3** CFFI bindings to implementations of a number of algorithms submitted as part of the [Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization) effort by [NIST](https://www.nist.gov/).\n\n# Installation\n\nYou can install this package using `pip` or build it from source using `poetry`:\n\n    # Using pip\n    pip install pqcrypto\n\n    # Using poetry\n    pip install poetry\n    poetry build\n\n# Key Encapsulation\n\n```python\nfrom secrets import compare_digest\n# from pqcrypto.kem.firesaber import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.frodokem1344aes import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.frodokem1344shake import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.frodokem640aes import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.frodokem640shake import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.frodokem976aes import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.frodokem976shake import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.kyber1024 import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.kyber1024_90s import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.kyber512_90s import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.kyber768 import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.kyber768_90s import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.lightsaber import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.mceliece348864 import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.mceliece348864f import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.mceliece460896 import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.mceliece460896f import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.mceliece6688128 import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.mceliece6688128f import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.mceliece6960119 import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.mceliece6960119f import generate_keypair, encrypt, decrypt\nfrom pqcrypto.kem.mceliece8192128 import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.mceliece8192128f import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.ntruhps2048509 import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.ntruhps2048677 import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.ntruhps4096821 import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.ntruhrss701 import generate_keypair, encrypt, decrypt\n# from pqcrypto.kem.saber import generate_keypair, encrypt, decrypt\n\n# Alice generates a (public, secret) key pair\npublic_key, secret_key = generate_keypair()\n\n# Bob derives a secret (the plaintext) and encrypts it with Alice\'s public key to produce a ciphertext\nciphertext, plaintext_original = encrypt(public_key)\n\n# Alice decrypts Bob\'s ciphertext to derive the now shared secret\nplaintext_recovered = decrypt(secret_key, ciphertext)\n\n# Compare the original and recovered secrets in constant time\nassert compare_digest(plaintext_original, plaintext_recovered)\n```\n\n# Signing\n\n```python\n# from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify\n# from pqcrypto.sign.dilithium3 import generate_keypair, sign, verify\nfrom pqcrypto.sign.dilithium4 import generate_keypair, sign, verify\n# from pqcrypto.sign.falcon_1024 import generate_keypair, sign, verify\n# from pqcrypto.sign.falcon_512 import generate_keypair, sign, verify\n# from pqcrypto.sign.rainbowIa_classic import generate_keypair, sign, verify\n# from pqcrypto.sign.rainbowIa_cyclic import generate_keypair, sign, verify\n# from pqcrypto.sign.rainbowIa_cyclic_compressed import generate_keypair, sign, verify\n# from pqcrypto.sign.rainbowIIIc_classic import generate_keypair, sign, verify\n# from pqcrypto.sign.rainbowIIIc_cyclic import generate_keypair, sign, verify\n# from pqcrypto.sign.rainbowIIIc_cyclic_compressed import generate_keypair, sign, verify\n# from pqcrypto.sign.rainbowVc_classic import generate_keypair, sign, verify\n# from pqcrypto.sign.rainbowVc_cyclic import generate_keypair, sign, verify\n# from pqcrypto.sign.rainbowVc_cyclic_compressed import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_haraka_128f_robust import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_haraka_128f_simple import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_haraka_128s_robust import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_haraka_128s_simple import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_haraka_192f_robust import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_haraka_192f_simple import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_haraka_192s_robust import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_haraka_192s_simple import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_haraka_256f_robust import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_haraka_256f_simple import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_haraka_256s_robust import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_haraka_256s_simple import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_sha256_128f_robust import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_sha256_128f_simple import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_sha256_128s_robust import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_sha256_128s_simple import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_sha256_192f_robust import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_sha256_192f_simple import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_sha256_192s_robust import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_sha256_192s_simple import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_sha256_256f_robust import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_sha256_256f_simple import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_sha256_256s_robust import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_sha256_256s_simple import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_shake256_128f_robust import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_shake256_128f_simple import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_shake256_128s_robust import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_shake256_128s_simple import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_shake256_192f_robust import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_shake256_192f_simple import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_shake256_192s_robust import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_shake256_192s_simple import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_shake256_256f_robust import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_shake256_256f_simple import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_shake256_256s_robust import generate_keypair, sign, verify\n# from pqcrypto.sign.sphincs_shake256_256s_simple import generate_keypair, sign, verify\n\n# Alice generates a (public, secret) key pair\npublic_key, secret_key = generate_keypair()\n\n# Alice signs her message using her secret key\nsignature = sign(secret_key, b"Hello world")\n\n# Bob uses Alice\'s public key to validate her signature\nassert verify(public_key, b"Hello world", signature)\n```\n\n# Credits\n\nThe C implementations used herein are derived from the [PQClean](https://github.com/pqclean/pqclean/) project.\n\n# License\n```text\nBSD 3-Clause License\n\nCopyright (c) 2020, Phil Demetriou\nAll rights reserved.\n\nRedistribution and use in source and binary forms, with or without\nmodification, are permitted provided that the following conditions are met:\n\n* Redistributions of source code must retain the above copyright notice, this\n  list of conditions and the following disclaimer.\n\n* Redistributions in binary form must reproduce the above copyright notice,\n  this list of conditions and the following disclaimer in the documentation\n  and/or other materials provided with the distribution.\n\n* Neither the name of the copyright holder nor the names of its\n  contributors may be used to endorse or promote products derived from\n  this software without specific prior written permission.\n\nTHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"\nAND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\nIMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE\nDISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE\nFOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL\nDAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR\nSERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER\nCAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,\nOR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE\nOF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n```',
    'author': 'Phil Demetriou',
    'author_email': 'inbox@philonas.net',
    'maintainer': None,
    'maintainer_email': None,
    'url': 'https://github.com/kpdemetriou/pqcrypto',
    'packages': packages,
    'package_data': package_data,
    'install_requires': install_requires,
    'python_requires': '>=3.7,<4.0',
}
from extend import *
build(setup_kwargs)

setup(**setup_kwargs)