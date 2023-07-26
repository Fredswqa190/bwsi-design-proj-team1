import os
import hashlib
from Crypto.PublicKey import ECC
from chacha20poly1305 import ChaCha20Poly1305
"""
key = ECC.generate(curve='P-256')
print(key)
"""
key = os.urandom(32)

cip = ChaCha20Poly1305(key)

with open('firmware/gcc/main.bin', 'rb') as fp:
    firmware = fp.read()

nonce = os.urandom(12)
ciphertext = cip.encrypt(nonce, firmware)

plaintext = cip.decrypt(nonce, ciphertext)

print(plaintext)