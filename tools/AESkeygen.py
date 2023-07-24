import os
import hashlib
from Crypto.PublicKey import ECC
from chacha20poly1305 import ChaCha20Poly1305

key = ECC.generate(curve='P-256')
print(key)



cip = ChaCha20Poly1305(key)

nonce = os.urandom(12)
ciphertext = cip.encrypt(nonce, b'hello world')

plaintext = cip.decrypt(nonce, ciphertext)

print(plaintext)