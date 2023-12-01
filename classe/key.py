import random
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


class Key:
    def __init__(self, key):
        self.KEY = key
        self.keyBase = []
        self.keys = [[], [], [], []]
    
    def deriveKeys(self, key, numKeys, exit=32):
        master_key_bytes = key.encode('utf-8')
        random.seed(hashlib.sha256(key.encode('utf-8')).hexdigest())
        salt = random.randbytes(256)
        return [hashlib.sha256(HKDF(algorithm=hashes.SHA256(), length=exit, salt=salt, info=str(i).encode('utf-8'), backend=default_backend()).derive(master_key_bytes).hex().encode('utf-8')).hexdigest() for i in range(numKeys)]





a = Key("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff")
b = a.derive_keys(a.KEY, 10)
print(b)
print(b[0])
c = 'abcdfghtuyielrkznghzfgrhdgcgdbfv'
print(c.encode('utf-8'))
resultat_xor = 
print(resultat_xor)
resultat_xor = 
print(resultat_xor)
