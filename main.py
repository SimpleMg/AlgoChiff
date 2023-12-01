import random
import hashlib
import secrets
import base64
from argparse import ArgumentParser

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend



class Encrypt:
    def __init__(self, KEY, message):
        self.key = Key(KEY)
        self.func = allFunc()
        self.message = self.splitMessage(message)
        print("Message",self.message)
        self.initialisationVector()
        self.initialisationKeys()
        self.layer(0)
    
    def splitMessage(self, bits) -> list:

        return [self.func.intToHex(self.func.stringToInt('Je m"appelle Minh')), self.func.intToHex(self.func.stringToInt('Je m"appelle MArtin')), self.func.intToHex(self.func.stringToInt('Je m"appelle Vecteur')), self.func.intToHex(self.func.stringToInt('Je m"appelle Zeo'))]

    def initialisationKeys(self):
        self.key.keyBase = self.key.deriveKeys(self.key.KEY, 4)
        self.key.keys[0] = self.key.deriveKeys(self.key.keyBase[0], 5 * len(self.message))
        self.key.keys[1] = self.key.deriveKeys(self.key.keyBase[1], 16 * len(self.message))
        self.key.keys[2] = self.key.deriveKeys(self.key.keyBase[2], 5 * len(self.message))
        self.key.keys[3] = self.key.deriveKeys(self.key.keyBase[3], 2)

    def initialisationVector(self):
        self.vecInit = []
        self.vecInit.append([secrets.randbelow(len(self.func.func)) for i in range((5*16) * len(self.message))])
        self.vecInit.append([secrets.randbelow(len(self.func.funcKey)) for i in range(16 * len(self.message))])

    def layer(self, layer):
        for i in range(len(self.message)):
            for j in range(5):
                key = self.key.deriveKeys(self.key.keys[layer][j + i * 5], 3)
                self.message[i] = self.func.xor(key[0], self.message[i])
                self.message[i] = self.func.funcKey[j%len(self.func.funcKey)][0](self.message[i], key[1])
                self.message[i] = self.func.xor(key[2], self.message[i])

        print("Résultat Chiffrement",self.message)
        b = Decrypt("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", self.message)
    
    def mainLoop(self):
        for i in range(len(self.message)):
            for j in range(16):
                key = self.key.deriveKeys(self.key.keys[1][j], 3)
                self.message[i] = self.func.xor(key[0], self.message[i])
                for k in range(5):
                    self.func.func[self.vecInit[0][j*5 + k + i * 16 * 5]]
    
    def adaptationKey(self, message, key):
        if len(key) == len(message):
            return key
        else:
            return self.key.deriveKeys(key, 1, len(message))[0]



class Decrypt:
    def __init__(self, KEY, message):
        self.key = Key(KEY)
        self.func = allFunc()
        self.message = message
        self.initialisationKeys()
        self.layer(0)
    
    def initialisationKeys(self):
        self.key.keyBase = self.key.deriveKeys(self.key.KEY, 4)
        self.key.keys[0] = self.key.deriveKeys(self.key.keyBase[0], 5 * len(self.message))
        self.key.keys[1] = self.key.deriveKeys(self.key.keyBase[1], 16 * len(self.message))
        self.key.keys[2] = self.key.deriveKeys(self.key.keyBase[2], 5 * len(self.message))
        self.key.keys[3] = self.key.deriveKeys(self.key.keyBase[3], 2)
    
    def layer(self, layer):
        for i in range(1, len(self.message) + 1):
            for j in range(1, 6):
                key = self.key.deriveKeys(self.key.keys[layer][-(j + (i - 1) * 5)], 3)
                self.message[-i] = self.func.xor(key[2], self.message[-i])
                self.message[-i] = self.func.funcKeyDecode[(j-1)%len(self.func.funcKeyDecode)][0](self.message[-i] , key[1])
                self.message[-i] = self.func.xor(key[0], self.message[-i])
        print("Résultat Dechiffrement", self.message) 
    
    def adaptationKey(self, message, key):
        if len(key) == len(message):
            return key
        else:
            return self.key.deriveKeys(key, 1, len(message))[0]






a = Encrypt("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", "Message pour test")






'''

def argument() -> None:
    argParser = ArgumentParser()
    argParser.add_argument("-f", "--file", help="File with message")
    argParser.add_argument("-k", "--key", help="Encryption key")
    argParser.add_argument("-m", "--mode", help="Encrypt (E) / Decrypt (D)")
    args = argParser.parse_args()
    assert args.key, "Miss the KEY (512 bits) with --key <key>"
    KEY = Key(args.key)
    assert args.file, "Miss file path with --file <path>"
    message = open(args.file, 'r').read()
    mode = 1 if args.mode == 'D' else 0


if __name__ == '__main__':
    print(argument())

'''
