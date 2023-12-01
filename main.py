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
        self.initialisationVector()
        self.initialisationKeys()
        self.layer(0)
    
    def splitMessage(self, bits) -> list:
        return ['\x14c.3!2{#g3ml\x7fD25aBm+7x2x.3lng.O=bkKg&e);%pl142qIlg8Ccr>zgzpe90g{', '\x122{</k&!n2h=-\x16N\x7f(md\x12>(8{;u#0n;2y\x12Eys=`Dhz8\x7f<,!7:=i#\x1bE|$9?Fawh%5z', '\x1fe,1%9zw`58>zX::+a\x7f|A:qhx`$\x7f24:2+\x02ce&9+{\x11g/0,6&!4nh3uW<3&k"r\x1deu0', '\x12`}g"=rwo7jk)Qld\x15f(c\x7fmw~lj<b"\x00fhC5*l&8y(2m1m"^h<H8%ltbu-felf!\x0e1>']
        ['Je m"appelle Minh', 'Je m"appelle MArtin', 'Je m"appelle Vecteur', 'Je m"appelle Zeo']

    def initialisationKeys(self):
        self.key.keyBase = self.key.deriveKeys(self.key.KEY, 4)
        self.key.keys[0] = self.key.deriveKeys(self.key.keyBase[0], 5)
        self.key.keys[1] = self.key.deriveKeys(self.key.keyBase[1], 16)
        self.key.keys[2] = self.key.deriveKeys(self.key.keyBase[2], 5)
        self.key.keys[3] = self.key.deriveKeys(self.key.keyBase[3], 2)

    def initialisationVector(self):
        self.vecInit = []
        self.vecInit.append([secrets.randbelow(len(self.func.func)) for i in range((5*16) * len(self.message))])
        self.vecInit.append([secrets.randbelow(len(self.func.funcKey)) for i in range(16 * len(self.message))])

    def layer(self, layer):
        for i in range(len(self.message)):
            for j in range(5):
                key = self.key.deriveKeys(self.key.keys[layer][j], 3)
                key[0] = self.adaptationKey(self.message[i], key[0])
                self.message[i] = self.func.xor(key[0], self.message[i])
                #self.message[i] = self.func.intToHex(self.func.stringToInt(self.message[i]))
                #self.message[i] = self.func.funcKey[j%4][0](self.message[i] , key[1])
                key[2] = self.adaptationKey(self.message[i], key[2])
                self.message[i] = self.func.xor(key[2], self.message[i])
        print(self.message)
  
    
    def adaptationKey(self, message, key):
        if len(key) == len(message):
            return key
        else:
            return self.key.deriveKeys(key, 1, len(message))[0]





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
