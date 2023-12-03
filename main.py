import random
import hashlib
import secrets
import numpy
import math
import base64
from argparse import ArgumentParser

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

class allFunc:
    def __init__(self):
        self.func = {0: self.binary_inversion, 1: self.binary_switch, 2: self.substitute_hex, 3: self.reverseOneTwo, 4: self.reverseString}
        self.funcKey = {0: self.matriceMelange, 1: self.messageToListToMelange}
        # self.funcKey = {0: self.matriceMelange, 1: self.messageToListToMelange}
        self.funcDecode = {0: self.binary_inversion, 1: self.binary_switch_decode, 2: self.substitute_hex_decode, 3: self.reverseOneTwo, 4: self.reverseString}
        self.funcKeyDecode = {0: self.matriceMelange_decode, 1: self.messageToListToMelange_decode}
        # self.funcKeyDecode = {0: self.matriceMelange_decode, 1: self.messageToListToMelange_decode}

    def xor(self, key, msg):
        if len(key) > len(msg):
            key = key[:(len(msg))]
        elif len(key) < len(msg):
            while len(key) < len(msg):
                key += key
            key = key[:(len(msg))]
        assert len(key) == len(msg), "xor: msg and key have not the same len"
        a = self.hexToBin(key)
        b = self.hexToBin(msg)
        res = ''
        for i in range(len(a)):
            res += str(int(a[i]) ^ int(b[i]))
        return self.binToHex(res)

    #Fonction de conversion
    def stringToInt(self, text):
        res = [str(ord(i)).zfill(len(str(max([ord(c) for c in text])))) for i in text]
        return str(len(res[0])) + ''.join(res)

    def intToString(self, text):
        length = int(text[0])
        numbers = [text[i:i+length] for i in range(1, len(text), length)]
        return ''.join(chr(int(num)) for num in numbers)

    def intToHex(self, number):
        number = int(number)
        res = ""
        while number > 0:
            number, remainder = divmod(number, 16)
            res = "0123456789abcdef"[remainder] + res
        return res if res else "0"

    def hexToInt(self, hexa):
        return str(sum(int(char, 16) * (16 ** i) for i, char in enumerate(hexa[::-1])))

    def hexToBin(self, hexa):
        res = ''
        for i in hexa:
            res += bin(int(i, 16))[2:].zfill(4)
        return  res

    def binToHex(self, hexa):
        return ''.join([hex(int(hexa[i:i+4], 2))[2:] for i in range(0, len(hexa), 4)])
    
    def binToInt(self, binary):
        return int(binary, 2)

    def intToBin(self, number):
        return bin(int(number))[2:]

    #Fonction de chiffrement
    #sans clef de chiffrement
    def binary_inversion(self, hexa):
        binary = self.hexToBin(hexa)
        res = ''
        for i in binary:
            res += '0' if i == '1' else '1'
        hexa = self.binToHex(res)
        return hexa
    
    def binary_switch(self, hexa):
        binary = self.hexToBin(hexa)
        res =""
        for i in range(len(binary)-1):
            if binary[i+1] == "1":
                res += '0' if binary[i] == '1' else '1'
            else:
                res += binary[i]
        res = res + binary[-1]
        return self.binToHex(res)

    def binary_switch_decode(self, hexa):
        binary = self.hexToBin(hexa)
        for i in range(2, len(binary)+1):
            if binary[-i+1] == "1":
                binary = binary[0:-i] + ('0' if binary[-i] == '1' else '1') + binary[len(binary)-i+1:len(binary)] 
        return self.binToHex(binary)
    
    def substitute_hex(self, hex_input):
        hex_input = hex_input
        substituted_hex = ''.join('{:X}'.format(15 - int(c, 16)) for c in hex_input)
        return substituted_hex.lower()
    
    def substitute_hex_decode(self, substituted_hex):
        substituted_hex = substituted_hex
        original_hex = ''.join('{:X}'.format(15 - int(c, 16)) for c in substituted_hex)
        return original_hex.lower()
    
    def reverseOneTwo(self, hexa):
        hexa = list(hexa)
        for i in range(len(hexa) - 1):
            if i % 2 == 0:
                charIndiceSave = hexa[i]
                hexa[i] = hexa[i + 1]
                hexa[i + 1] = charIndiceSave
        return ''.join(hexa)
    
    def reverseString(self, hexa):
        return hexa[::-1]

    #Avec clef de Chiffrement
    def matriceMelange(self, hexa, KEY):
        if len(hexa)%2 != 0: 
            hexa = '0' + hexa
            zero = True
        else: zero = False
        hexaForm = [format(i, '02x') for i in range(256)]
        random.seed(KEY)
        random.shuffle(hexaForm)
        matrice = [hexaForm[i:i+16] for i in range(0, 256, 16)]
        res = "".join(matrice[int(hexa[i], 16)][int(hexa[i + 1], 16)] for i in range(0, len(hexa), 2))
        if zero == True: res = "ff" + res
        else: res = "ee" + res
        return res
    
    def matriceMelange_decode(self, hexa, KEY):
        if hexa[:2] == "ff": zero = True
        elif hexa[:2] == "ee": zero = False
        hexaForm = [format(i, '02x') for i in range(256)]
        random.seed(KEY)
        random.shuffle(hexaForm)
        matrice = [hexaForm[i:i+16] for i in range(0, 256, 16)] 
        res = ''
        for k in range(0, len(hexa), 2):
            idx = [(i, j) for i, row in enumerate(matrice) for j, val in enumerate(row) if val == hexa[k]+hexa[k+1]][0]
            res += hex(idx[0])[-1:] + hex(idx[1])[-1:]
        if zero == True: res = res[3:]
        else: res = res[2:]
        return res
    
    def messageToListToMelange(self, hexa, KEY):
        hexa = [i for i in hexa]
        random.seed(KEY)
        [random.shuffle(hexa) for _ in range(random.randint(5, 20))]
        return ''.join(hexa)

    def messageToListToMelange_decode(self, hexa, KEY):
        hexa = [i for i in hexa]
        index = [str(i) for i in range(len(hexa))]
        random.seed(KEY)
        for i in range(random.randint(5, 20)):
            random.shuffle(index)
        res = [None for _ in range(len(hexa))]
        for idx, v in enumerate(index):
            res[int(v)] = hexa[idx]
        return ''.join(res)

class Encrypt:
    def __init__(self, KEY, message):
        self.key = Key(KEY)
        self.func = allFunc()
        self.message = message
        self.splitMessage(True)
        self.initialisationKeys()
        self.initialisationVector()
        self.layer(0)
        self.concatenationMessage()
        self.splitMessage()
        self.initialisationVector()
        self.mainLoop()
        self.concatenationMessage(self.vecInit)
        self.splitMessage()
        self.layer(2)
        self.concatenationMessage()
        #decrypt = Decrypt("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", self.message)
        
        
    def splitMessage(self, first=False):
        if first:
            hexa = self.func.intToHex(self.func.stringToInt(self.message))
            if len(hexa)%2!=0:hexa = '0' + hexa
        else:
            hexa = self.message
        self.message = [hexa[i:i+32] for i in range(0, len(hexa), 32)]

    def initialisationKeys(self):
        self.key.keyBase = self.key.deriveKeys(self.key.KEY, 4)
        self.key.keys[3] = self.key.deriveKeys(self.key.keyBase[3], 2)
    
    def splitMessageReverse(self, first=False):
        if first:
            self.message = self.func.intToString(self.func.hexToInt(''.join(self.message)))
        else:
            self.message = ''.join(self.message)

    def initialisationVector(self):
        self.vecInit = []
        self.vecInit.append([secrets.randbelow(len(self.func.func)) for i in range((5*16) * len(self.message))])
        self.vecInit.append([secrets.randbelow(len(self.func.funcKey)) for i in range(16 * len(self.message))])

    def layer(self, layer):
        self.key.keys[layer] = self.key.deriveKeys(self.key.keyBase[layer], 5 * len(self.message))
        for i in range(len(self.message)):
            for j in range(5):
                key = self.key.deriveKeys(self.key.keys[layer][j + i * 5], 3)
                self.message[i] = self.func.xor(key[0], self.message[i])
                self.message[i] = self.func.funcKey[j%len(self.func.funcKey)](self.message[i], key[1])
                self.message[i] = self.func.xor(key[2], self.message[i])

    def mainLoop(self):
        self.key.keys[1] = self.key.deriveKeys(self.key.keyBase[1], 16 * len(self.message))
        for i in range(len(self.message)):
            for j in range(16):
                key = self.key.deriveKeys(self.key.keys[1][j + i * 16], 3)
                self.message[i] = self.func.xor(key[0], self.message[i])
                for k in range(5):
                    self.message[i] = self.func.func[self.vecInit[0][j*5 + k + i * 16 * 5]](self.message[i])
                self.message[i] = self.func.funcKey[self.vecInit[1][j + i * 16]](self.message[i], key[1])
                self.message[i] = self.func.xor(key[2], self.message[i])
    
    def adaptationKey(self, message, key):
        if len(key) == len(message):
            return key
        else:
            return self.key.deriveKeys(key, 1, len(message))[0]
    
    def concatenationMessage(self, vector=None):
        concat = self.message
        maxLen = len(max(concat, key=len))
        concat = [concat[i].zfill(maxLen) for i in range(len(concat))]
        lenMess = hex(len(self.message))[2:].zfill(4)
        concat = lenMess + "".join(concat)
        if vector:
            vec = ''
            for i in vector[0]:vec += str(i).zfill(2)
            vec += str(len(self.func.func))
            for i in vector[1]:vec += str(i).zfill(2)
        self.message =  concat if not vector else vec + str(len(self.func.func)) + concat

class Decrypt:
    def __init__(self, KEY, message):
        self.key = Key(KEY)
        self.func = allFunc()
        self.message = message
        self.initialisationKeys()
        self.concatenationMessageReverse()
        self.layer(2)
        self.splitMessageReverse()
        self.concatenationMessageReverse(True)
        self.mainLoop()
        self.splitMessageReverse()
        self.concatenationMessageReverse()
        self.layer(0)
        self.splitMessageReverse(True)
        
    def splitMessageReverse(self, first=False):
        if first:
            self.message = self.func.intToString(self.func.hexToInt(''.join(self.message)))
        else:
            self.message = ''.join(self.message)
    
    def initialisationKeys(self):
        self.key.keyBase = self.key.deriveKeys(self.key.KEY, 4)
        self.key.keys[3] = self.key.deriveKeys(self.key.keyBase[3], 2)
    
    def layer(self, layer):
        self.key.keys[layer] = self.key.deriveKeys(self.key.keyBase[layer], 5 * len(self.message))
        for i in range(1, len(self.message) + 1):
            for j in range(1, 6):
                key = self.key.deriveKeys(self.key.keys[layer][-(j + (i - 1) * 5)], 3)
                self.message[-i] = self.func.xor(key[2], self.message[-i])
                self.message[-i] = self.func.funcKeyDecode[(j-1)%len(self.func.funcKeyDecode)](self.message[-i] , key[1])
                self.message[-i] = self.func.xor(key[0], self.message[-i])
    
    def mainLoop(self):
        self.key.keys[1] = self.key.deriveKeys(self.key.keyBase[1], 16 * len(self.message))
        for i in range(1, len(self.message)+1):
            for j in range(1, 17):
                key = self.key.deriveKeys(self.key.keys[1][-(j + (i - 1) * 16)], 3)
                self.message[-i] = self.func.xor(key[2], self.message[-i])
                self.message[-i] = self.func.funcKeyDecode[self.vecInit[1][-(j + (i-1) * 16)]](self.message[-i], key[1])
                for k in range(1, 6):
                    self.message[-i] = self.func.funcDecode[self.vecInit[0][-((j-1)*5 + k + (i-1) * 16 * 5)]](self.message[-i])
                self.message[-i] = self.func.xor(key[0], self.message[-i])


    def adaptationKey(self, message, key):
        if len(key) == len(message):
            return key
        else:
            return self.key.deriveKeys(key, 1, len(message))[0]
    
    def concatenationMessageReverse(self, vector=False):
        vectorlst = []
        if vector:
            spliter = self.message.find(str(len(self.func.func)))
            vectorlst.append(self.message[0:spliter])
            spliter2 = self.message.find(str(len(self.func.func)), spliter + 1)
            vectorlst.append(self.message[spliter+1:spliter2])
            self.message = self.message[spliter2+1:]
            self.vecInit = [[int(vectorlst[0][i:i+2]) for i in range(0, len(vectorlst[0]), 2)], [int(vectorlst[1][i:i+2]) for i in range(0, len(vectorlst[1]), 2)]]
        else:message = [0, 0]
        idx = int(self.message[0:4], 16)
        message = self.message[4:]
        assert len(message)%idx == 0, "Message non divisible"
        sizeMessage = len(message) / idx
        messageLst = [message[i:i+int(sizeMessage)] for i in range(0, len(message), int(sizeMessage))]
        self.message = [chaine.lstrip('0') if len(chaine.lstrip('0'))%2 == 0 else "0" + chaine.lstrip('0') for chaine in messageLst]

# mess = "Mais salope le voila ton message laaaa !"
# KEY = "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"
# encrypt = Encrypt(KEY, mess)
# decrypt =  Decrypt(KEY, encrypt.message)
# print(decrypt.message)


def argument() -> None:
    argParser = ArgumentParser()
    argParser.add_argument("-f", "--file", help="File with message")
    argParser.add_argument("-k", "--key", help="Encryption key")
    argParser.add_argument("-m", "--mode", help="Encrypt (E) / Decrypt (D)")
    args = argParser.parse_args()
    assert args.key, "Miss the KEY (512 bits) with --key <key>"
    KEY = args.key
    assert args.file, "Miss file path with --file <path>"
    message = open(args.file, 'r', encoding="utf-8").read()
    
    mode = 1 if args.mode == 'D' or args.mode == 'Decrypt' else 0
    if mode == 0:
        message = [message[i:i+32] for i in range(0, len(message), 32)]
        for i in range(len(message)):
            message[i] = Encrypt(KEY, message[i])
        file = open('chiff.txt', 'w', encoding="utf-8")
        file.write('|'.join([i.message for i in message]))
    else:
        message = message.split('|')
        for i in range(len(message)):
            message[i] = Decrypt(KEY, message[i])
        file = open('dechi.txt', 'w', encoding="utf-8")
        file.write(''.join([i.message for i in message]))

        


if __name__ == '__main__':
    argument()
