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
        self.func = {0: self.binary_inversion, 1: self.binary_switch, 2: self.binary_conversion, 3: self.reverseOneTwo, 4: self.reverseString, 5: self.iteration}
        self.funcKey = {0: self.matriceMelange, 1: self.messageToListToMelange}
        self.funcKeyDecode = {0: self.matriceMelange_decode, 1: self.messageToListToMelange_decode}

    def xor(self, input_hex1, input_hex2, zero=True):
        int1 = int(input_hex1, 16)
        int2 = int(input_hex2, 16)
        result_int = int1 ^ int2
        result_hex = format(result_int, 'x')
        if len(result_hex)%2 != 0 and zero:
            result_hex = "0" + result_hex
        return result_hex

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
        decimal = int(hexa, 16)
        return  bin(decimal)[2:]

    def binToHex(self, binaire):
        decimal = int(binaire, 2)
        return hex(decimal)[2:]
    
    def binToInt(self, binary):
        return int(binary, 2)

    def intToBin(self, number):
        return bin(int(number))[2:]

    #Fonction de chiffrement
    #sans clef de chiffrement
    def binary_inversion(self, hexa, decode=False):
        if hexa[0] == "0": hexa = hexa[1:]
        if decode:
            bin = self.intToBin(self.hexToInt(hexa[:-8]))
            diff = self.hexToInt(hexa[-8:])
        else: 
            bin = self.intToBin(self.hexToInt(hexa))
            diff = 0
        if diff != 0:
            for i in range(int(diff)):
                bin = "0" + bin
        res = ''.join('0' if c == '1' else '1' for c in bin)
        diff = len(bin) - len(self.intToBin(self.binToInt(res)))
        if decode == False: res = self.intToHex(self.binToInt(res)) + self.intToHex(diff).zfill(8) 
        else: res = self.intToHex(self.binToInt(res))
        return res if len(res)%2 == 0 else "0" + res
    
    def binary_inversion_decode(self, hexa):
        return self.binary_inversion(hexa, True)
    
    def binary_switch(self, hexa):
        bin = self.intToBin(self.hexToInt(hexa))
        res = ""
        for i in range((len(bin)-1)):
            if bin[i+1] == '1': 
                res += self.binary_inversion(self.intToHex(self.binToInt(bin[i])))[1:2]
            else: 
                res += bin[i]
        res = res+bin[-1]
        if len(self.intToBin(self.binToInt(res))) != len(bin):
            diff = len(bin)-len(self.intToBin(self.binToInt(res)))
        else:
            diff = 0
        res = self.intToHex(self.binToInt(res)) + self.intToHex(diff).zfill(8)
        return res if len(res)%2 == 0 else "0" + res

    def binary_switch_decode(self, hexa):
        bin = self.intToBin(self.hexToInt(hexa[:-8]))
        diff = self.hexToInt(hexa[-8:])
        if diff != 0: 
            for i in range(int(diff)):
                bin = "0" + bin
        last = decode = bin[-1]
        for i in range(2, len(bin)+1):
            if last == "1":
                decode = self.binary_inversion(self.intToHex(self.binToInt(bin[-i])))[1:2] + decode
                last = self.binary_inversion(self.intToHex(self.binToInt(bin[-i])))[1:2]
            else:
                decode = bin[-i] + decode
                last = bin[-i]
        res = self.intToHex(self.binToInt(decode))
        return res if len(res)%2 == 0 else "0" + res
    
    def binary_conversion(self, binary):
        res = ''
        binary = binary.replace('01', '0|1').replace('10', '1|0').split('|')
        if binary[0][0] != '0':res += '000'
        for i in range(len(binary)):
            lenBinary = len(binary[i])
            res += ''.join(['999000' * (lenBinary // 999), str(lenBinary % 999).zfill(3)])
        return res
    
    def binary_conversion_decode(text: str):
        return ''.join(str(idx % 2) * int(chunk) for idx, chunk in enumerate([text[i:i+3] for i in range(0, len(text), 3)]))
    
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
    
    def iteration(self, hexa):
        iterationLst = []
        for i in range(len(hexa)):
            toIterate = ""
            for j in range(len(hexa)):
                toIterate += hexa[(j+i)%len(hexa)]
            iterationLst.append(toIterate)
        iterationLst.sort()
        idx = iterationLst.index(hexa)
        sep = "a4d2"
        return(str(idx) + sep + iterationLst[-1])
    
    def iteration_decode(self, text):
        idx = ""
        sep = text.find("a4d2")
        idx = text[:sep]
        text = text[sep+4:]
        iterationLst = []
        for i in range(len(text)):
            toIterate = ""
            for j in range(len(text)):
                toIterate += text[(j+i)%len(text)]
            iterationLst.append(toIterate)
        iterationLst.sort()
        return(iterationLst[int(idx)])

    #Avec clef de Chiffrement
    def matriceMelange(self, hexa, KEY):
        hexaForm = [format(i, '02x') for i in range(256)]
        random.seed(KEY)
        random.shuffle(hexaForm)
        matrice = [hexaForm[i:i+16] for i in range(0, 256, 16)]
        return ''.join(matrice[int(hexa[i], 16)][int(hexa[i + 1], 16)] for i in range(0, len(hexa), 2))
    
    def matriceMelange_decode(self, hexa, KEY):
        hexaForm = [format(i, '02x') for i in range(256)]
        random.seed(KEY)
        random.shuffle(hexaForm)
        matrice = [hexaForm[i:i+16] for i in range(0, 256, 16)] 
        res = ''
        for k in range(0, len(hexa), 2):
            idx = [(i, j) for i, row in enumerate(matrice) for j, val in enumerate(row) if val == hexa[k]+hexa[k+1]][0]
            res += hex(idx[0])[-1:] + hex(idx[1])[-1:]
        return res
    
    def messageToListToMelange(self, hexa, KEY):
        assert len(hexa) % 2 == 0, "Not a hexa"
        hexa = [hexa[i:i + 2] for i in range(0, len(hexa), 2)]
        random.seed(KEY)
        [random.shuffle(hexa) for _ in range(random.randint(5, 20))]
        return ''.join(hexa)
    
    def messageToListToMelange_decode(self, hexa, KEY):
        hexa = [hexa[i:i+2] for i in range(0, len(hexa), 2)]
        index = [str(i) for i in range(len(hexa))]
        random.seed(KEY)
        for i in range(random.randint(5, 20)):
            random.shuffle(index)
        res = [None for _ in range(len(hexa))]
        for idx, v in enumerate(index):
            res[int(v)] = hexa[idx]
        return ''.join(res)
    
    def multMatrice(self, hexa, KEY):
        mtcHexa = []
        hexaLst = []
        mtcSizeLine = math.ceil(math.sqrt(len(hexa)/2))
        mtcSize = pow(mtcSizeLine, 2)
        hexa = hexa.zfill(mtcSize*2)
        for i in range(len(hexa)):
            if i%2 == 0:
                hexaLst.append(hexa[i] + hexa[i+1])
        for i in range(mtcSize):
            mtcLine = []
            if i%mtcSizeLine == 0:
                j = 0
                while j < mtcSizeLine:
                    mtcLine.append(hexaLst[i+j])
                    j += 1
                mtcHexa.append(mtcLine)
        mtcMultHexa = [format(i, '02x') for i in range(mtcSize)]
        random.seed(KEY)
        random.shuffle(mtcMultHexa)
        mtcMult = [mtcMultHexa[i:i+mtcSizeLine] for i in range(0, mtcSize, mtcSizeLine)]
        for i in range(len(mtcMult)):
            for j in range(len(mtcMult[i])):
                mtcMult[i][j] = int(mtcMult[i][j], base=16)
        for i in range(len(mtcHexa)):
            for j in range(len(mtcHexa[i])):
                mtcHexa[i][j] = int(mtcHexa[i][j], base=16)
        mtcMultNumpy = numpy.array(mtcMult)
        mtchexaNumpy = numpy.array(mtcHexa)
        mtcResult = numpy.dot(mtcMultNumpy,mtchexaNumpy)
        mtcResult = list(mtcResult)
        for i in range(len(mtcResult)):
            mtcResult[i] = list(mtcResult[i])
        for i in range(len(mtcResult)):
            for j in range(len(mtcResult[i])):
                mtcResult[i][j] = hex(mtcResult[i][j].item())
                mtcResult[i][j] = mtcResult[i][j][2:].zfill(6)
        result = ""
        for i in range(len(mtcResult)):
            for j in range(len(mtcResult[i])):
                result += mtcResult[i][j]
        return result
    
    def multMatrice_decode(self, hexa, KEY):
        toDecodeTbl = []
        toDecodeMtc = []
        for i in range(len(hexa)):
            if i%6 == 0:
                toDecodeTbl.append(hexa[i] + hexa[i+1] + hexa[i+2] + hexa[i+3] + hexa[i+4] + hexa[i+5])
        mtcSizeLine = math.sqrt(len(toDecodeTbl))
        for i in range(len(toDecodeTbl)):
            mtcLine = []
            if i%mtcSizeLine == 0:
                j = 0
                while j < mtcSizeLine:
                    mtcLine.append(toDecodeTbl[i+j])
                    j += 1
                toDecodeMtc.append(mtcLine)
        mtcSize = pow(len(toDecodeMtc), 2)
        mtcDivHexa = [format(i, '02x') for i in range(mtcSize)]
        random.seed(KEY)
        random.shuffle(mtcDivHexa)
        mtcDiv = [mtcDivHexa[i:i+int(mtcSizeLine)] for i in range(0, mtcSize, int(mtcSizeLine))]
        for i in range(len(toDecodeMtc)):
            for j in range(len(toDecodeMtc[i])):
                toDecodeMtc[i][j] = int(toDecodeMtc[i][j], base=16)
        for i in range(len(mtcDiv)):
            for j in range(len(mtcDiv[i])):
                mtcDiv[i][j] = int(mtcDiv[i][j], base=16)
        toDecodeMtcNumpy = numpy.array(toDecodeMtc)
        mtcDivNumpy = numpy.array(mtcDiv)
        mtcDivNumpyInverse = numpy.linalg.inv(mtcDivNumpy)
        mtcResultNumpy = numpy.dot(mtcDivNumpyInverse, toDecodeMtcNumpy)
        mtcResult = list(mtcResultNumpy)
        for i in range(len(mtcResult)):
            mtcResult[i] = list(mtcResult[i])
        for i in range(len(mtcResult)):
            for j in range(len(mtcResult[i])):
                mtcResult[i][j] = hex(round(mtcResult[i][j]))
                mtcResult[i][j] = mtcResult[i][j][2:]
        result = ""
        for i in range(len(mtcResult)):
            for j in range(len(mtcResult[i])):
                result += mtcResult[i][j]
        result = result.lstrip("0")
        if len(result)%2 != 0:
            result = "0" + result
        return result
    
class Encrypt:
    def __init__(self, KEY, message):
        self.key = Key(KEY)
        self.func = allFunc()
        self.message = self.splitMessage(message)
        print("Message",self.message)
        self.initialisationVector()
        self.initialisationKeys()
        self.layer(0)
        #self.mainLoop()


    
    def splitMessage(self, message) -> list:
        hexa = self.func.intToHex(self.func.stringToInt(message))
        return [hexa[i:i+32] for i in range(0, len(hexa), 32)]

    def initialisationKeys(self):
        self.key.keyBase = self.key.deriveKeys(self.key.KEY, 4)
        self.key.keys[3] = self.key.deriveKeys(self.key.keyBase[3], 2)

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
        print("Résultat Chiffrement",self.message)

        b = Decrypt("4fc9ce8d6459781b09d0b83f69692868dc86035b11f36e47fa552a0267323a21be3c1066fc58e3068dda830f1b142275818c83d87ff59081118de5408d67b629", self.message)

    def mainLoop(self):
        self.key.keys[1] = self.key.deriveKeys(self.key.keyBase[1], 16 * len(self.message))
        for i in range(len(self.message)):
            for j in range(16):
                key = self.key.deriveKeys(self.key.keys[1][j], 3)
                self.message[i] = self.func.xor(key[0], self.message[i])
                for k in range(5):
                    self.message[i] = self.func.func[self.vecInit[0][j*5 + k + i * 16 * 5]](self.message[i])
                self.message[i] = self.func.funcKey[self.vecInit[1][i]](self.message[i], key[1])
                self.message[i] = self.func.xor(key[2], self.message[i])
        
        print("Résultat Chiffrement",self.message)
        #b = Decrypt("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", self.message)
    
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
        print(self.key.keyBase)
        print(self.key.keys)
        self.layer(0)
    
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
        print("Résultat Dechiffrement", self.func.intToString(self.func.hexToInt(self.message)))
    
    def mainLoop(self):
        self.key.keys[1] = self.key.deriveKeys(self.key.keyBase[1], 16 * len(self.message))
    
    def mainLoop(self):
        self.key.keys[1] = self.key.deriveKeys(self.key.keyBase[1], 16 * len(self.message))
        for i in range(len(self.message)):
            for j in range(16):
                key = self.key.deriveKeys(self.key.keys[1][j], 3)
                self.message[i] = self.func.xor(key[0], self.message[i])
                for k in range(5):
                    self.message[i] = self.func.func[self.vecInit[0][j*5 + k + i * 16 * 5]](self.message[i])
                self.message[i] = self.func.funcKey[self.vecInit[1][i]](self.message[i], key[1])
                self.message[i] = self.func.xor(key[2], self.message[i])

    def adaptationKey(self, message, key):
        if len(key) == len(message):
            return key
        else:
            return self.key.deriveKeys(key, 1, len(message))[0]

toEncrypt = Encrypt("4fc9ce8d6459781b09d0b83f69692868dc86035b11f36e47fa552a0267323a21be3c1066fc58e3068dda830f1b142275818c83d87ff59081118de5408d67b629", "zizi")
                    

"""print("1) Chiffrement\n2) Déchiffrement")
choice = input("Que voulez vous faire (1/2): ")

if choice == "1":
    key = input("Entrez la clef: ")
    #"4fc9ce8d6459781b09d0b83f69692868dc86035b11f36e47fa552a0267323a21be3c1066fc58e3068dda830f1b142275818c83d87ff59081118de5408d67b629"
    toEncrypt = input("Entrez la chaine à Chiffrer: ")

    toEncrypt = Encrypt(key, toEncrypt)

elif choice == "2":
    key = input("Entrez la clef: ")
    #"ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"
    toDecrypt = input("Entrez la chaine à déchifrer: ")

    toEncrypt = Decrypt(key, toDecrypt)"""





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
