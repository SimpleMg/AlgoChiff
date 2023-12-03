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
    
    def isPrime(self, n):
        return n > 1 and all(n % i != 0 for i in range(2, int(n**0.5) + 1))

    def nextPrimeNumber(self, nombre):
        if nombre < 2:return nombre
        superieur = nombre + 1
        while not self.isPrime(superieur):superieur += 1
        return superieur

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
        if len(hexa)%2 != 0: hexa = '0' + hexa
        hexaForm = [format(i, '02x') for i in range(256)]
        random.seed(KEY)
        random.shuffle(hexaForm)
        matrice = [hexaForm[i:i+16] for i in range(0, 256, 16)]
        return ''.join(matrice[int(hexa[i], 16)][int(hexa[i + 1], 16)] for i in range(0, len(hexa), 2))
    
    def matriceMelange_decode(self, hexa, KEY):
        hexa = ("0" + hexa) if len(hexa)%2 != 0 else hexa
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
        self.message = message
        self.splitMessage(True)
        self.initialisationKeys()
        self.initialisationVector()
        self.layer(0)
        self.concatenationMessage()
        self.splitMessage()
        print(self.message)
        self.initialisationVector()
        self.mainLoop()
        self.concatenationMessage(self.vecInit)
        self.splitMessage()
        self.layer(2)
        #print(self.func.xor("fedf12834c0881b469d5116cbf273aeab2e75bf8386c6c6ccea795e3c61ee5e7d7a9f448d488fd5787912b60fc00c523ff38fdf7f3be0e4c2ad777552b945fb4447e342db24fee30bbafa3be385999817b4edca8b0871ce469f00308119fa86e2e0ae4af27434a1f8f752a6eded5d9d744af376a411d2a38032d8a48c3839f60f95ac4d9c18c9f8cf88c43b2fe1ef39a92db80fb26e01abb088998c35b441d7607d4e9ae9f8a77dda0d496fc08e724f49bee","1862f2909dc48fa8fe6c48be3322787642b4c59e162f5442cdd6020595712b16"))
        b = Decrypt("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", self.message)
        
        
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
            print("\n----------\nI: ", i)
            for j in range(16):
                print("\n     J: ", j)
                key = self.key.deriveKeys(self.key.keys[1][j + i * 16], 3)
                self.message[i] = self.func.xor(key[0], self.message[i])
                for k in range(5):
                    print("\n          K: ", k)
                    print("\n          Fonction de Chiffrement sans Clef:")
                    print("          Fonction numéro: ", self.vecInit[0][j*5 + k + i * 16 * 5])
                    print("          Indice dans le vecteur: ", j*5 + k + i * 16 * 5)
                    print("          Message à chiffrer: ", self.message[i])
                    self.message[i] = self.func.func[self.vecInit[0][j*5 + k + i * 16 * 5]](self.message[i])
                    print("          Message chiffré: ", self.message[i])
                print("\n     Fonction de Chiffrement avec Clef:")
                print("     Fonction numéro: ", self.vecInit[1][j + i * 16])
                print("     Indice dans le vecteur: ", j + i * 16)
                print("     Message à chiffrer: ", self.message[i])
                print("     Clef de chiffrement: ", key[1])
                self.message[i] = self.func.funcKey[self.vecInit[1][j + i * 16]](self.message[i], key[1])
                print("     Résultat chiffré: ", self.message[i])
                self.message[i] = self.func.xor(key[2], self.message[i])
    
    def adaptationKey(self, message, key):
        if len(key) == len(message):
            return key
        else:
            return self.key.deriveKeys(key, 1, len(message))[0]
    
    def concatenationMessage(self, vector=None):
        res = self.message
        lenMax = len(max(res, key=len))
        lenMax = self.func.nextPrimeNumber(lenMax)
        res = [i.zfill(lenMax) for i in res]
        res = str(len(res)) + "".join(res)
        if vector:
            vec = ''
            for i in vector[0]:vec += str(i).zfill(2)
            vec += str(len(self.func.func))
            for i in vector[1]:vec += str(i).zfill(2)
        self.message =  res if not vector else vec + str(len(self.func.func)) + res




class Decrypt:
    def __init__(self, KEY, message):
        self.key = Key(KEY)
        self.func = allFunc()
        self.message = message
        self.initialisationKeys()
        self.layer(2)
        self.splitMessageReverse()
        self.concatenationMessageReverse(True)
        print("\n\n\nDECRIPTAGE EN COUR !!!!!!!!!!!!!!!!!")
        self.mainLoop()
        self.splitMessageReverse()
        self.concatenationMessageReverse()
        self.layer(0)
        print(self.message)
        self.splitMessageReverse(True)
        print("Résultats: ", self.message)
        
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
            print("\n----------\nI: ", i)
            for j in range(1, 17):
                print("\n     J: ", j)
                key = self.key.deriveKeys(self.key.keys[1][-(j + (i - 1) * 16)], 3)
                self.message[-i] = self.func.xor(key[2], self.message[-i])
                print("\n     Fonction de déchiffrement avec Clef:")
                print("     Fonction numéro: ", self.vecInit[1][-(j + (i-1) * 16)])
                print("     Indice dans le vecteur: ", -(j + (i-1) * 16), " / ", len(self.vecInit[1])-(j + (i-1) * 16))
                print("     Message à déchiffrer: ", self.message[-i])
                print("     Clef de déchiffrement: ", key[1])
                self.message[-i] = self.func.funcKeyDecode[self.vecInit[1][-(j + (i-1) * 16)]](self.message[-i], key[1])
                print("     Résultat déchiffré: ", self.message[-i])
                for k in range(1, 6):
                    print("\n          K: ", k)
                    print("\n          Fonction de déhiffrement sans Clef:")
                    print("          Fonction numéro: ", self.vecInit[0][-((j-1)*5 + k + (i-1) * 16 * 5)])
                    print("          Indice dans le vecteur: ", -((j-1)*5 + k + (i-1) * 16 * 5), " / ", len(self.vecInit[0])-((j-1)*5 + k + (i-1) * 16 * 5))
                    print("          Message à déchiffrer: ", self.message[-i])
                    self.message[-i] = self.func.funcDecode[self.vecInit[0][-((j-1)*5 + k + (i-1) * 16 * 5)]](self.message[-i])
                    print("          Message déchiffré: ", self.message[-i])
                self.message[-i] = self.func.xor(key[0], self.message[-i])



    def adaptationKey(self, message, key):
        if len(key) == len(message):
            return key
        else:
            return self.key.deriveKeys(key, 1, len(message))[0]
    
    def concatenationMessageReverse(self, vector=False):
        message = []
        if vector:
            spliter = self.message.find(str(len(self.func.func)))
            message.append(self.message[0:spliter])
            spliter2 = self.message.find(str(len(self.func.func)), spliter + 1)
            message.append(self.message[spliter+1:spliter2])
            self.message = self.message[spliter2+1:]
            self.vecInit = [[int(message[0][i:i+2]) for i in range(0, len(message[0]), 2)], [int(message[1][i:i+2]) for i in range(0, len(message[1]), 2)]]
        else:message = [0, 0]
        gIdx = False
        temp = 0
        while not gIdx:
            temp = self.message.find('0', temp)
            if len(self.message[temp:])%int(self.message[0:temp]) == 0:
                message.append(self.message[0:temp])
                message.append(self.message[temp:])
                gIdx = True
        nbr_block = int(message[2])
        res = [message[3][i:i+int(len(message[3])/nbr_block)] for i in range(0, len(message[3]), int(len(message[3])/nbr_block))]
        self.message = [chaine.lstrip('0') if len(chaine.lstrip('0'))%2 == 0 else "0" + chaine.lstrip('0') for chaine in res]
        
        


toEncrypt = Encrypt("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", "0azdad0zaza")






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
    
    mode = 1 if args.mode == 'D' or args.mode == 'Decrypt' else 0
    if mode == 1:
        message = [message[i:i+64] for i in range(0, len(message), 64)]
        for i in len(message):
            message[i] = Encrypt(KEY, message[i])
        file = open('res.txt', 'w')
        file.write('|'.join([i.messege for i in message]))
    else:
        message = message.split('|')
        for i in len(message):
            message[i] = Decrypt(KEY, message[i])
        file = open('res.txt', 'w')
        file.write('|'.join([i.messege for i in message]))

        


if __name__ == '__main__':
    print(argument())

'''
