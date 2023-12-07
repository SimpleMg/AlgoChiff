import random
import hashlib
import secrets
import time
from argparse import ArgumentParser

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

class Key:
    def __init__(self, key):
        self.KEY = key
        self.key_base = []  # will contain 4 keys to generate self.keys
        self.keys = [[], [], [], []]  # [[keys for layer(0)], [keys for mainLoop()], [keys for layer(2)], [keys for intermediate step]]

    def deriveKeys(self, key, num_keys, exit=32):  # deriveKeys(self, key to be derived, number of keys needed, length of output keys)
        '''
        Allows derivation of a key into multiple keys without reversible possibility using sha256.
        Uses HKDF for creating sub-keys.
        '''
        master_key_bytes = key.encode('utf-8')
        random.seed(hashlib.sha256(key.encode('utf-8')).hexdigest())
        salt = random.randbytes(256)
        derived_keys = [
            hashlib.sha256(
                HKDF(
                    algorithm=hashes.SHA256(),
                    length=exit,  # output length
                    salt=salt,  # salt for regenerating keys with the same key and parameters
                    info=str(i).encode('utf-8'),  # info contains the key number
                    backend=default_backend()
                ).derive(master_key_bytes)
            ).hexdigest()
            for i in range(num_keys)
        ]
        return derived_keys  # returns the list of sub-keys


class allFunc:
    def __init__(self):
        '''
        Contains dictionaries with functions for encryption without a key in self.func along with their inverses in self.funcDecode.
        Contains dictionaries with functions for encryption with a key in self.funcKey along with their inverses in self.funcKeyDecode.
        '''
        self.func = {0: self.binary_inversion, 1: self.binary_switch, 2: self.substitute_hex, 3: self.reverseOneTwo, 4: self.reverseString}
        self.funcKey = {0: self.matriceMelange}
        self.funcDecode = {0: self.binary_inversion, 1: self.binary_switch_decode, 2: self.substitute_hex_decode, 3: self.reverseOneTwo, 4: self.reverseString}
        self.funcKeyDecode = {0: self.matriceMelange_decode}

    def xor(self, key, msg):
        '''
        XOR operation between two strings.
        Adapting the key to have strings of the same length.
        Conversion to binary for XOR operation.
        '''
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

    def stringToInt(self, text):
        '''
        Converts a string into str(int) to simplify special characters.
        Uses their Unicode code.
        '''
        res = [str(ord(i)).zfill(len(str(max([ord(c) for c in text])))) for i in text]
        return str(len(res[0])) + ''.join(res)

    def intToString(self, text):
        '''
        Inverse of stringToInt.
        '''
        length = int(text[0])
        numbers = [text[i:i+length] for i in range(1, len(text), length)]
        return ''.join(chr(int(num)) for num in numbers)

    def intToHex(self, number):
        '''
        Converts an int to hexadecimal.
        '''
        number = int(number)
        res = ""
        while number > 0:
            number, remainder = divmod(number, 16)
            res = "0123456789abcdef"[remainder] + res
        return res if res else "0"

    def hexToInt(self, hexa):
        '''
        Inverse of intToHex.
        '''
        return str(sum(int(char, 16) * (16 ** i) for i, char in enumerate(hexa[::-1])))

    def hexToBin(self, hexa):
        '''
        Converts a hexadecimal to binary.
        '''
        res = ''
        for i in hexa:
            res += bin(int(i, 16))[2:].zfill(4)
        return res

    def binToHex(self, hexa):
        '''
        Inverse of hexToBin.
        '''
        return ''.join([hex(int(hexa[i:i+4], 2))[2:] for i in range(0, len(hexa), 4)])


    def binary_inversion(self, hexa):
        '''
        Fonction d'inversion des 0 et 1 en binaire
        '''
        binary = self.hexToBin(hexa)
        res = ''
        for i in binary:
            res += '0' if i == '1' else '1'
        hexa = self.binToHex(res)
        return hexa
    
    def binary_switch(self, hexa):
        '''
        Fonction de manipulation de binaire par transposition
        '''
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
        '''
        Inverse de binary_switch
        '''
        binary = self.hexToBin(hexa)
        for i in range(2, len(binary)+1):
            if binary[-i+1] == "1":
                binary = binary[0:-i] + ('0' if binary[-i] == '1' else '1') + binary[len(binary)-i+1:len(binary)] 
        return self.binToHex(binary)
    
    def substitute_hex(self, hex_input):
        '''
        Hexadecimal substitution function.
        '''
        hex_input = hex_input
        substituted_hex = ''.join('{:X}'.format(15 - int(c, 16)) for c in hex_input)
        return substituted_hex.lower()

    def substitute_hex_decode(self, substituted_hex):
        '''
        Inverse of substitute_hex.
        '''
        substituted_hex = substituted_hex
        original_hex = ''.join('{:X}'.format(15 - int(c, 16)) for c in substituted_hex)
        return original_hex.lower()

    def reverseOneTwo(self, hexa):
        '''
        Binary manipulation function by transposition.
        '''
        hexa = list(hexa)
        for i in range(len(hexa) - 1):
            if i % 2 == 0:
                charIndiceSave = hexa[i]
                hexa[i] = hexa[i + 1]
                hexa[i + 1] = charIndiceSave
        return ''.join(hexa)

    def reverseString(self, hexa):
        '''
        Function to reverse the string of characters.
        '''
        return hexa[::-1]

    def matriceMelange(self, hexa, KEY):
        '''
        Function similar to S-Box but uses an additional encryption key to generate the matrix randomly.
        '''
        if len(hexa) % 2 != 0: 
            hexa = '0' + hexa
            zero = True
        else: 
            zero = False
        hexaForm = [format(i, '02x') for i in range(256)]
        random.seed(KEY)
        random.shuffle(hexaForm)
        matrice = [hexaForm[i:i+16] for i in range(0, 256, 16)]
        res = "".join(matrice[int(hexa[i], 16)][int(hexa[i + 1], 16)] for i in range(0, len(hexa), 2))
        if zero == True: 
            res = "ff" + res
        else: 
            res = "ee" + res
        return res

    def matriceMelange_decode(self, hexa, KEY):
        '''
        Inverse of matriceMelange.
        '''
        if hexa[:2] == "ff": 
            zero = True
        elif hexa[:2] == "ee": 
            zero = False
        assert hexa[:2] == "ff" or hexa[:2] == "ee"
        hexaForm = [format(i, '02x') for i in range(256)]
        random.seed(KEY)
        random.shuffle(hexaForm)
        matrice = [hexaForm[i:i+16] for i in range(0, 256, 16)] 
        res = ''
        for k in range(0, len(hexa), 2):
            idx = [(i, j) for i, row in enumerate(matrice) for j, val in enumerate(row) if val == hexa[k]+hexa[k+1]][0]
            res += hex(idx[0])[-1:] + hex(idx[1])[-1:]
        if zero == True: 
            res = res[3:]
        else: 
            res = res[2:]
        return res

    def messageToListToMelange(self, hexa, KEY):
        '''
        Function not used but intended for random transposition.
        '''
        hexa = [i for i in hexa]
        random.seed(KEY)
        [random.shuffle(hexa) for _ in range(random.randint(5, 20))]
        return ''.join(hexa)

    def messageToListToMelange_decode(self, hexa, KEY):
        '''
        Inverse of messageToListToMelange.
        '''
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
    def __init__(self, KEY, message, comp=[2, 2, 2]):
        self.key = Key(KEY)
        self.complex = comp # Number of iterations for the loops
        self.func = allFunc()
        self.message = message
        '''
        Follows the encryption plan from our technical documentation
        --------------------------------
        1) Division of the message into chunks of 32 characters
        2) First layer
        3) Intermediate
        4) Main loop
        5) Intermediate with the vector
        6) Last layer
        7) Reconstruction
        '''
        self.splitMessage(True) # 1
        self.initialisationKeys() 
        self.layer(0) # 2
        self.concatenationMessage() # 3
        self.splitMessage() # 3
        self.initialisationVector() # Initializes the initialization vector that will determine the order of functions randomly
        self.mainLoop() # 4
        self.concatenationMessage(self.vecInit) # 5
        self.splitMessage() # 5
        self.layer(2) # 6
        self.concatenationMessage() # 7
        
    def splitMessage(self, first=False):
        '''
        Division of the message into chunks of 32 characters
        '''
        if first:
            hexa = self.func.intToHex(self.func.stringToInt(self.message))
            if len(hexa)%2!=0:hexa = '0' + hexa
        else:
            hexa = self.message
        self.message = [hexa[i:i+32] for i in range(0, len(hexa), 32)]

    def initialisationKeys(self):
        '''
        Prepare the keys to be derived later
        '''
        self.key.keyBase = self.key.deriveKeys(self.key.KEY, 4)
        self.key.keys[3] = self.key.deriveKeys(self.key.keyBase[3], 2)

    def initialisationVector(self):
        '''
        Initializes the initialization vector that will determine the order of functions randomly
        '''
        self.vecInit = []
        self.vecInit.append([secrets.randbelow(len(self.func.func)) for i in range((self.complex[2]*self.complex[1]) * len(self.message))]) # For functions without a key
        self.vecInit.append([secrets.randbelow(len(self.func.funcKey)) for i in range(self.complex[1] * len(self.message))]) # For functions with a key

    def layer(self, layer):
        '''
        Encryption layer used during the first and last layers
        '''
        self.key.keys[layer] = self.key.deriveKeys(self.key.keyBase[layer], self.complex[0] * len(self.message)) # Generating subkeys for each part of the message
        for i in range(len(self.message)): # For each part of the message
            for j in range(self.complex[0]): # x repetition for each part of the message (default x=2)
                key = self.key.deriveKeys(self.key.keys[layer][j + i * self.complex[0]], 3) # Generating 3 subkeys for each operation
                self.message[i] = self.func.xor(key[0], self.message[i]) # XOR
                self.message[i] = self.func.funcKey[j%len(self.func.funcKey)](self.message[i], key[1]) # Encryption function with a key
                self.message[i] = self.func.xor(key[2], self.message[i]) # XOR

    def mainLoop(self):
        self.key.keys[1] = self.key.deriveKeys(self.key.keyBase[1], self.complex[1] * len(self.message)) # Generating subkeys for each part of the message
        for i in range(len(self.message)): # For each part of the message
            for j in range(self.complex[1]): # x repetition for each part of the message (default x=2)
                key = self.key.deriveKeys(self.key.keys[1][j + i * self.complex[1]], 3) # Generating 3 subkeys for each operation
                self.message[i] = self.func.xor(key[0], self.message[i]) # XOR
                for k in range(self.complex[2]): # x repeat keyless encryption (default x=2)
                    self.message[i] = self.func.func[self.vecInit[0][j*self.complex[2] + k + i * self.complex[1] * self.complex[2]]](self.message[i]) # function chosen by the initialization vector
                self.message[i] = self.func.funcKey[self.vecInit[1][j + i * self.complex[1]]](self.message[i], key[1]) # Encryption function with a key
                self.message[i] = self.func.xor(key[2], self.message[i]) # XOR
    
    def concatenationMessage(self, vector=None):
        '''
        Group message pieces into one 
        Possibility of adding the initialization vector
        '''
        concat = self.message
        maxLen = len(self.message[0])
        concat = "".join(concat[i] for i in range(len(concat)))
        lenMess = hex(maxLen)[2:].zfill(4)
        concat = lenMess + "".join(concat)
        if vector:
            vec = ''
            for i in vector[0]:vec += str(i).zfill(2)
            vec += str(len(self.func.func))
            for i in vector[1]:vec += str(i).zfill(2)
        self.message =  concat if not vector else vec + str(len(self.func.func)) + concat

class Decrypt:
    '''
    Contains the inverse methods of Encrypt
    Executes them in the reverse direction of the encryption
    '''
    def __init__(self, KEY, message, comp=[2, 2, 2]):
        self.key = Key(KEY)
        self.func = allFunc()
        self.complex = comp
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
        self.key.keys[layer] = self.key.deriveKeys(self.key.keyBase[layer], self.complex[0] * len(self.message))
        for i in range(1, len(self.message) + 1):
            for j in range(1, self.complex[0]+1):
                key = self.key.deriveKeys(self.key.keys[layer][-(j + (i - 1) * self.complex[0])], 3)
                self.message[-i] = self.func.xor(key[2], self.message[-i])
                self.message[-i] = self.func.funcKeyDecode[(j-1)%len(self.func.funcKeyDecode)](self.message[-i] , key[1])
                self.message[-i] = self.func.xor(key[0], self.message[-i])
    
    def mainLoop(self):
        self.key.keys[1] = self.key.deriveKeys(self.key.keyBase[1], self.complex[1] * len(self.message))
        for i in range(1, len(self.message)+1):
            for j in range(1, self.complex[1]+1):
                key = self.key.deriveKeys(self.key.keys[1][-(j + (i - 1) * self.complex[1])], 3)
                self.message[-i] = self.func.xor(key[2], self.message[-i])
                self.message[-i] = self.func.funcKeyDecode[self.vecInit[1][-(j + (i-1) * self.complex[1])]](self.message[-i], key[1])
                for k in range(1, self.complex[2]+1):
                     self.message[-i] = self.func.funcDecode[self.vecInit[0][-((j-1)*self.complex[2] + k + (i-1) * self.complex[1] * self.complex[2])]](self.message[-i])
                self.message[-i] = self.func.xor(key[0], self.message[-i])
    
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
        idxlen = int(self.message[0:4], 16)
        message = self.message[4:]
        messageLst = [message[i:i+int(idxlen)] for i in range(0, len(message), int(idxlen))]
        self.message = messageLst

def argument():
    # Default complexity settings for encryption/decryption
    comp = [2, 2, 2]
    
    # Parsing command-line arguments
    argParser = ArgumentParser()
    argParser.add_argument("-f", "--file", help="File with message")
    argParser.add_argument("-k", "--key", help="Encryption key")
    argParser.add_argument("-m", "--mode", help="Encrypt (E) / Decrypt (D)")
    args = argParser.parse_args()
    
    # Setting the encryption key or generating a random one if not provided
    if args.key:
        KEY = args.key
    else:
        KEY = hex(secrets.randbits(512))[2:]
        print(KEY)
    
    # Checking if a file path is provided
    assert args.file, "Missing file path with --file <path>"
    
    # Reading the message from the specified file
    message = open(args.file, 'r', encoding="utf-8").read()
    
    # Determining the mode (Encrypt or Decrypt)
    mode = 1 if str(args.mode).lower() == 'd' or str(args.mode).lower() == 'decrypt' else 0
    
    # Encryption or decryption process based on the mode
    if mode == 0:  # Encrypt
        time1 = time.time()
        # Breaking the message into chunks of 128 characters
        message = [message[i:i+128] for i in range(0, len(message), 128)]
        
        # Encrypting each chunk of the message using the specified key and complexity settings
        for i in range(len(message)):
            message[i] = Encrypt(KEY, message[i], comp)
        
        # Writing the encrypted chunks to a file
        file = open('chiff.txt', 'w', encoding="utf-8")
        file.write('|'.join([i.message for i in message]))  # Writing encrypted messages separated by '|'
        print(round(time.time()-time1, 2), 'sec')  # Printing the time taken for encryption
        
    else:  # Decrypt
        time1 = time.time()
        # Splitting the message by '|' to get individual encrypted chunks
        message = message.split('|')
        
        # Decrypting each chunk of the message using the specified key and complexity settings
        for i in range(len(message)):
            message[i] = Decrypt(KEY, message[i], comp)
        
        # Writing the decrypted chunks to a file
        file = open('dechi.txt', 'w', encoding="utf-8")
        file.write(''.join([i.message for i in message]))  # Writing decrypted messages
        print(round(time.time()-time1, 2), 'sec')  # Printing the time taken for decryption

if __name__ == '__main__':
    argument()
