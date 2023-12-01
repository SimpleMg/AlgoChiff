class chiff:
    def __init__(self):
        pass

    def chiffrementCesar(self, decalage):
        resultat = ""
        for char in self.message:
            if char.isalpha():
                asciiOffset = 65 if char.isupper() else 97
                resultat += chr((ord(char) - asciiOffset + decalage) % 26 + asciiOffset)
            else:
                resultat += char
        return resultat


    def chiffrementVigenere(self):
        resultat = ""
        lenK = len(self.key)
        for char in range(len(self.message)):
            if self.message[char].isalpha():
                asciiOffset = 65 if self.message[char].isupper() else 97
                resultat += chr(((ord(self.message[char]) - asciiOffset) + (ord(self.key[char % lenK]) - asciiOffset)) % 26 + asciiOffset)
            else:
                resultat += self.message[char]
        return resultat
    

    def xorOperator(self, a, b):
        aBinary = format(a, 'b')
        bBinary = format(b, 'b')
        maxL = max(len(aBinary), len(bBinary))
        aBinary = aBinary.zfill(maxL)
        bBinary = bBinary.zfill(maxL)
        resultat = ""
        for i in range(maxL):
            bit = '1' if aBinary[i] != bBinary[i] else '0'
            resultat += bit
        return int(resultat, 2)
        

    def chiffrementXOR(text, key):
        byte_result = bytearray()
        keyLength = len(key)
        for i in range(len(text)):
            xor_result = xorOperator(ord(text[i]), ord(key[i % keyLength]))
            byte_result.append(xor_result)  
        return byte_result.hex()  



