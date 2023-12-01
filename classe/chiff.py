class chiff:
    def __init__(self, KEY, message):
        self.key = KEY
        self.message = message


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
        

    def chiffrementXOR(self):
        resultat = ""
        keyLength = len(self.key)
        for i in range(len(self.message)):
            # resultat += chr(ord(text[i]) ^ ord(key[i % keyLength]))
            resultat += chr(self.xorOperator(ord(self.message[i]), ord(self.key[i % keyLength])))
        return resultat




