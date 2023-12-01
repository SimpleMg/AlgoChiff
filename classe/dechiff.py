
class Dechiff:
    def __init__(self, KEY, message):
        self.key = KEY
        self.message = message
        
    
    def dechiffrementVigenere(self):
        resultat = ""
        lenK = len(self.key)
        for char in range(len(self.message)):
            if self.message[char].isalpha():
                asciiOffset = 65 if self.message[char].isupper() else 97
                resultat += chr(((ord(self.message[char]) - asciiOffset) - (ord(self.key[char % lenK]) - asciiOffset)) % 26 + asciiOffset)
            else:
                resultat += self.message[char]
        return resultat

    
    def dechiffrementXOR(hex_text, key):
        byte_text = bytearray.fromhex(hex_text)  
        resultat = ""
        keyLength = len(key)
        for i in range(len(byte_text)):
            xor_result = xorOperator(byte_text[i], ord(key[i % keyLength]))
            resultat += chr(xor_result)
        return resultat
