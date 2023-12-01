class allFunc:
    def __init__(self, message):
        self.message = message
    

    def reverseString(self):
        return self.message[::-1]
    

    def reverseOneTwo(self):
        self.message = list(self.message)
        for i in range(len(self.message) - 1):
            if i % 2 == 0:
                charIndiceSave = self.message[i]
                self.message[i] = self.message[i + 1]
                self.message[i + 1] = charIndiceSave
        return ''.join(self.message)
    

    def obfuscateStringBase64(self):
        stringToBytes = str(self.message).encode('utf-8')
        bytesToBase64 = base64.b64encode(stringToBytes)
        return bytesToBase64.decode('utf-8')
    

    def deobfuscateStringBase64(self):
        base64ToBytes = self.message.encode('utf-8')
        base64ToBytes = base64.b64decode(base64ToBytes)
        return base64ToBytes.decode('utf-8')
    

    def conversion_binaire(self):
        res = ''
        binary = self.message.replace('01', '0|1').replace('10', '1|0').split('|')
        if binary[0][0] != '0':res += '000'
        for i in range(len(binary)):
            lenBinary = len(binary[i])
            res += ''.join(['999000' * (lenBinary // 999), str(lenBinary % 999).zfill(3)])
        return res

    
    def conversion_binaire_decode(self):
        return ''.join(str(idx % 2) * int(chunk) for idx, chunk in enumerate([self.message[i:i+3] for i in range(0, len(self.message), 3)]))
    


    def inverse_binaire(nombre_binaire):
	return ''.join('0' if bit == '1' else '1' for bit in nombre_binaire)

    
    def matriceMelange(self):
        hexa = [format(i, '02x') for i in range(256)]
        random.seed(CLEE)
        random.shuffle(hexa)
        matrice = [hexa[i:i+16] for i in range(0, 256, 16)] 
        return ''.join(matrice[int(self.message[i], 16)][int(self.message[i + 1], 16)] for i in range(0, len(self.message), 2))


    def matriceMelange_decode(self):
        hexa = [format(i, '02x') for i in range(256)]
        random.seed(CLEE)
        random.shuffle(hexa)
        matrice = [hexa[i:i+16] for i in range(0, 256, 16)] 
        res = ''
        for k in range(0, len(self.message), 2):
            idx = [(i, j) for i, row in enumerate(matrice) for j, val in enumerate(row) if val == self.message[k]+self.message[k+1]][0]
            res += hex(idx[0])[-1:] + hex(idx[1])[-1:]
        return res
