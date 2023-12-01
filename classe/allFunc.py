class allFunc:
    def __init__(self, message):
        self.message = message
    

    def reverseString(stringForReverse):
        return stringForReverse[::-1]
    

    def reverseOneTwo(stringForOneTwo):
        stringForOneTwo = list(stringForOneTwo)
        for i in range(len(stringForOneTwo) - 1):
            if i % 2 == 0:
                charIndiceSave = stringForOneTwo[i]
                stringForOneTwo[i] = stringForOneTwo[i + 1]
                stringForOneTwo[i + 1] = charIndiceSave
        return ''.join(stringForOneTwo)
    

    def obfuscateStringBase64(stringForObfuscate):
        stringToBytes = str(stringForObfuscate).encode('utf-8')
        bytesToBase64 = base64.b64encode(stringToBytes)
        return bytesToBase64.decode('utf-8')
    

    def deobfuscateStringBase64(stringForDeobfuscate):
        base64ToBytes = stringForDeobfuscate.encode('utf-8')
        base64ToBytes = base64.b64decode(base64ToBytes)
        return base64ToBytes.decode('utf-8')
    

    def conversion_binaire(binary: str):
        print(binary)
        res = ''
        binary = binary.replace('01', '0|1').replace('10', '1|0').split('|')
        if binary[0][0] != '0':res += '000'
        for i in range(len(binary)):
            lenBinary = len(binary[i])
            res += ''.join(['999000' * (lenBinary // 999), str(lenBinary % 999).zfill(3)])
        return res

    
    def conversion_binaire_decode(text: str):
        return ''.join(str(idx % 2) * int(chunk) for idx, chunk in enumerate([text[i:i+3] for i in range(0, len(text), 3)]))
    

    def inverse_binaire(nombre_binaire):
        nombre_inverse = ''.join('0' if bit == '1' else '1' for bit in nombre_binaire)
        return nombre_inverse
    

    def binary_switch(binary):
        return ''.join(binary_inversion(binary[i]) if binary[i+1] == '1' else binary[i] for i in range(len(binary)-1))+(binary[-1])


    def binary_switch_decode(binary):
        last = decode = binary[-1]
        for i in range(2, len(binary)+1):
            if last == "1":
                decode = binary_inversion(binary[-i]) + decode
                last = binary_inversion(binary[-i])
            else:
                decode = binary[-1] + decode
                last = binary[-1]
        return decode
    

    def matriceMelange(hexa_I):
        hexa = [format(i, '02x') for i in range(256)]
        random.seed(CLEE)
        random.shuffle(hexa)
        matrice = [hexa[i:i+16] for i in range(0, 256, 16)] 
        return ''.join(matrice[int(hexa_I[i], 16)][int(hexa_I[i + 1], 16)] for i in range(0, len(hexa_I), 2))


    def matriceMelange_decode(hexa_I):
        hexa = [format(i, '02x') for i in range(256)]
        random.seed(CLEE)
        random.shuffle(hexa)
        matrice = [hexa[i:i+16] for i in range(0, 256, 16)] 
        res = ''
        for k in range(0, len(hexa_I), 2):
            idx = [(i, j) for i, row in enumerate(matrice) for j, val in enumerate(row) if val == hexa_I[k]+hexa_I[k+1]][0]
            res += hex(idx[0])[-1:] + hex(idx[1])[-1:]
        return res
