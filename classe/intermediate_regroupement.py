class allFunc:

    def est_premier(self,n):
        """Vérifie si un nombre est premier."""
        if n < 2:
            return False
        for i in range(2, int(n**0.5) + 1):
            if n % i == 0:
                return False
        return True



    def nombre_premier_proche(self,nombre):
        """Trouve le nombre premier le plus proche supérieur."""
        if nombre < 2:
            return "Il n'y a pas de nombre premier inférieur à 2."

        # Chercher le nombre premier le plus proche supérieur
        superieur = nombre + 1
        while True:
            if self.est_premier(superieur):
                break
            superieur += 1

        return superieur



class Encrypt:
    def __init__(self, KEY, message):
        self.key = Key(KEY)
        self.message = self.splitMessage(message)
        self.key.keyBase = self.key.deriveKeys(self.key.KEY, 4)
        self.key.keys[0] = self.key.deriveKeys(self.key.keyBase[0], 5)
        self.key.keys[1] = self.key.deriveKeys(self.key.keyBase[1], 16)
        self.key.keys[2] = self.key.deriveKeys(self.key.keyBase[2], 5)
        self.key.keys[3] = self.key.deriveKeys(self.key.keyBase[3], 2)


    def splitMessage(self, bits) -> list:
        pass





def intermediaire_regroupement(message):
    # Diviser la chaîne en morceaux de lenth caractères
    x=allFunc()
    regroup = message
    avant_nbr_premier = len(max(regroup, key=len))
    if not x.est_premier(avant_nbr_premier):
        avant_nbr_premier=x.nombre_premier_proche(avant_nbr_premier)
        
    regroup=[i.zfill(avant_nbr_premier) for i in regroup]
    print(regroup)
    regroup= "".join(regroup)+ '|' + str(len(regroup))
    print(regroup)
    return regroup
    




def decode_regroupement(message):
    message = message.split("|")
    print(message)
    nbr_block = int(message.pop(1))
    print(nbr_block)
    decoupage = len(message[0])/nbr_block
    print(decoupage)
    



    '''lenth = 2
    resultat = [self.message[i:i+lenth] for i in range(0, len(self.message), lenth)]
    return resultat
    '''

        # Exemple d'utilisation


liste=["zeufhzsdiucghzyidcgzygvc","qsucfhayigzcayigfcazycgaucgh","asudhgcaiyuzcgayugcaygcaygcmvaygcaztgvefgcdtyagvcauvcgsayhdcgyiudgazcxyhzbv"]

resultat_decoupe = intermediaire_regroupement(liste)



print(resultat_decoupe)

print(decode_regroupement(resultat_decoupe))







