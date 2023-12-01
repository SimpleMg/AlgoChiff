'''

# bloc d'un message chiffré 
first_block = "abcdefghij"

# Diviser la chaîne en morceaux de deux caractères
resultat = [first_block[i:i+2] for i in range(0, len(first_block), 2)]

# Afficher le résultat

print(resultat)
'''

def divide(block_text, lenth):
    # Diviser la chaîne en morceaux de lenth caractères
    resultat = [block_text[i:i+lenth] for i in range(0, len(block_text), lenth)]
    return resultat

# Exemple d'utilisation
block_text = "abcdefghij"
lenth = 2

resultat_decoupe = divide(block_text, lenth)



print(resultat_decoupe)
