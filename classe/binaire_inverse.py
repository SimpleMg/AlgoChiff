def inverse_binaire(nombre_binaire):
	return ''.join('0' if bit == '1' else '1' for bit in nombre_binaire)

print(inverse_binaire("01010101100"))
