def inverse_binaire(nombre_binaire):
	nombre_inverse = ''.join('0' if bit == '1' else '1' for bit in nombre_binaire)
	return nombre_inverse

print(inverse_binaire("01010101100"))