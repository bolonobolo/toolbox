# Ceasar bruteforce

MAX_KEY_SIZE = 26

def get_text():
	while True:
		print("Enter the text to bruteforce")
		text = raw_input()	
		return text

def shift(text, key):
	translated = ""
	for symbol in text:
		if symbol.isalpha():
			num = ord(symbol)
			num -= key
			if symbol.isupper():
				if num > ord('Z'):
					num -= 26
				elif num < ord('A'):
					num += 26
			elif symbol.islower():
				if num > ord('z'):
					num -= 26
				elif num < ord('a'):
					num += 26
			translated += chr(num) 
		else:
			translated += symbol	
	return translated

text = get_text()
for key in range(1, MAX_KEY_SIZE + 1):
	print("Key %d: --> " % (key) + shift(text, key))