# Ceasar Cipher

MAX_KEY_SIZE = 26

def getMode():
	while True:
		print("Do you wish do encrypt or decrypt?")
		mode = raw_input().lower()
		if mode in "encrypt e decrypt d".split():
			return mode
		else:
			print('Enter either "encrypt" or "e" or "decrypt" or "d".')

def getMessage():
	print("Enter the text")
	return raw_input()

def getKey():
	key = 0
	while True:
		print("Enter the key value from 1 to %s" % (MAX_KEY_SIZE))  
		key = int(raw_input())
		if key >= 1 and key <= MAX_KEY_SIZE:
			return key
		print("Enter a good key value")

def getCipher(mode, plain, key):
	if mode[0] == 'd':
		key = -key
	translated = ""

	for symbol in plain:
		if symbol.isalpha():
			num = ord(symbol)
			num += key

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

mode = getMode()
plain = getMessage()
key = getKey()

print('Your translated text is:')
print(getCipher(mode, plain, key))
	



