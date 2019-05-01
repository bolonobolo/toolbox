#!/usr/bin/python

# Block Ciphers script

from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from base64 import b64encode,b64decode
import random
import string

def getMode():
	while True:
		print("Do you wish do encrypt or decrypt?")
		mode = raw_input().lower()
		if mode in "encrypt e decrypt d".split():
			return mode
		else:
			print('Enter either "encrypt" or "e" or "decrypt" or "d".')

def getCipher():
	while True:
		print("Choose the cipher (des, 3des, aes)")
		cipher = raw_input().lower()
		if cipher in "des 3des aes".split():
			return cipher
		else:
			print('Choose the cipher from des, 3des and aes')

def getMessage():
	print("Enter the text")
	return raw_input()

def getKey():
	print("Enter the key")
	return raw_input()

def getIV():
	print("Enter the IV")
	return raw_input()


def genkey(length):
	key = []
	# in ascii one letter = 8 bit = 1 byte 
	# DES needs 64 bits keys 64/8 = 8 letters
	# 3DES needs 128 or 192 bits, i choosed 192 192/8 = 24
	# AES needs 128, 192, or 256 bits, i choosed 256 256/8 = 32
	for _ in range (0,length):
		key.append(random.SystemRandom().choice(
				string.ascii_uppercase + string.ascii_lowercase + string.digits
				)) 
	return ''.join(key)

def chooser(cipher, key, iv):
	if cipher == "des":
		cipher = DES.new(key, DES.MODE_OFB, iv)
	elif cipher == "3des":
		cipher = DES3.new(key, DES3.MODE_OFB, iv)
	elif cipher == "aes":
		cipher = AES.new(key, AES.MODE_OFB, iv)
	return cipher

def padding(size, text):
	while len(text) % size != 0:
			text += " "
	return text	

def cipherAlgo(cipher, key, text, size, iv):
	cipher = chooser(cipher, key, iv)	
	text = padding(size, text)
	text = cipher.encrypt(text)
	msg = b64encode(text)
	return msg

def decipherAlgo(cipher, key, text, iv):
	cipher = chooser(cipher, key, iv)
	text = b64decode(text)	
	msg = cipher.decrypt(text)
	return msg

def main():
	cipher = getCipher()
	mode = getMode()
	text = getMessage()
	if mode[0] == "e":
		if cipher == "des":
			key = genkey(8) # 64 bits of key
			iv = genkey(8)
			size = 8 # block size has to be 8 bytes
		elif cipher == "3des":
			key = genkey(24) # 192 bits of key
			iv = genkey(8)
			size = 8 # block size has to be 8 bytes
		elif cipher == "aes":
			key = genkey(32) # 256 bits of key
			iv = genkey(16)
			size = 16 # block size has to be 16 bytes
		msg = cipherAlgo(cipher, key, text, size, iv)
		print("Encrypted message: %s" % (msg))
		print("The key is: %s" % (key))
		print("The IV is: %s" % (iv))
	elif mode[0] == "d":
		key = getKey()
		iv = getIV()
		msg = decipherAlgo(cipher, key, text, iv)
		print("Decrypted message: %s" % (msg))

if __name__ == '__main__':
	main()