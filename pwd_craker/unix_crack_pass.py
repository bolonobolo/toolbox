import crypt
import sys

def testPass(line):
	if ":" in line:
		user = line.split(":")[0]
		cryptPass = line.split(":")[1].strip(" ")
		print "[*] Cracking password for user: " + user
		salt = cryptPass[0:2]
		dictFile = open(sys.argv[1],"r")
		for word in dictFile.readlines():
			word = word.strip("\n")
			cryptWord = crypt.crypt(word.salt)
			if (cryptWord == cryptPass):
				print "[*] Found password: " + word + "\n"
				return
		print "[-] Password Not Found.\n"
		return


def main():
	if len(sys.argv) != 3:
		print "Usage: unix_crack_pass.py <dictionary> <shadow file>"
		return
	else:	
		passFile = open(sys.argv[2])		
		for line in passFile:
			if ":" in line:
				testPass(line)
			
			
if __name__ == '__main__':
	main()