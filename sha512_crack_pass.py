import crypt
import sys

def splitCrypt(string):
	## The shadow format is $id$salt$hashed
	idhash = string.split("$")[1]
	hashed = string.split("$")[3]
	## The id rapresent the cypher algo used:
	# $1$ is MD5
    # $2a$ is Blowfish
    # $2y$ is Blowfish
    # $5$ is SHA-256
    # $6$ is SHA-512
	if idhash == str(1):
		algo = "MD5"
	elif idhash == str(5):
		algo = "SHA-256"
	elif idhash == str(6):
		algo = "SHA-512"
	else:
		algo = "Blowfish"
	retList = []
	retList.append(idhash)
	retList.append(algo)
	return retList

def testPass(line):
	if ":" in line:
		# Obtain user crypted password and sal directly from sahdow
		user = line.split(":")[0]
		cryptPass = line.split(':')[1].strip(' ')
		salt = cryptPass[0:11]

		# Obtain the algo type from the splitCrypt function, only for check
		string = line.split(":")[1]
		retList = splitCrypt(string)
		algo = retList[1]
		print "[*] Cracking password for user: " + user
		print "[*] The password is encrypted with " + algo + " algorithm"
		dictFile = open(sys.argv[1],"r")
		for word in dictFile.readlines():
			word = word.strip("\n")
			cryptWord = crypt.crypt(word,salt)
			if (cryptWord == cryptPass):
				print "[*] Found password: " + word + "\n"
				return
		print "[-] Password Not Found.\n"
		return

def main():
	if len(sys.argv) != 3:
		print "Usage: sha512_crack_pass.py <dictionary> <shadow file>"
		return
	else:	
		passFile = open(sys.argv[2])		
		for line in passFile:
			if "$" in line:
				testPass(line)
						
if __name__ == '__main__':
	main()