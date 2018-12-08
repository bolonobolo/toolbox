#!/usr/bin/python

import zipfile
import optparse
from threading import Thread

# This tool is usefull only when the zip file is protected by cleartext password (on linux with command zip -P)

def extractFile(zFile, password):
	try:
		zFile.extractall(pwd=password)
		print "[*] Found password " + password + "\n"
	except:
		pass

def main():
	parser = optparse.OptionParser("usage %prog " + "-f <zipfile> -d <dictionary>")
	parser.add_option("-f", dest="zname", type="string", help="specify zip file")
	parser.add_option("-d", dest="dname", type="string", help="specify dictionary file")
	(options, args) = parser.parse_args()
	if (options.zname == None) | (options.dname == None):
		print parser.usage
		exit(0)
	else:
		zname = options.zname
		dname = options.dname
	zFile = zipfile.ZipFile(zname)
	passFile = open(dname)
	for line in passFile.readlines():
		print "[*] Cracking..."
		password = line.strip("\n")
		print "[*] tring password: " + password 
		t = Thread(target=extractFile, args=(zFile, password))
		t.start()

if __name__ == '__main__':
	main()
	