#!/usr/bin/python

import zipfile
import sys
import optparse
from threading import Thread

def extractFile(zFile, passsword):
	try:
		zFile.extracall(pwd=passsword)
		print "[*] Found password " + password + "\n"
	except:
		pass

def main():
	parser = optparse.OptionParser("usage%prog " + "-f <zipfile> -d <distionary>")
	parser.add_option("-f", dest="zname", type="string", help="specify zip file")
	parser.add_option("-d", dest="dname", type="string", help="specify dictionary file")
	(options, args) = parser.parse_args()
	if (options.zname == None) | (options.dname == None):
		print parser.usage
		exit(0)
	else:
		zname = options.zname
		dname = options.dname
	zFile = zipfile.Zipfile(zname)
	passFile = open(dname)
	for line in passFile():
		password = line.strip("\n")
		t = Thread(target=extractFile, args=(zFile, password))
		t.start()

if __name__ == '__main__':
	main()
	