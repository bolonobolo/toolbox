#!/usr/bin/python

# Tool for port scan, banner grabbing and homepage screenshot
# 
# Requierments:
# 	- python 2.7.x
# 		https://www.python.org/downloads/
# 	- webscreenshot.py
# 		pip install webscreenshot
# 
# Remember to install python with pip and to enable automatic PATH modification to avoid troubles


import optparse
import socket
from socket import *
from threading import *
import os
screenLock = Semaphore(value=1)


def connScan(tgtHost, tgtPort):
	try:
		connSkt = socket(AF_INET, SOCK_STREAM)
		connSkt.connect((tgtHost, tgtPort))
		connSkt.send("TestTest\r\n")
		results = connSkt.recv(100)
		print "[*] %d/tcp open"% tgtPort
	except:
		print "[-] %d/tcp closed"% tgtPort		
	finally:
		# screenLock.release()
		connSkt.close()

def retBanner(tgtHost, tgtPorts):
	try:
		connSkt = socket(AF_INET, SOCK_STREAM)
		connSkt.connect((tgtHost, tgtPort))
		connSkt.send("TestTest\r\n")
		results = connSkt.recv(100)
		print "[*]" + str(results)
		screenLock.release()
		connSkt.close()
	except:
		print "[-] Cannot grab Banner"

def portScan(tgtHost, tgtPorts, banGrab, screenSh):
	try:
		tgtIP = gethostbyname(tgtHost)
	except:
		print "[-] Cannot resolve '%s': Unknown host"%tgtHost
		return
	try:
		tgtName = gethostbyaddr(tgtIP)
		print "\n[*] Scan result for:" + tgtIP
		print "[*] Resolved: " + tgtName[0]
	except:
		print "\n[*] Scan result for:" + tgtIP
	setdefaulttimeout(1)
	for tgtPort in tgtPorts:
		connScan(tgtHost, int(tgtPort))
		# t1 = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
		# t1.start()
		if (banGrab == True):
			retBanner(tgtHost, int(tgtPort))
			# t2 = Thread(target=retBanner, args=(tgtHost, int(tgtPort)))
			# t2.start()
		if (screenSh == True and (int(tgtPort) == 443 or int(tgtPort) == 80)):
			print("\nAcquiring screenshots...")
			os.system("webscreenshot http://" + tgtHost + ":" + tgtPort + " > NUL")	
def main():
	parser = optparse.OptionParser("usage %prog -H " + "<target host> -p <target port> or -f <path_to_IP_list> (optional -s for page screenshot, -b for banner grab)")
	parser.add_option("-H", dest="tgtHost", type="string", help="specify target host")
	parser.add_option("-p", dest="tgtPort", type="string", help="specify target port")
	parser.add_option("-f", dest="tgtFile", type="string", help="specify targets file")
	parser.add_option("-s", action="store_true", dest="screenSh", help="tell scanner to grab screenshot", default=False)
	parser.add_option("-b", action="store_true", dest="banGrab", help="tell scanner to grab banner", default=False)


	(options, args) = parser.parse_args()
	banGrab = options.banGrab
	screenSh = options.screenSh
	tgtFile = options.tgtFile
	if (tgtFile != None):
		file = open(tgtFile,"r") 
		for line in file:
  			targets = str(line).split(":")
  			tgtHost = targets[0]
  			tgtPorts = targets[1]
  			tgtPorts = str(tgtPorts).split(",")
			portScan(tgtHost, tgtPorts, banGrab, False)
		if (screenSh == True):
			os.system("webscreenshot -i " + tgtFile)
		file.close()
	else:	
		tgtPorts = str(options.tgtPort).split(",")
		tgtHost = options.tgtHost
		if (tgtHost == None) | (tgtPorts[0] == None):
			print "[-] You nust specify a target host and port[s]"
			exit(0)
		portScan(tgtHost, tgtPorts, banGrab, screenSh)

if __name__ == '__main__':
	main()


