#!/usr/bin/python

from socket import *
from threading import *
import optparse
import nmap
import time
screenLock = Semaphore(value=1)

def parseOptions():
	parser = optparse.OptionParser("usage %prog -H " + "<target host> -p <target port> -u <use udp prot> (Optional) -b <grab banner> (Optional) -w <file to write> (Optional)")
	parser.add_option("-H", dest="tgtHost", type="string", help="specify target host")
	parser.add_option("-p", dest="tgtPort", type="string", help="specify target port comma separated, all for 1-65534, <min port> - <max port> for port range")
	parser.add_option("-w", dest="writeFile", type="string", help="write to file")
	parser.add_option("-u", action="store_true", dest="scanPrt", help="specify udp protocol", default=False)
	parser.add_option("-b", action="store_true", dest="banGrab", help="tell scanner to grab banner", default=False)
	parser.add_option("-N", action="store_true", dest="nmapScan", help="choose what scanner", default=False)
	return parser

def getPorts(tgtPort):
	tgtPorts = []
	if '-' in tgtPort:
		highrange = int(tgtPort.split('-')[1])
		lowrange = int(tgtPort.split('-')[0])
		for i in range(lowrange,(highrange+1)):
			tgtPorts.append(str(i))
	elif tgtPort == "all":
		for i in range(1,65534):
			tgtPorts.append(str(i))
	else:		
		tgtPorts = tgtPort.split(",")
	return tgtPorts

def checkTgtStatus(tgtHost):
	arguments = "-sP -Pn"
	nmScan = nmap.PortScanner()
	nmScan.scan(tgtHost, arguments=arguments)	
	return nmScan[tgtHost].state()

def scan(tgtHost, tgtPort, options):
	scanPrt = options.scanPrt
	banGrab = options.banGrab
	setdefaulttimeout(1)
	time.sleep(1)
	try:
		connSkt = socket(AF_INET, SOCK_STREAM)
		connSkt.connect((tgtHost, int(tgtPort)))
		connSkt.send("bolowashere\r\n")
		results = connSkt.recv(100)
		print "[*] tcp/" + str(tgtPort) + " open\r"
		if (banGrab == True):
			print " |_ " + str(results)
		screenLock.release()
		connSkt.close()
	except:
		print "[*] tcp/" + str(tgtPort) + " closed\r"		

def nmapScan(tgtHost, tgtPort, options):
	arguments = "-sS -Pn"
	scanPrt = options.scanPrt
	banGrab = options.banGrab
	writeFile = options.writeFile
	if (scanPrt == False):
		scanPrt = "tcp"
	else:
		scanPrt = "udp"
	nmScan = nmap.PortScanner()
	nmScan.scan(tgtHost, tgtPort, arguments=arguments)
	if (writeFile != None):
		file = open(writeFile,"w") 
		file.write(nmScan.csv()) 
		file.close() 
	# Scan contents debug 
	# print nmScan[tgtHost]
	state = nmScan[tgtHost][scanPrt][int(tgtPort)]['state']
	name = nmScan[tgtHost][scanPrt][int(tgtPort)]['name']
	print "[*] " + scanPrt + "/" + tgtPort + " " + state + " --> " + name
	if (state == "open"):
		if (banGrab == True):
			results = grabBanner(tgtHost, tgtPort)
			print " |_ " + str(results)

def main():
	parser = parseOptions()
	(options, args) = parser.parse_args()
	tgtHost = options.tgtHost
	tgtPort = options.tgtPort
	tgtPorts = getPorts(tgtPort)
	if (tgtHost == None) | (tgtPorts[0] == None):
		print parser.usage
		exit(0)
	print "[*] Scanning: " + tgtHost
	print "[*] Host is " + checkTgtStatus(tgtHost)
	for tgtPort in tgtPorts:
		if (options.nmapScan == True) :
			nmapScan(tgtHost, tgtPort, options)
		else:	
			t = Thread(target=scan, args=(tgtHost, tgtPort, options))
			t.start()

if __name__ == '__main__':
	main()


