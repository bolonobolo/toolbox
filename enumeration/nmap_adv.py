#!/usr/bin/python

# import socket
from socket import *
import optparse
import nmap

def checkTgtStatus(tgtHost):
	arguments = "-sP -Pn"
	nmScan = nmap.PortScanner()
	nmScan.scan(tgtHost, arguments=arguments)	
	return nmScan[tgtHost].state()

def parseOptions():
	parser = optparse.OptionParser("usage %prog -H " + "<target host> -p <target port> -u <use udp prot> (Optional) -b <grab banner> (Optional)")
	parser.add_option("-H", dest="tgtHost", type="string", help="specify target host")
	parser.add_option("-p", dest="tgtPort", type="string", help="specify target port")
	parser.add_option("-u", action="store_true", dest="scanPrt", help="specify udp protocol", default=False)
	parser.add_option("-b", action="store_true", dest="banGrab", help="tell scan to grab banner", default=False)
	return parser

def nmapScan(tgtHost, tgtPort, scanPrt, banGrab):
	arguments = "-sS -Pn"
	nmScan = nmap.PortScanner()
	nmScan.scan(tgtHost, tgtPort, arguments=arguments)
	state = nmScan[tgtHost][scanPrt][int(tgtPort)]['state']
	name = nmScan[tgtHost][scanPrt][int(tgtPort)]['name']
	print "[*] " + scanPrt + "/" + tgtPort + " " + state + " --> " + name
	if (state == "open") & (banGrab == True):
		connSkt = socket(AF_INET, SOCK_STREAM)
		connSkt.connect((tgtHost, int(tgtPort)))
		connSkt.send("bolowashere\r\n")
		results = connSkt.recv(100)
		print " |--> " + str(results)


def main():
	parser = parseOptions()
	(options, args) = parser.parse_args()
	tgtHost = options.tgtHost
	tgtPorts = str(options.tgtPort).split(",")
	scanPrt = options.scanPrt
	banGrab = options.banGrab
	if (scanPrt == False):
		scanPrt = "tcp"
	else:
		scanPrt = "udp"	
	if (tgtHost == None) | (tgtPorts[0] == None):
		print parser.usage
		exit(0)
	print "[*] Scanning: " + tgtHost
	print "[*] Host is " + checkTgtStatus(tgtHost)
	for tgtPort in tgtPorts:
		nmapScan(tgtHost, tgtPort, scanPrt, banGrab)

if __name__ == '__main__':
	main()


