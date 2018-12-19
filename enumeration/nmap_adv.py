#!/usr/bin/python

from socket import *
import optparse
import nmap

def grabBanner(tgtHost, tgtPort):
	connSkt = socket(AF_INET, SOCK_STREAM)
	connSkt.settimeout(3)
	try:
		connSkt.connect((tgtHost, int(tgtPort)))
		connSkt.send("bolowashere\r\n")
		results = connSkt.recv(100)
		return results
	except:
		exit(0)

def checkTgtStatus(tgtHost):
	arguments = "-sP -Pn"
	nmScan = nmap.PortScanner()
	nmScan.scan(tgtHost, arguments=arguments)	
	return nmScan[tgtHost].state()

def parseOptions():
	parser = optparse.OptionParser("usage %prog -H " + "<target host> -p <target port> -u <use udp prot> (Optional) -b <grab banner> (Optional) -w <file to write> (Optional)")
	parser.add_option("-H", dest="tgtHost", type="string", help="specify target host")
	parser.add_option("-p", dest="tgtPort", type="string", help="specify target port, all for 1-65534")
	parser.add_option("-w", dest="writeFile", type="string", help="write to file")
	parser.add_option("-u", action="store_true", dest="scanPrt", help="specify udp protocol", default=False)
	parser.add_option("-b", action="store_true", dest="banGrab", help="tell scanner to grab banner", default=False)
	return parser

def nmapScan(tgtHost, tgtPort, options):
	arguments = "-sS -Pn --open"
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
	if (state == "open") & (banGrab == True):
		results = grabBanner(tgtHost, tgtPort)
		print " |_ " + str(results)


def main():
	parser = parseOptions()
	(options, args) = parser.parse_args()
	tgtHost = options.tgtHost
	# TODO implement the all ports option
	tgtPorts = str(options.tgtPort).split(",")
	if (tgtHost == None) | (tgtPorts[0] == None):
		print parser.usage
		exit(0)
	print "[*] Scanning: " + tgtHost
	print "[*] Host is " + checkTgtStatus(tgtHost)
	for tgtPort in tgtPorts:
		nmapScan(tgtHost, tgtPort, options)

if __name__ == '__main__':
	main()


