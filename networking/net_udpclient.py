#!/usr/bin/python

import socket
import optparse

# the garbage string to send
global garbage
garbage = "AAAAAAABBBBBBBBBBBCCCCCCCCCCC"

def Client(target_host, target_port):
	try:
		client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		client.sendto(garbage,(target_host,target_port))
		data, response = client.recvfrom(4096)
		return data
	except:
		print "Could not connect to Host or port"

def main():
	parser = optparse.OptionParser("usage %prog -H " + "<target host> -p <target port>")
	parser.add_option("-H", dest="tgtHost", type="string", help="specify target host")
	parser.add_option("-p", dest="tgtPort", type="string", help="specify target port")
	(options, args) = parser.parse_args()
	tgtHost = options.tgtHost
	tgtPort = options.tgtPort
	if (tgtHost == None) | (tgtPort == None):
		print "[-] You nust specify a target host and port"
		exit(0)
	resp = Client(tgtHost, tgtPort)
	if resp != None:
		print resp

if __name__ == '__main__':
	main()