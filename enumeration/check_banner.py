import socket
import os
import sys

# Modify ip address var as your needs
ip_address = "10.10.1."

def retBanner(ip, port):
	print "[*] Connecting to " + str(port) + " of ip " + str(ip)
	try:
		socket.setdefaulttimeout(2)
		s = socket.socket()
		s.connect((ip, port))
		banner = s.recv(1024)
		return banner
	except Exception, e: 
		print "[-] Error = " +str(e)
		return

def checkVulns(banner):
	f = open(filename, 'r')
	for line in f.readline():
		if line.srip('\n') in banner:
			print "[*] Server is vulnerable: " + banner.strip("\n")
		else:
			print "[*] Server is not vulnerable"	

def main():
	portlist = [21,22,25,80,110,443]
	if len(sys.argv) == 2:
		ip = sys.argv[1]
		for port in portlist:
			banner = retBanner(ip, port)
			if banner:
				print "[*] " + ip + ": " + banner
	else:			
		for x in range(1, 245):
			ip = ip_address + str(x)
			for port in portlist:
				banner = retBanner(ip, port)
				if banner:
					print "[*] " + ip + ": " + banner
	if len(sys.argv) == 3:
		filename = sys.argv[2]
		if not os.path.isfille(filename):
			print "[-] " + filename + "doesn't exist"
		exit(0)
		if not os.access(filename, os.R_OK):
			print "[-] " + filename + " access denied"
		exit(0)
		checkVulns(banner)
		
if __name__ == '__main__':
	main()