#!/usr/bin/python2.7

import sys
import socket
import getopt
import threading
import subprocess

#global vars

listen				= False
command				= False
uplaod 				= False
execute 			= ""
target 				= ""
upload_destination 	= ""
port 				= 0

def run_command(command):
	
	# trim the new line
	command = command.rstrip()
	print "[*] Processing command: %s" % command
	# run the command and get the oputput back
	try:
		output = subprocess.check_output(command,stderr=subprocess.STDOUT, shell=True)
	except:
		output = "Failed to execute command \r\n"

	# send the output back to the client
	return output

def client_handler(client_socket):
	global upload
	global execute
	global command

	# check for upload
	if len(upload_destination):

		# read in all of the bytes and write to the destination
		file_buffer = ""

		# keep reading data until none is available
		while True:
			data = client_socket.recv(1024)

			if not data:
				break
			else:
				file_buffer += data

	 	# take this bytes and try to write them out
		try:
			file_descriptor = open(upload_destination,"wb")
			file_descriptor.write(file_buffer)
			file_descriptor.close()
		except:
			client_socket.send("Failed to save file to %s\r\n" % upload_destination)

	# check for command execution
	if len(execute):
		# run the command
		output = run_command(execute)
		client_socket.send(output)

	# another loop if a command shell was requested
	if command:

		while True:
			# show a simple prompt
			client_socket.send("<bolo shell #> ")

			# receiving until "enter key" is hit
			cmd_buffer = ""
			while "\n" not in cmd_buffer:
				cmd_buffer += client_socket.recv(1024)

			# send back the command output
			response = run_command(cmd_buffer)

			# send back the response
			client_socket.send(response)

def server_loop():
	global target
	global port

	# if no target is defined, we listen on all interfaces
	if not len(target):
		target = "0.0.0.0"

	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.bind((target,port))
	server.listen(5)

	while True:
		client_socket, addr = server.accept()
		print "[*] Accept connection from: %s:%d" % (addr[0],addr[1])

		# spin off a thread to handle our new client
		client_thread = threading.Thread(target=client_handler, args=(client_socket,))
		client_thread.start()

def client_sender(buffer):
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	try:
		#connect to our target host
		client.connect((target,port))

		if len(buffer):
			client.send(buffer)

		while True:
			# wait for data back to us
			recv_len = 1
			response = ""
			while recv_len:
				data = client.recv(4096)
				recv_len = len(data)
				response += data

				if recv_len < 4096:
					break
			print response,

			# wait for more input
			buffer = raw_input("")
			buffer += "\n"

			#send it off
			client.send(buffer)

	except:
		print "[*] Exception! Exiting..."

		#close the connection
		client.close()	

def usage():
	print "Netcat Clone Tool"
	print 
	print "Usage: net_nc_clone.py -t target_host -p port"
	print "-l --listen					- listen on [host]:[port] for incoming connections"
	print "-e --execute=<file to run>	- execute the given file upon receiving a connection"
	print "-c --command 				- initialize a command shell"
	print "-u --upload=<destination>	- upon receiving a connection upload a file and write it to <destination>"
	print
	print
	print "Examples: "
	print "net_nc_clone.py -t 192.168.0.10 -p 5555 -l -c"
	print "net_nc_clone.py -t 192.168.0.10 -p 5555 -l -u c:\\target.exe"
	print "net_nc_clone.py -t 192.168.0.10 -p 5555 -l -e \"cat /etc/passwd\""
	print "echo 'ABCDEFG' | ./net_nc_clone.py -t 192.168.0.10 -p 135"
	sys.exit(0)

def main():
	global listen				
	global command				
	global upload 				
	global execute 			
	global target 				
	global upload_destination 	
	global port

	if not len(sys.argv[1:]):
		usage()

#read the command line options

	try:
		opts, args = getopt.getopt(sys.argv[1:],"hle:t:p:cu:",["help","listen","execute","target","port","command","upload"])
	except getopt.GetoptError as err:
		print str(err)
		usage()

	for o,a in opts:
		if o in ("-h","--help"):
			usage()
		elif o in ("-l", "--listen"):
			listen = True
		elif o in ("-e","--execute"):
			execute = a
		elif o in ("-c", "--command"):
			command = True
		elif o in ("-u","--upload"): 
			upload_destination = a
		elif o in ("-t", "--target"):
			target = a
		elif o in ("-p", "--port"):
			port = int(a)
		else:
			assert False, "Unhandled option"

# are we going to listen or just send data from stdin?

	if not listen and len(target) and port > 0:
		# read the buffer from command line
		# send CTRL-D if not sending input to stdin
		buffer = sys.stdin.read()

		# send data off
		client_sender(buffer)

# otherwhise we are going to listen and maybe upload things, execute commands, drop shells back
# depending on options above
	
	if listen:
		server_loop()

main()		






















