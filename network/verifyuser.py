#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 2:
	print "Usage: verfy.py <username>"
	sys.exit(0)
	
# Create a Socket
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the Server
connect=s.connetct(('192.168.34.231',25))

# Receive the banner
banner=s.recv(1024)
print banner

# VRFY a username
s.send('VRFY' + sys.argv[1] + '\r\n')
result=s.recv(1024)
print result

# Close the circuit
s.close()


