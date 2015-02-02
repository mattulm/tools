#!/usr/bin/env python
import socket
import subprocess
import sys
from datetime import datetime

remoteServer	= raw_input("Enter a remote host to scan: ")
remoteServerIP	= socket.gethostbyname(remoteServer)

try:
	for port in range(1,1025):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		result = sock.connect_ex((remoteServerIP, port))
		if result == 0:
			print "Port {}: \t Open".format(port)
		sock.close()
		
except socket.gaierror:
	print 'Hostname could not be resolved. Exiting'
	sys.exit()
	
except socket.error:
	print "Could not connect to the server"
	sys.exit()
	


