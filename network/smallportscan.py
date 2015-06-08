import socket
for port in range(20,25):
	try:
		s = socket.socket()
		print "[+] Attempting to connect to 127.0.0.1: "+ str(port)
		s.connect(('127.0.0.1',port))
		s.send('scan')
		banner = s.recv(1024)
		if banner:
			print "[+] Port " + str(port) +"open: \n"+banner
		s.close
	except:pass 
