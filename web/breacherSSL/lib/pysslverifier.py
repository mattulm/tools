####################################################################################################################################
####
#### This python script will verify Certificate Signer of REMOTE SSL HOST AND PORT against Firefox Trusted Root CAs
####
#### Aung Khant, http://yehg.net/
####
###################################################################################################################################


import socket
import ssl
import sys
import os


# Download the latest ROOT CA
# http://curl.haxx.se/ca/cacert.pem

ca_cert_path = "trusted-ca"
ca_cert_file = "firefox-cacert.pem"


host = "127.0.0.1"
port = 443

if (len(sys.argv) ==1):
    print "Usage: %s host port=443" % __file__
    sys.exit(1)
elif (len(sys.argv) ==2):
    host = sys.argv[1]
elif (len(sys.argv) ==3):
    host = sys.argv[1] 
    port = int(sys.argv[2])
else:
    host = sys.argv[1]
    port = int(sys.argv[2])
    ca_cert_file =sys.argv[3] 

current_path = os.path.dirname(os.path.realpath(__file__))
current_path = current_path.replace("lib","")
new_ca_path = os.path.join(current_path,ca_cert_path,ca_cert_file)
print new_ca_path

try:
    sock = socket.socket()
    sock = ssl.wrap_socket(sock,
      cert_reqs=ssl.CERT_REQUIRED,
      ca_certs=new_ca_path,
      ciphers="HIGH:-aNULL:-eNULL:-PSK:RC4-SHA:RC4-MD5" 
      
    )
    sock.settimeout(9.0)
    sock.connect((host, port))
    cert = ssl.get_server_certificate((host,port))
    print cert
    
except socket.error as msg:
    print  msg
    # known bug
    if str(msg).find("EOF occurred in violation of protocol")>-1:
        print "signer-OK"
    elif str(msg).find("certificate verify failed")>-1:
        print "NO"
        sys.exit(1)
    sys.exit(1)

sock.sendall( "GET http://"+ host + "/ HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Mozilla/5.0 (iPhone; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0 Mobile/1A498b Safari/419.3\r\nConnection: close\r\n\r\n")
data = sock.recv(1024)
sock.close()
#print "Received: \n", repr(data)
print "signer-OK"
