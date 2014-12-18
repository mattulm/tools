import socket, ssl, pprint,sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ciphers = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"


# Require a certificate from the server. We used a self-signed certificate
# so here ca_certs must be the server certificate itself.
ssl_sock = ssl.wrap_socket(s)

host = sys.argv[1]
port = int(sys.argv[2])
ssl_sock.connect((host, port))

cipher= ssl_sock.cipher()
print cipher[0]
