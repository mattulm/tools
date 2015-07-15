#!/usr/bin/env python

try:
    import socket
    import argparse
    import os.path
except Exception as e:
    print "Some modules are missing...\nCheck the output error: "
    print e

def options():
	parser = argparse.ArgumentParser(description='Check for smtp server and test email addresses')
	parser.add_argument('-s', '--server', help='Enter a list input of server (file)', required=True)
	parser.add_argument('-u', '--user', help='Enter a list input of user to test email address (file)', required=False)
	args = vars(parser.parse_args())
	return args

def main():
    args = options()
    countServer = 0

    if args['server']:
        serverInput = args['server']
        if os.path.isfile(serverInput):
            fileServerInput = open(serverInput, 'r')
            dataServer = fileServerInput.read()
            dataServer = dataServer.split("\n")
            del dataServer[-1]
            try:
                for itemDataServer in dataServer:
                    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    print "Target server: %s" % itemDataServer
                    connect=s.connect((itemDataServer, 25))
                    banner=s.recv(1024)
                    print "banner :", banner,
                    if args['user']:
                        userInput = args['user']
                        if os.path.isfile(userInput):
                            fileUserInput = open(userInput, 'r')
                            dataUser = fileUserInput.read()
                            dataUser = dataUser.split("\n")
                            del dataUser[-1]
                            try:
                                for itemDataUser in dataUser:
                                    s.send("VRFY " + itemDataUser + "\r\n")
                                    result=s.recv(1024)

                                    if "250" in result:
                                        print "VRFY: %s exist" % (itemDataUser)

                                    if "252" in result:
                                        print "VRFY: User %s appears to be valid but could not be verified" % (itemDataUser)

                                    if "502" in result:
                                        print "VRFY: Command disallowed (%s)" % (itemDataUser)

                                    if "550" in result:
                                        print "VRFY: %s does not exist" % (itemDataUser)

                                print ""

                            except socket.error:
                                print "Connection refused"

                        else:
                            s.send("VRFY " + userInput + "\r\n")
                            result=s.recv(1024)

                            if "250" in result:
                                print "VRFY: %s exist" % (userInput)

                            if "252" in result:
                                print "VRFY: User %s appears to be valid but could not be verified" % (userInput)

                            if "502" in result:
                                print "VRFY: Command disallowed (%s)" % (userInput)

                            if "550" in result:
                                print "VRFY: %s does not exist" % (userInput)

                            print ""
            
            except Exception:
                print "error"

        else:
            try:
                s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                print "Target: %s" % serverInput
                connect=s.connect((serverInput, 25))
                banner=s.recv(1024)
                print "banner: ", banner,
                
            except Exception as e:
                print serverInput , ": port 25 blocked\n"
                print e
                s.close()

            if args['user']:
                userInput = args['user']
                if os.path.isfile(userInput):
                    fileUserInput = open(userInput, 'r')
                    dataUser = fileUserInput.read()
                    dataUser = dataUser.split("\n")
                    del dataUser[-1]
                    try:
                        for itemDataUser in dataUser:
                            s.send("VRFY " + itemDataUser + "\r\n")
                            result=s.recv(1024)

                            if "250" in result:
                                print "VRFY: %s exist" % (itemDataUser)

                            if "252" in result:
                                print "VRFY: User %s appears to be valid but could not be verified" % (itemDataUser)

                            if "502" in result:
                                print "VRFY: Command disallowed"

                            if "550" in result:
                                print "VRFY: %s does not exist" % (itemDataUser)

                        print ""

                    except socket.error:
                        print "Connection refused"            
                else:                
                    s.send("VRFY " + userInput + "\r\n")
                    result=s.recv(1024)

                    if "250" in result:
                        print "VRFY: %s exist" % (userInput)

                    if "252" in result:
                        print "VRFY: User %s appears to be valid but could not be verified" % (userInput)

                    if "502" in result:
                        print "VRFY: Command disallowed"

                    if "504" in result:
                        print "VRFY: need fully-qualified address"

                    if "550" in result:
                        print "VRFY: %s does not exist" % (userInput)

if __name__ == '__main__':
    main()