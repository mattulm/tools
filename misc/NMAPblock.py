#!/usr/bin/python
# This was written for educational purpose and pentest only. Use it at your own risk.
# Author will be not responsible for any damage!
# !!! Special greetz for my friend sinner_01 !!!
# Toolname        : nmapBlock.py
# Coder           : baltazar a.k.a b4ltazar < b4ltazar@gmail.com>
# Version         : 0.1
# Greetz for rsauron and low1z, great python coders
# greetz for d3hydr8, r45c4l, fx0, Soul, MikiSoft, c0ax, b0ne and all members of ex darkc0de.com, ljuska.org
 
import sys, subprocess
 
def logo():
  print "\n|---------------------------------------------------------------|"
  print "| b4ltazar[@]gmail[dot]com                                      |"
  print "|   05/2012     nmapBlock.py    v.0.1                           |"
  print "|        b4ltazar.wordpress.com                                 |"
  print "|                                                               |"
  print "|---------------------------------------------------------------|\n"
   
if sys.platform == 'linux' or sys.platform == 'linux2':
    subprocess.call("clear", shell=True)
    logo()
else:
    subprocess.call("cls", shell=True)
    logo()
    print "This is not Unix system, sorry!"
    print "Thanks for using script, please visit b4ltazar.wordpress.com"
    sys.exit(1)
     
subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
subprocess.call("iptables -F", shell=True)
subprocess.call("iptables -t nat -F", shell=True)
subprocess.call("iptables -t filter -A INPUT -p TCP -m state --state RELATED,ESTABLISHED -j ACCEPT", shell=True)
subprocess.call("iptables -t filter -A INPUT -p UDP -m state --state RELATED,ESTABLISHED -j ACCEPT", shell=True)
subprocess.call("iptables -t filter -A INPUT -p ICMP -m state --state RELATED,ESTABLISHED -j ACCEPT", shell=True)
subprocess.call("iptables -t filter -A INPUT -m state --state INVALID -j DROP", shell=True)
subprocess.call('iptables -t filter -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j LOG --log-prefix "FIN: "', shell=True)
subprocess.call("iptables -t filter -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP", shell=True)
subprocess.call('iptables -t filter -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j LOG --log-prefix "PSH: "', shell=True)
subprocess.call("iptables -t filter -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP", shell=True)
subprocess.call('iptables -t filter -A INPUT -p tcp --tcp-flags ACK,URG URG -j LOG --log-prefix "URG: "', shell=True)
subprocess.call("iptables -t filter -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP", shell=True)
subprocess.call('iptables -t filter -A INPUT -p tcp --tcp-flags ALL ALL -j LOG --log-prefix "XMAS scan: "', shell=True)
subprocess.call("iptables -t filter -A INPUT -p tcp --tcp-flags ALL ALL -j DROP", shell=True)
subprocess.call('iptables -t filter -A INPUT -p tcp --tcp-flags ALL NONE -j LOG --log-prefix "NULL scan: "', shell=True)
subprocess.call("iptables -t filter -A INPUT -p tcp --tcp-flags ALL NONE -j DROP", shell=True)
subprocess.call('iptables -t filter -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j LOG --log-prefix "pscan: "', shell=True)
subprocess.call("iptables -t filter -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP", shell=True)
subprocess.call('iptables -t filter -A INPUT -p tcp --tcp-flags SYN,FIN SYN, FIN -j LOG --log-prefix "pscan 2: "', shell=True)
subprocess.call("iptables -t filter -A INPUT -p tcp --tcp-flags SYN,FIN SYN, FIN -j DROP", shell=True)
subprocess.call('iptables -t filter -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j LOG --log-prefix "pscan 2: "', shell=True)
subprocess.call("iptables -t filter -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP", shell=True)
subprocess.call('iptables -t filter -A INPUT -p tcp --tcp-flags ALL SYN,FIN -j LOG --log-prefix "SYNFIN-SCAN: "', shell=True)
subprocess.call("iptables -t filter -A INPUT -p tcp --tcp-flags ALL SYN,FIN -j DROP", shell=True)
subprocess.call('iptables -t filter -A INPUT -p tcp --tcp-flags ALL URG,PSH,FIN -j LOG --log-prefix "NMAP-XMAS-SCAN: "', shell=True)
subprocess.call("iptables -t filter -A INPUT -p tcp --tcp-flags ALL URG,PSH,FIN -j DROP", shell=True)
subprocess.call('iptables -t filter -A INPUT -p tcp --tcp-flags ALL FIN -j LOG --log-prefix "FIN-SCAN: "', shell=True)
subprocess.call("iptables -t filter -A INPUT -p tcp --tcp-flags ALL FIN -j DROP", shell=True)
subprocess.call('iptables -t filter -A INPUT -p tcp --tcp-flags ALL URG,PSH,SYN,FIN -j LOG --log-prefix "NMAP-ID: "', shell=True)
subprocess.call("iptables -t filter -A INPUT -p tcp --tcp-flags ALL URG,PSH,SYN,FIN -j DROP", shell=True)
subprocess.call('iptables -t filter -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j LOG --log-prefix "SYN-RST: "', shell=True)
