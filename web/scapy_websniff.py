#!/usr/bin/env python

from scapy.all import *
from scapy.error import Scapy_Exception
import HTTP

m_iface="wlan0"
count=0

def pktTCP(pkt):
    global count
    count=count+1
    if HTTP.HTTPRequest or HTTP.HTTPResponse in pkt:
        src=pkt[IP].src
        srcport=pkt[IP].sport
        dst=pkt[IP].dst
        dstport=pkt[IP].dport
        test=pkt[TCP].payload
        if HTTP.HTTPRequest in pkt:
            print "HTTP Request:"
            print test
            print "======================================================================"

        if HTTP.HTTPResponse in pkt:
            print "HTTP Response:"
            print test
            print "======================================================================"
      
sniff(filter='tcp and port 80',iface=m_iface,prn=pktTCP)
