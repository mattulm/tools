#!/usr/bin/env python

from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

for i in xrange(10):
      pkt=sr1(IP(dst='www.google.com')/TCP(sport=9999,dport=20+i, flags='S'))
      if pkt.getlayer(TCP).flags == 18L:
            print 'Port %s is open' %pkt.getlayer(TCP).sport
      elif pkt.getlayer(TCP).flags == 20L:
            print 'Port %s is closed' %pkt.getlayer(TCP).sport
