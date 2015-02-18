#!/usr/bin/python
# 
# Copyright (C) 2010 Michael Messner
#
# Description: SNMP user enumeration via the VRFY command
#
# Author: Michael Messner <michael.messner@integralis.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import socket
import sys
import os.path
import logging
import time


if len(sys.argv) < 4:
	print "Usage: %s <IP-Adr> <port> <user> <found-code>" % sys.argv[0]
	print "\t<IP-Adr> could also be a file"
	print "\t<user> could also be a file"
	print "\t<found-code> is optional, if not given we use 252 as found pattern"
	sys.exit(1)

log = logging.getLogger()
ch  = logging.StreamHandler()

debug = 1	#set to 0 for no debugging, set to 1 for debugging messages
log.setLevel(logging.INFO)

logfile = './smtp.log'
if os.path.isfile(logfile):
	print "old logfile found ... removing it"
	print "<Strg>+<c> for interrupt"
	try:
		time.sleep(5)
		os.remove(logfile)
	except:
		print "\n\rinterrupted"
		sys.exit(0)

if os.path.exists(os.path.dirname(logfile)):
	fh = logging.FileHandler(logfile)
else:
	raise "log directory does not exist (" + os.path.dirname(logfile) + ")"
	sys.exit(1)

log.addHandler(ch)
log.addHandler(fh)

port = int(sys.argv[2])

if len(sys.argv) > 4:
	foundcode = sys.argv[4]	#normally 250 or 252
else:
	foundcode = "252" 	# default to 252
	log.info("using default code for valid users = %s" % (foundcode))

if os.path.isfile(sys.argv[1]):
	ips = sys.argv[1]
	try:
		r = open(ips, "r")
	except:
		print "IP file does not exist"
		sys.exit(1)
else:
	ips = sys.argv[1]

if os.path.isfile(sys.argv[3]):
	user = sys.argv[3]
	try:
		f = open(user, "r")
	except:
		print "Userfile does not exist"
		sys.exit(1)
else:
	user = sys.argv[3]

def audit(usern,ips,s):
	usern = usern.strip()
	ips = ips.strip()
	log.info("auditing for user: %s on IP: %s" % (usern,ips))
	s.send('VRFY '+ usern + '\r\n')
	result=s.recv(1024)
	if debug == 1:
		log.info(result)
	if result.startswith(foundcode):
		log.info("valid user: %s on IP: %s " % (usern,ips))
		log.info("#############################################")
	else:
		log.info("not valid user: %s on IP: %s " % (usern,ips))
		log.info("#############################################")

def connection(ips,port,usern):
		try:
			s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			try:
				connect=s.connect((ips, port))
				banner=s.recv(1024)
				log.info("\n\r#############################################")
				if debug == 1:
					log.info('Bannerdetails:\n\r' + banner)
				audit(usern,ips,s)
			except socket.error, msg:
				s = None
		except socket.error, msg:
			s = None
		if s is None:
			ips = ips.strip()
			log.info("\r\n#############################################")
			log.info("Connection error on %s" % (ips))
			log.info("%s" % (msg))
			log.info("#############################################")
		else:
			s.close()

if os.path.isfile(ips):
	for ips in r.readlines():
		log.info("starting auditing for: %s" % (ips))
		if os.path.isfile(user):
			for usern in f.readlines():
				connection(ips,port,usern)
			f.seek(0)
		else:
			connection(ips,port,user)
	r.close()
else:
	log.info("starting auditing for: %s" % (ips))
	if os.path.isfile(user):
		for user in f.readlines():
			connection(ips,port,user)
		f.close()
	else:
		connection(ips,port,user)
fh.close()
