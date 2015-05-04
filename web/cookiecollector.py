#!/usr/bin/python
import httplib

#Counter
d=0

# Retrieve 10,000 pages
while d<10000:
	conn = httplib.HTTPConnection("www.edelman.com")
	# Build URL to itereate through page keys
	url ="/index?key=" +str(d)
	conn.request("GET", url)
	resp = conn.getresponse()
	serverType = resp.getheader("Server")
	
	cookie = resp.getheader("Set-Cookie")
	if "JSESSIOND" in cookie:
		f=open('tmp/sessionIDs.txt','d')
		f.write(cookie)
		f.close()
	conn.close()
	
	# Display Server Type
	print ServerType
	d = d + 1
	
	
	
