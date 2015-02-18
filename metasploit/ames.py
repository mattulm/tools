from xml.etree import ElementTree as ET
import sys
import os
import subprocess
import string

#### freakyclowns AMES ##################################
# AMES - Another Metasploit Exploit Suggester		#				
#	(pronounced AIMS)				#
# Inspired by a perl tool that Fish originally wrote	#
# 							#
# This however is written from scratch to use the new	#
# nessus xml output inplace of the old .nbe file format	#
# version 0.1 alpha 21/01/14				#
# version 0.1 beta 22/01/14				#
#							#
#########################################################

# Changelog
# 0.1 alpha - written from scratch 100% change
# 0.1 beta
#  fixed duplicate cve findings for different OS's
#  added colors and debug code


####  usage #####################################
#						#
# python progname.py nessus.outputfile		#
#						#
#################################################

# You need to update this line with your trunk folder - e.g. /opt/metasploit/apps/pro/msf3/modules/exploits/
# it must end in a /
trunk = "UPDATEME"
#trunk = "/opt/metasploit/apps/pro/msf3/modules/exploits/"
winpayload = "windows/meterpreter/bind_tcp"
linuxpayload = "linux/x86/meterpreter/bind_tcp"
javapayload = "java/meterpreter/bind_tcp"
solpayload = "solaris/x86/shell_bind_tcp"
osxpayload = "osx/x64/shell_bind_tcp"


#change debug = 1 to turn on debugging
debug = 0
# change colors = 0 to turn off debugging
colors = 1
purple = "\33[0;35m"
teal = "\33[0;36m"
orange = "\33[0;33m"
red = "\33[0;31m"
rstcolor = "\033[0;0m"

# set up and grav the file and process the xml
NessusFile = sys.argv[1]
tree = ET.parse(NessusFile)
root = tree.getroot()

# Check to see if the trunk is set, generally the first time user
if trunk == "UPDATEME":
    print "You need to update this file with your trunk location"
    exit()

def debugme(starbug):
  #this function is for debugging
	if debug == 1:
		if colors == 1:
			print red+"DEBUGHERE: "+rstcolor, starbug
		else:
			print "DEBUGHERE: ", starbug
	else:
		return	
def subproc(komand):
  # this function just starts a subprocess and returns the output
	proc = subprocess.Popen([komand], stdout=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()
	return out


def grabranking(file):
   #this function greps for the ranking value in the supplied file
	komand = "grep Rank "+ file
	debugme(komand)
	out = subproc(komand)
	# the returned line is full of stuff - we need to strip out only what we need
	plank = out.split("=")
	ranking =plank[1].strip()
	debugme(ranking)
	return ranking

def grabtitle(file):
  #this function greps for the title/name from the supplied file
        komand = '''grep -e "'Name'" '''+ file

	debugme(komand)
        out = subproc(komand)
	
        # the returned line is full of stuff - we need to strip out only what we need
	plank = out.split("'")
	title = plank[3]

	debugme(title)

        return title

def grabos(file):
  # this function greps for the OS platform from the supplied file
        komand = '''grep "'Platform'" '''+ file
	debugme(komand)
	out = subproc(komand)
	# the returned line is full of stuff - we need to strip out only what we need
	plank = out.split("'")
        platform = plank[3]
	debugme(platform)
        return platform

def printme(port,host,exploit,cve,os,rank,title):
  # this function does the main print out stuff
	if colors == 1:
		if rank == "ExcellentRanking":
			rank = purple+rank+rstcolor
		elif rank == "GreatRanking":
			rank = orange+rank+rstcolor
		elif rank == "GoodRanking":
			rank = teal+rank+rstcolor
	print "== ("+rank+")  ("+title+")   ("+os+")  ("+cve+") =="

	# here we set the payload to use based on the OS we found
	if os == "linux":
		payload = linuxpayload
	elif os == "win":
		payload = winpayload

	elif os == "solaris":
		payload = solpayload

	elif os == "osx":
		payload = osxpayload

	elif os == "java":
		payload = javapayload
	else:
		#some payloads we have yet to work out so for now its TODO :(
		payload = "TODO"
	print "msfcli exploit/"+exploit,"PAYLOAD="+payload, "RPORT="+port, "RHOST="+host," E"	
	print ""

def checkcve(cve,port,host):
  # do a grep with the cve provided and grab the files names it matches

	# we need to slice the cve to get a pattern match as nessus modules dont have CVE- infront of their names!
	komand = "grep -l -r "+cve[4:]+" "+trunk+"*"
	debugme(komand)
	out = subproc(komand)

	# we need to split out the returned matches incase we have multiple matches for different OSs
	foobar = out.split("\n")
	
	if len(out) > 0:
		for each in foobar:
			if len(each) > 0:
				rank = grabranking(each)
				title = grabtitle(each)
				os = grabos(each)
				# this line takes the users trunk dir and removes some stuff
				exploit = each[len(trunk):-3]
				# this is it! we get to send all the extracted data to the main print function
				printme(port,host,exploit,cve,os,rank,title)		
				debugme(exploit)		

	
def dom():
  # this function basically just reads in the xml tree and finds what we need and sends it for processing

	for reporthosts in root[1]:
		hostz = reporthosts.get('name')
		for ports in reporthosts:
			portz = ports.get('port')
			element = ports.findall('cve')
			for cve in element:
				seevee = cve.text
				checkcve(seevee,portz,hostz)
				debugme(seevee)


#only one function to run :)
dom()





