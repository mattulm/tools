#!/usr/bin/python
import urllib2
site = raw_input("site : ") # http://www.google.com/ ---> this must be in this form
list = open((raw_input("list with folders : "))) # a textfile , one folder/line
for folder in list :
    try :
        url = site+folder
        urllib2.urlopen(url).read()
        msg = "[-] folder " + folder + " exist"
        print msg
    except :
        msg = "[-] folder " + folder + "does not exist"
        print msg
print ""
print "[-] done"
