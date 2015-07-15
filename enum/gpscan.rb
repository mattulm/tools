#!/usr/bin/env ruby

# == gpscan: Scan Google Profile for a list of people who mention the specified company
#
# gpscan uses a google dork to search for people who mention the specified company
# name in their Google Profiles
#
# Thanks to Matias Brutti for the google scraping code. For a more thorough implemention
# of this concept try his tool ESearchy available from http://github.com/FreedomCoder/esearchy
#
# == Usage
#
# gpscan.rb <company name>
#
# -h, --help:
#    show help
#
# <company name>: The company to look for
#
# 1.0 Released
# 1.1 Updated the google search string, thanks to Raul Siles (raul@taddong.com) for the new one
#
# Author:: Robin Wood (robin@digininja.org)
# Copyright:: Copyright (c) Robin Wood 2011
# Licence:: Creative Commons Attribution-Share Alike Licence
#

require "cgi"
require 'net/http'
require 'uri'
#
#
# Display the usage
def usage
	puts"gpscan 1.1 Robin Wood (dninja@gmail.com) (www.digininja.org)

Usage: gpscan.rb <company name>
	--help, -h: show help

	<company name>: The company to look for

"
	exit
end

if ARGV.size != 1
	usage
end

company_name = ARGV[0]

if company_name == "--help" or company_name == "-h"
	usage
end

puts "Scanning Google Profiles for employees of " + company_name

company_name = CGI::escape company_name

url = '/custom?num=100&hl=en&q=site%3Awww.google.com+intitle%3A"Google+Profile"+"Companies+I\'ve+worked+for"+"at+' + company_name + '"&btnG=Search'
#url = "/cse?q=site:www.google.com+intitle:%22Google+Profile%22+%22Companies+I%27ve+worked+for%22+%22at+" + company_name + "%22&hl=en&cof=&num=100&filter=0"
params = {'User-Agent' => "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"}
site = "www.google.com"
port = 80

#puts "query = " + site + url

http = Net::HTTP.new(site, port)
data = []

http.start do |http|
	request = Net::HTTP::Get.new(url, params)
	response = http.request(request)
	#puts response
	if response.body =~ /did not match any documents./
		puts "No results found"
		exit
	else 
		data = response.body.scan(/<h2 class="r"><a class="l" href="([^"]*)[^>]*>([^>]*) - <b>Google Profile<\/b>/im)
	end
end

data.each { |x|
	puts "Name: " + x[1]
	puts "Profile URL: " + x[0]
	puts
}

