#!/usr/bin/env ruby

################################################################################
#    Full Path Discloser / Error Hunter
#  
#    license: GPL 
#    released date: 2010-09-28
#     
#    last updated: 2012-01-26
#
#    (c) Aung Khant, http://yehg.net               
#                                                 
#    YGN Ethical Hacker Group, Yangon, Myanmar
#
#    Check the update via
#    svn checkout http://inspathx.googlecode.com/svn/trunk/ inspathx   
#
#    Send bugs, suggestions, contributions to inspathx @ yehg .net
#        
#    How's it useful?
#    
#    Web application developers sometimes fail to add safe checks against
#    authentications, file inclusion ..etc are prone
#    to reveal possible sensitive information when
#    those applications' URLs are directly requested.
#    Sometimes, it's a clue to File Inclusion vulnerability.
#    For open-source applications, source code can be downloaded and 
#    checked to find such information. 
#    
#    This script will do this job.
#    First you have to download source archived file of your desired OSS.
#    Second, extract it.
#    Third, feed its path to inspath
#    
#    The inspath takes
#    Required:
#
#    -d with source directory (of application like /src/webapp/joomla)
#    -u with the target base URL (like http://localhost) Avoid specifying file name like http://localhost/index.php
#
#    Optional:
#    -t with the number of threads concurrently to run (default is 10)
#    -l with the language [one of php,asp,aspx,jsp,cfm,all] (default is all)
#    -x with your desired extensions separated by comma(s) (default : php4,php5,php6,php,asp,aspx,jsp,jspx,cfm)
#    -m/--method with http method (either get or post)
#    -q/--data with http data ("a=1&b=2")	
#    -h/--headers with http headers (format: "x-ping-back: %00\r\ncookie: %00)
#    -p/--param-array flag that makes inpathx identify parameters (a=1&b=2) in target url and submit with arrayified parameters (a[]=1&b[]=2)
#    -n/--null-cookie flag to send session cookies with null value
#    -f/--follow flag to indicate whether you want inpathx to follow http redirection
#    
#    -p, -n, -f don't need any value specified. They do their stuffs when you specify -n, -p, -f
#
#    Check out EXAMPLES for more options and usage 
#
#    Read the related text: 
#    http://yehg.net/lab/pr0js/view.php/path_disclosure_vulnerability.txt
#
#    Use portable bash versions if you wish:
#    http://www.pentesterscripting.com/discovery/web_requester
#    http://www.pentesterscripting.com/exploitation/bash_web_parameter_fuzzer
#
################################################################################

require 'net/http'
require 'net/https'
require 'uri'
require 'open-uri'
require 'thread'
require 'find'
require 'logger'
require 'optparse'
require 'erb'
require 'fileutils'

# change it if you want it
$useragent = {'User-Agent'=>'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'}


def log(s)
  logger = Logger.new($logpath)  
  logger.datetime_format = "%Y-%m-%d %H:%M:%S pid:"
  logger.info(s)
  logger.close
end


def logpath(s)
  file  = $logpath + '-path_vuln_.txt'
  logger = Logger.new(file)  
  logger.datetime_format = ""
  logger.info(s)
  logger.close
end

def cleanvlog()
  ologpath = $logpath + '-path_vuln_.txt'
  nlogpath = $logpath + '-path_vuln.txt'

  unless File.exist? ologpath
    return
  end  

  sf = File.new(ologpath,"r")
  furl = []
  while fline = sf.gets
      fu = ''
      if fline.length > 1 and fline =~ /INFO/
          fu = fline.to_s
          fu = fu[fu.index(': ')+2,fu.length]        
          fu.gsub!("\n","") 
          fu.gsub!("\r\n","")
          furl << fu
      end
  end
  
  sf.close
                  
  if furl.length > 0
      flist = File.new(nlogpath,"w")
      flist.puts("# Date: #{Time.now.strftime("%Y-%m-%d %H:%M:%S")}\n\n")
  
      furl.each do |fl|
          flist.puts(fl)
      end
      if File.exist? ologpath
        File.delete ologpath
      end    
  end
  
  flist.close
  

end

def path_check(s)
  p = ''
  if s.class.to_s == 'Array' and s.length == 1 
    p = s[0]
  else 
    p = s    
  end
  if p == ''
    return false
  elsif p.include?'www.w3.org/TR/' or p.include?'my.netscape.com'
    return false
  else
    return true
  end
end

def correct_path(p,u)
    if p!= ''
        p.gsub!(/("|\[)/,"") if p.class.to_s == 'String'
    end
    if u != '' and p.class.to_s == 'Array'
        ps = p[0].to_s.scan(/(\/home\/#{u}\/([0-9a-zA-Z\.\_\-\+]+)\/)/)[0]
        if ps.class.to_s == 'Array' and ps.size > 0
            return ps[0]
        end
    else 
        px = p[0].to_s
       if px =~ /htdocs/
           p = px[0,px.index(/htdocs/)+6].to_s
       elsif px =~ /wwwroot/
           p = px[0,px.index(/wwwroot/)+8].to_s
       elsif px =~ /www/
           p = px[0,px.index(/www/)+4].to_s
       elsif px =~ /public_html/
           p = px[0,px.index(/public_html/)+12].to_s
       elsif px.scan(/\/[\w]+\/[\w]+\//).length > 0
           p = px.scan(/\/[\w]+\/[\w]+\//)[0].to_s
       end
    end
    return p
end

def user_check(s)
  u = ''
  if u.class.to_s == 'Array' and u.length == 1     
    u = s[0]
  else 
    u = s    
  end
  if u == ''
    return false
  else
    return true
  end
end

def get_cookie(url,data='',headers={},follow_redirect=false,key='',cert='')
    
    cookies = []
    uri = URI.parse(url)
    uri.path += '/' if uri.path.size == 0
    http = Net::HTTP.new(uri.host,uri.port)
    http.read_timeout = 180
    http.open_timeout = 180 

    if uri.scheme == "https"
        http.use_ssl= true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE

        if key != ''
            http.key = key
            http.cert = cert
        end
    end
    
    if data != ''
        req,body = http.get(uri.path+'?'+data,headers)    
    else
        req,body = http.get(uri.path,headers)    
    end   
    
    if /(20|30)/.match(req.code.to_s) 
        unless req.header["set-cookie"] == nil
            req.get_fields('Set-Cookie').each  do |v|
                c1 = v.split(';')
                c1.each do|v|
                    unless v =~ /(domain|expires|httpOnly|path)/
                        cookies << v.split('=')[0]
                    end
                end
            end            
        end 
    end
    cookies.compact!
    cookies.uniq!
    return cookies
end

def prepare_cookies(sa)
    cookies = ''    
    if sa.class.to_s == 'Array'
        sa.map!{ |s| s + '='}
        sa.each do |v|
            cookies = cookies + v + '; '
        end
    end    
    return cookies
end

def get_params(param_num,url,data,headers,key,cert)
    params = []
    links = []
    param_num = 1 if param_num == '' or param_num == 0
    uri = URI.parse(url)
    uri.path += '/' if uri.path.size == 0
    http = Net::HTTP.new(uri.host,uri.port)
    http.read_timeout = 100
    http.open_timeout = 80

    if uri.scheme == "https"
        http.use_ssl= true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE

        if key != ''
            http.key = key
            http.cert = cert
        end
    end

    if data != ''
        req,body = http.get(uri.path+'?'+data,headers)    
    else
        req,body = http.get(uri.path,headers)    
    end   

    target = uri.scheme + '://' + uri.host

    body.scan(/href="(.*?)"/){
        link = $1        
        if link =~ /^(\/|[a-z]|\?)/ or link =~ /^#{target}/        
            if link =~ /(\?|\=)/ and link !~ /^java/         
                links << link
            end
        end    
    }
    body.scan(/href='(.*?)'/){
        link = $1        
        if link =~ /^(\/|[a-z]|\?)/ or link =~ /^#{target}/        
            if link =~ /(\?|\=)/ and link !~ /^java/
                links << link
            end
        end    
    }
    
    if links.length > 0
        links.each do|l|            
            c = []
            d = []
            a = l.split('?')
            a.each do |b|                                
                if b.include?'='
                    if b =~ /(&amp;[a-zA-Z]+=)/
                        c = b.split('&amp;')                        
                        c.each do |d|                           
                           params << d.split('=')[0] 
                        end
                    elsif b.include?'&'
                        c = b.split('&')
                        c.each do |d|
                           params << d.split('=')[0] 
                        end
                    else
                        params << b.split('=')[0] 
                    end
                end
            end
        end
    end
    params.uniq!
    params.compact!
    str = ''
    if params.class.to_s == 'Array'
        pnum = '[]'*param_num
        params.map!{ |s| s + pnum + '='}
        params.each do |v|
            str = str + v + '&'
        end
    end   
    return str
end

def decompress(string, type='deflate')
  require 'zlib'
  require 'stringio'
  buf = ''
  if type == 'deflate'
    zstream = Zlib::Inflate.new
    buf = zstream.inflate(string)
    zstream.finish
    zstream.close
  elsif type == 'gzip'
    tmp = Zlib::GzipReader.new(StringIO.new(string))
    buf = tmp.read
  end
  buf
end

def fix_uri(u)
    URI.escape(u.to_s, Regexp.new("[^-_.!~*'\(\)a-zA-Z0-9\\d\/@\$]"))
end

def clean_ddslash(u)
   
   nu = u
   
   sc = 'http://' if /^http:/.match(u)
   sc = 'https://' if /^https:/.match(u)

   nu.sub!('http://','')
   nu.sub!('https://','')

   if nu.include?'//'
      nu.gsub!('//','/')
      return sc + nu
   end
   nu = sc + nu 
   return nu

end
def extract_scheme(u)
    unless u.split('/')[0] == nil
        return u[0,u.split('/')[0].length-1]
    else 
        return 'http'
    end
end

def extract_host(u)
    unless u.split('/')[2] == nil
        return u.split('/')[2]
    else
        return '/'
    end
end

def extract_uri(s,h,u)
    s = s + '://'
    return u[s.length+h.length,u.length]
end

def get_url(url,key='',cert='',method='get',data='',headers={},null_cookie=false, follow_redirect=false,regexp='')   
  begin    
    
    uri = URI.parse(url)
    uri.path += '/' if uri.path.size == 0    
    http = Net::HTTP.new(uri.host,uri.port)
    http.read_timeout = 100
    http.open_timeout = 80

    if uri.scheme == "https"
        http.use_ssl= true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE

        if key != ''
            http.key = key
            http.cert = cert
        end
    end

    is_vuln = false
    query = ''
    query = uri.query unless uri.query == nil or uri.query == ''    
    if method == 'head'
            req,body = http.get(uri.path,headers)    
            if req['X-AspNet-Version'] =~ /^1/i
                puts '[*] testing for dotnet 1.x full path disclosure ..'
                get_url(url + 'a%5c.aspx',key,cert,'get',data='',headers={},null_cookie=false, follow_redirect=false,regexp='')
                get_url(url + '~.aspx',key,cert,'get',data='',headers={},null_cookie=false, follow_redirect=false,regexp='')
                return
            end
    elsif method == 'get'
        query = query + '&' + data unless data == ''
        if query != ''
            req,body = http.get(uri.path+'?'+query,headers)    
        else
            req,body = http.get(uri.path,headers)    
        end
    else
        if query != ''
            req,body = http.post2(uri.path+'?'+query,data,headers)    
        else
            req,body = http.post2(uri.path,data,headers)    
        end
    end
    
    if req.code =~ /(301|302)/        
        if follow_redirect == true
            puts "-> #{url} | #{req.code.to_s}\n(Redirected to : " + req.header["location"]  + ")\n\n"
            if req.header["location"] =~ /^http/i
                get_url(req.header["location"],key,cert,'get',data='',headers={},null_cookie=false, follow_redirect=false,regexp='')
            else 
                newurl = uri.scheme + "://" + uri.host
                newurl += ":" + uri.port.to_s if uri.port != nil
                if req.header["location"] !~ /^\//
                    newurl += uri.path.to_s.sub(/[^\/]*$/, "") + "/"
                end
                get_url(newurl + req.header["location"],key,cert,'get',data='',headers={},null_cookie=false, follow_redirect=false,regexp='')
                #get_url($target.to_s + req.header["location"],key,cert,'get',data='',headers={},null_cookie=false, follow_redirect=false,regexp='')
            end
        end
    end
    
    if req['Content-Encoding'] =~ /gzip|deflate/
        body = decompress(body,req['Content-Encoding'])
    end

    
    if /(20|50)/.match(req.code.to_s) 
      if body.length < 5 or uri.path =~ /index\.([a-z]{2,4})%$/        
        return 
      end
      
    
      if regexp != ''
        if /(#{regexp})/mi.match(body)
          is_vuln = true
        end  
      end
    
      case $language
          when /(php4|php5|php6|php)/            
            if /((notice|warning|parse\serror|fatal\serror):|<b>(notice|warning|parse\serror|fatal\serror)<\/b>:|undefined\s(variable|constant|index|offset)|PHP\s(notice|warning|error)|\( ! \)<\/span> PropelException:|<b>Warning<\/b>:|Warning:  session_start\(\) \[|<b>Warning<\/b>:  f|Warning:  f|<b>Warning<\/b>:  m|Warning:  m)/mi.match(body)
              is_vuln = true
              puts $1
            end         
          when /(asp|aspx)/
            if /(This error page might contain sensitive information because ASP.NET is configured to show verbose error messages using &lt;customErrors mode="Off"|[HttpException]: The file '|<span><H1>Server Error in '\/' Application.<hr width=100% size=1 color=silver><\/H1> |<span><H1>Server Error in '\/|An unknown error occured in this application.|This error was caught by <b>Application Handler<\/b>.<\/p>|Description: <\/font><\/b>An unhandled exception occurred|COMException \(0x80004005\)|The system cannot find the path specified|<h1>Server Error in|Server Error in \'\/\'|<h1>Server Error<\/h1>|strFileName=|<h2> <i>Invalid file name for monitoring: ')/mi.match(body)
              is_vuln = true
            end         
          when /(jsp|jspx)/
            if /(<b>exception<\/b> <pre>java.lang.IllegalArgumentException: setAttribute:|<pre>org\.apache\.jasper\.JasperException|<u>The server encountered an internal error \(\) that prevented it from fulfilling this request\.<\/u>|<h1>HTTP Status 500 - <\/h1>|at java\.lang\.Thread\.run|at javax\.servlet\.http\.HttpServlet|<PRE>Message Exception occurred in|<H1>500 Internal Server Error<\/H1>|Message Exception occurred|ArgumentException\:)/mi.match(body)
              is_vuln = true
            end  
          when /(cfm)/
            if /(<li>Enable Robust Exception Information to provide greater detail about the source of errors|File not found:|Error Occurred While Processing Request|<div class="Label">Diagnostic Information:<\/div>|The server encountered an internal error and was unable to complete |<cfif|<cfelse|<cfset|<cfquery|<CFLOCATION|<cfoutput|<cfcatch|<cftry|<cfdump|<cferror)/mi.match(body)
                is_vuln = true
            end 
                    
      else            
            if /((notice|warning|parse\serror|fatal\serror):|<b>(notice|warning|parse\serror|fatal\serror)<\/b>:|undefined\s(variable|constant|index|offset)|PHP\s(notice|warning|error)|\( ! \)<\/span> PropelException:|<b>Warning<\/b>:  f|Warning:  f|<b>Warning<\/b>:  m|Warning:  m|This error page might contain sensitive information because ASP.NET is configured to show verbose error messages using &lt;customErrors mode="Off"|[HttpException]: The file '|<span><H1>Server Error in '\/' Application.<hr width=100% size=1 color=silver><\/H1> |<span><H1>Server Error in '\/|An unknown error occured in this application.|This error was caught by <b>Application Handler<\/b>.<\/p>|Description: <\/font><\/b>An unhandled exception occurred|COMException \(0x80004005\)|The system cannot find the path specified|<h1>Server Error in|Server Error in \'\/\'|strFileName=|<h2> <i>Invalid file name for monitoring: '|<h1>Server Error<\/h1>|<b>exception<\/b> <pre>java.lang.IllegalArgumentException: setAttribute:|<pre>org\.apache\.jasper\.JasperException|<u>The server encountered an internal error \(\) that prevented it from fulfilling this request\.<\/u>|<h1>HTTP Status 500 - <\/h1>|at java\.lang\.Thread\.run|at javax\.servlet\.http\.HttpServlet|<PRE>Message Exception occurred in|<H1>500 Internal Server Error<\/H1>|Message Exception occurred|ArgumentException\:|<li>Enable Robust Exception Information to provide greater detail about the source of errors|File not found:|Error Occurred While Processing Request|<div class="Label">Diagnostic Information:<\/div>|The server encountered an internal error and was unable to complete |<cfif|<cfelse|<cfset|<cfquery|<CFLOCATION|<cfoutput|<cfcatch|<cftry|<cfdump|<cferror)/mi.match(body)
                is_vuln = true
                puts $1
            end              
      end
    
      if /<b> Description: <\/b>An application error occurred on the server. The current custom error settings for this application prevent the details of/mi.match(body)
            puts "[*] regex fails. target aspx application is found to enable custom error handler.\n"
     end
    
      if is_vuln == true
          msg = "[*] #{url}"
          log("#{msg}\n\n[html_source]\n#{body}[/html_source]\n\n")          
          
          if $pathval == true
            purl = url
            purl = purl.gsub($target,'')
            msg = "/#{purl}"
            print "\n#{msg}"        
            logpath("#{msg}")           
          else            
            puts "\n#{msg}"  
          end
          
      end 
    elsif req.code == "404"
      #uncomment if you want
      #puts "[!404] #{url} - wrong path or file was removed?"
      #puts
    end	
  rescue Exception=>err
    if err.message !~ /end of file reached/
        if err.message =~ /execution expired/
            puts "\n:( -> #{url} - ERROR: the server does not respond fast enough\ntry again later for more accurate result."
        else
            puts "\n:( -> #{url}\n\ERROR:\n#{err.message}\n"
        end
    end
  end  
end


def print_help(s,p=$0)
  print_banner
  puts s  
  puts <<EOL

Example:
ruby inspathx.rb -u http://localhost/wordpress 
ruby inspathx.rb -u http://localhost/wordpress -p 1
ruby inspathx.rb -d /sources/wordpress -u http://localhost/wordpress
ruby inspathx.rb -d /sources/wordpress -g paths/wordpress-3.0.4
ruby inspathx.rb -d paths/wordpress-3.0.4 -u http://localhost/wordpress
ruby inspathx.rb -d c:/sources/wordpress -u http://localhost/wordpress -t 20 -l php
ruby inspathx.rb -d /sources/jspnuke -u http://localhost/jspnuke -t 20 -l jsp -x jsp,jspx -n

EOL
  exit!
end

def print_banner
  puts "\n=============================================================
Path Discloser (a.k.a inspathx) / Error Hunter
 (c) Aung Khant, aungkhant[at]yehg.net
  YGN Ethical Hacker Group, Myanmar, http://yehg.net/

svn co http://inspathx.googlecode.com/svn/trunk/ inspathx
=============================================================\n\n"
end

def error_msg(s)
    print_banner
    puts 'ERROR:'
    puts 
    puts '[X] ' + s
    exit!
end    

def parse_header(s)
    if s == ''
        return {}
    else
        unless s.to_s.include?':'
            error_msg('Invalid Header Format. Colon(:) must be included. (i.e \'Cookie: userid=%00)')
        end
        h0 = {}
        h1 = s.split('\r\n')
        h1.each do |v|
            h0[v.split(':')[0]] = v.split(':')[1]
        end 
        return h0
    end
end

def parse_data(s)
    if s == ''
        return ''
    else
        unless s.to_s.include?'='
            error_msg('Invalid get/post Data Format. Equal (=) must be included. (i.e "<script>=xss&a=1+or+1=1")')
        end
        h0 = {}
        h2 = {}
        h1 = s.split('&')
        r = ''        
        h1.each do |v|
            h0[v.split('=')[0]] = v.split('=')[1]
        end 
        h0.each do |k,v|
            h2[k] = ERB::Util.url_encode(v.to_s)
        end        
        h2.each do |k,v|
            r = r + k + '=' + v + '&'
        end      
        return r    
    end
end

def deb(s)
    puts '***' + s.to_s
    exit!
end    

def ar2s(ar)
    r = ''
    if ar.class.to_s == 'Array'
        ar.each do |v|
          r = r + v + ','  
        end
        if r.length >= 2
         r = r[0..(r.length-2)] if r[r.length-1] == ','
        end
    end
    return r
end

def is_dotnet1x(u)

end

def main

    begin

        mutex  = Mutex.new
        options = {}  

        parser = OptionParser.new do|opts|

            options[:dir] =  nil
            opts.on('-d','--dir /source/app','set source code directory/source path definition file of application')   do |dir|    
                options[:dir] = dir
            end

            options[:url] = nil
            opts.on('-u','--url http://site.com/','set url') do |url|
                options[:url] = url
            end

            options[:pem] = nil
            opts.on('-k','--keycert <pemfile>','client key + cert PEM file') do |pem|
                options[:pem] = pem
            end

            options[:threads] = 10
            opts.on('-t','--threads 10','set thread number(default: 10)') do |thr|
                options[:threads] = thr
            end  

            options[:language] = 'all'
            opts.on('-l','--language php','set language [php,asp,aspx,jsp,jspx,cfm,all] (default all - means scan all)') do |lan|
                options[:language] = lan
            end  

            options[:extension] = 'php4,php5,php6,php,asp,aspx,jsp,jspx,cfm'
            opts.on('-x','--extension php','set file extensions (php4,php5,...)  default regex: php4,php5,php6,php,asp,aspx,jsp,jspx,cfm') do |ext|
                options[:extension] = ext
            end

            options[:method] = 'get'
            opts.on('-m','--method TYPE','http method get/post (default: get)') do |m|
                options[:method] = m
            end  

            options[:headers] = ''
            opts.on('-h','--headers HEADERS','add http header (eg. "cookie: sid[%00]=1\r\nX-pingback:: %00")') do |h|
                options[:headers] = h
            end  

            options[:data] = ''
            opts.on('-q','--data DATA','http get/post data (e.g "a=<script>&b=../../../")') do |da|
                options[:data] = da
            end  

            options[:null_cookie] = false
            opts.on('-n','--null-cookie','add null session cookie (no need to specify cookie name).') do |c|
                options[:null_cookie] = true
            end 

            options[:follow_redirect] = false
            opts.on('-f','--follow','follow http redirection') do |f|
                options[:follow_redirect] = true
            end  
              
            options[:param_array] = false
            opts.on('-p','--param-array NUM','identify parameters in target url,make \'em array (value: 1 for [], 2 for [][], 3 for [][][], n .... []*n)  <note: --data value untouched>')  do |pa|
                pa = pa.to_i;
                pa = 1 if pa == 0 
                options[:param_array] = pa
            end  

            options[:regexp] = ''
            opts.on('-r','--regexp REGEXP','specify your own regexp to search in returned responses (eg: "require\(([a-zA-Z.\/\.-]+)\)") [will combine with built-in regexp] ') do |re|
                options[:regexp] = re
            end  

            options[:gen] =  nil
            opts.on('-g','--gen FILE','read source directory (-d) & generate file list so next time you can feed this file path in -d option instead of source directory.')   do |ge|    
                options[:gen] = ge
            end

            options[:removedirg] =  false
            opts.on('--rm','remove source directory used to generate path file list.')   do |ge|    
                options[:removedirg] = true
            end

            options[:comment] = ''
            opts.on('-c','--comment STRING','comment for path definition file to be used with -g and -d options. date is automatically appended.')   do |co|    
            options[:comment] = co
            end

            options[:pval] = false
            opts.on('--x-p','show only paths in console and write them to file with path_vuln.txt surfix. This does not contain target url portion.')  do |xv|
                options[:pval] = true
            end  
            
            opts.on('--xp','alias to --x-p')  do |xv|
                options[:pval] = true
            end 
            
            options[:search] = ''
            opts.on('-s','--search STRING','search path definition files in paths/ & paths_vuln/ directories.')   do |se|    
            options[:search] = se
            end
            

        end

        parser.parse!

        if options[:search] != ''
            print_banner()
            search = options[:search]
            search.gsub!(/\*|\&|\[|\]|\|\>|\<|\?|\/|\:|\;|\~|\`|\(|\)|\+|\=/)
            
            
            puts
            puts '~ searching for "' + search + '"  in path definition directories ...'
            puts

            spath = "paths" + File::SEPARATOR
            files = Dir.new(spath).entries
            ffound = 0
            files.each do |f|
                nf = f.downcase
                if nf =~ /(#{search})/
                   puts '--> ' + spath + nf
                   ffound += 1
                end
            end 

            spath = "paths_vuln" + File::SEPARATOR
            files = Dir.new(spath).entries
            
            files.each do |f|
                nf = f.downcase
                if nf =~ /(#{search})/
                   puts '--> ' + spath + nf
                   ffound += 1
                end
            end             
            puts 
            puts "~ 0 file found; tune your search ; case-insensitive" if ffound == 0
            if ffound == 1
                puts "~ #{ffound} file found" 
            elsif ffound > 0
                puts "~ #{ffound} files found" 
            end
            exit!
        end
        
        options[:dir] = ".DUMMY" if options[:dir] == nil
        sourcepath = options[:dir].to_s
        $extension = options[:extension].to_s.downcase().gsub(",","|")
        filter = /\.(#{$extension})$/i
        filter2 = /\.(#{$extension})+/i

        if options[:gen] != nil
            error_msg('-d/--dir option is neccessary when you specify -g/--gen option') if sourcepath == ''
            fgen = options[:gen].to_s
            if  File.directory?sourcepath
                begin
                    flist = File.new(fgen,"w")
                rescue Exception=>err
                    error_msg(err.message)
                end
                print_banner()
                puts
                
                comment = options[:comment]
                puts
                fcount = 0
                flist.puts('# ' + comment)
                flist.puts("# Date: #{Time.now.strftime("%Y-%m-%d %H:%M:%S")}\n\n")
                Find.find(sourcepath) do |fi|
                  type = case
                          when File.file?(fi) then
                             if filter.match(fi)  
                                flist.puts(fi.gsub(sourcepath,'') )
                                fcount += 1
                             end
                         else "?"
                         end  
                end
                puts "\nSuccessfully saved as #{fgen} with #{fcount} file paths.\nNext time, feed its path in -d option.\n\nSend bugs, suggestions, contributions to inspathx[at]yehg.net"
                flist.close
                if options[:removedirg]
                    puts 'Removing directory ' + sourcepath + ' ...'                
                    FileUtils.rm_rf(sourcepath)
                    puts 'Done!'
                end 
                exit!
            else
               error_msg('source directory (-d) does not exist.')
            end
            
        end

        print_help(parser.to_s) if options[:url] == nil 



        targeturl = options[:url].to_s

        targeturl = 'http://' + targeturl unless targeturl =~ /^htt(p|ps):\/\//i
        targeturl += '/' unless targeturl[targeturl.length-1,targeturl.length] == '/'
        targeturl = clean_ddslash(targeturl)
        tscheme = extract_scheme(targeturl)
        thost = extract_host(targeturl)
        tpath = fix_uri(extract_uri(tscheme,thost,targeturl))
        targeturl = tscheme + '://' + thost  + tpath
        targeturl += '/' if URI.parse(targeturl).path.size == 0
        $target = targeturl
        maxthread = options[:threads].to_i
        $language = options[:language].to_s.downcase()

        sourcepath = sourcepath.gsub(/\\/,'/') # window

        if File.directory?sourcepath
            if sourcepath[sourcepath.length-1,sourcepath.length]!='/'
                sourcepath =sourcepath+ '/'
            end
        end    

        sslkey = ''
        sslcert = ''
        if options[:pem]
            pemfile = File.read(options[:pem].to_s)
            sslkey = OpenSSL::PKey::RSA.new(pemfile)
            sslcert = OpenSSL::X509::Certificate.new(pemfile)
        end

        $logpath = targeturl.gsub(/(http|https):\/\//,'')
        $logpath = $logpath.gsub(/\//,'_')
        $logpath = $logpath.gsub(/(\:|\;|\~|\!|\@|\$|\*|\^|\(|\)|\'|\"|\/|<|>|\|)/,'-')
        if $logpath.length > 32 
         $logpath = $logpath[0,32] + '__.log'
        else
         $logpath += '.log'
        end

        server_user_name = '' # extracted from strings like /home/victim/www/....
        server_root = '' # will look like /home/victim/www/

        method = options[:method].to_s
        data = parse_data(options[:data].to_s)
        headers = parse_header(options[:headers].to_s)
        headers = headers.merge($useragent)

        if options[:param_array] != false
            if data == ''
                data = get_params(options[:param_array],targeturl,data,headers,sslkey,sslcert)
            else
                data = data +  get_params(options[:param_array],targeturl,data,headers,sslkey,sslcert)
            end
        end


        if options[:param_array] == true  && options[:method] == 'post'
            if data == '' && options[:method] == 'post'
                error_msg('--data must be specified when the http method is \'post\' and --param-array returns empty')
            end    
        elif  options[:method] == 'post'
            if data == '' 
                error_msg('--data must be specified when the http method is \'post\'')
            end 
        end

        follow_redirect = options[:follow_redirect]
        null_cookie = options[:null_cookie]
        regexp = options[:regexp]

        $pathval = options[:pval]


        # comment if you want to append logging
        if File.exist? $logpath
          File.delete $logpath
        end
        if File.exist? $logpath + '-path_vuln.txt'
          File.delete $logpath + '-path_vuln.txt'
        end
        
          

        #################################################################

        print_banner()
        if sourcepath == '.DUMMY'
            puts "\n# target: " + targeturl[0,targeturl.length-1] 
        else 
            puts "\n# target: #{targeturl}" 
        end
        puts "# source: #{sourcepath}\n# log file: #{$logpath}\n# follow redirect: #{follow_redirect}\n# null cookie: #{null_cookie}\n# param array: #{options[:param_array]}\n# total threads: #{maxthread}\n# time: #{Time.now.strftime("%H:%M:%S %m-%d-%Y")}\n\n"    

         
        log("TargetURL: #{targeturl}")
        log("Source: #{sourcepath}")
        log("Settings: follow redirect: #{follow_redirect},null cookie: #{null_cookie}, param array: #{options[:param_array]}, total threads: #{maxthread}")
        log("Date:  #{Time.now.strftime("%Y-%m-%d %H:%M:%S")}\n\n")


        if null_cookie == true
            puts '# identifying cookies to poison ...'
            url_cookies = get_cookie(targeturl, data, headers, follow_redirect, sslkey, sslcert )
            url_cookies << 'ASP.NET_SessionId' if $language =~ /(aspx)/
            url_cookies << 'ASPSESSIONID'  if $language =~ /(asp)/
            url_cookies << 'JSESSIONID'  if $language =~ /(jsp)/
            url_cookies << 'JSESSION_ALTERNATE'  if $language =~ /(jsp)/
            url_cookies << 'CFID'   if $language =~ /(cfm)/
            url_cookies << 'CFTOKEN'  if $language =~ /(cfm)/
            url_cookies << 'CFGLOBALS' if $language =~ /(cfm)/
            url_cookies << 'PHPSESSID'  if $language =~ /(php)/
            url_cookies.compact!
            url_cookies.uniq!
            puts '# got cookie(s): ' + ar2s(url_cookies) 
            puts 
            ncookies = {'Cookie'=>prepare_cookies(url_cookies)}
            headers = headers.merge(ncookies)
        end 


        Thread.abort_on_exception = true

        scans  = []
        count = 0
        reqcount = 0


        if File.exists?sourcepath
            if File.directory?sourcepath
                Find.find(sourcepath) do |f|
                  type = case
                          when File.file?(f) then
                             if filter.match(f)  
                                xf = fix_uri(f)
                                xf = xf.gsub(sourcepath,targeturl) 
                                scans[count] = Thread.new{
                                  mutex.synchronize do
                                    get_url(xf,sslkey,sslcert,method,data,headers,null_cookie,follow_redirect,regexp)                              
                                  end
                                }
                                count=count+1
                                reqcount=reqcount+1 
                                if (count != 0 && (count%maxthread) == 0)
                                    scans.each {|t|t.join;}
                                    scans = []
                                    count = 0
                                end
                             end
                         else "?"
                         end  
                end
            else
                
                sf = File.new(sourcepath,"r")
                furl = []
                while fline = sf.gets
                    fu = ''
                    if fline.length > 1 and fline !~ /^#/ 
                        if filter.match(fline) or filter2.match(fline)
                            target  = targeturl[0..(targeturl.length-2)] if fline.to_s =~ /^\//
                            fline.to_s.gsub!("\n","")
                            fline.to_s.gsub!("\r\n","")                            
                            fu = target.to_s  + fix_uri(fline.to_s).to_s
                            if fu =~ /NilClass/
                                error_msg('Triggered Nil value for target/uri; Check source path content for validity')
                            end
                            furl << fu
                        elsif sourcepath == '.DUMMY'
                            target  = targeturl[0..(targeturl.length-2)] 
                            furl <<  target
                        end
                    end
                end
                sf.close
                if furl.length > 0
                    furl.each do |fl|
                        scans[count] = Thread.new{
                          mutex.synchronize do
                            get_url(fl,sslkey,sslcert,method,data,headers,null_cookie,follow_redirect,regexp)                              
                          end
                        }
                        count=count+1
                        reqcount=reqcount+1 
                        if (count != 0 && (count%maxthread) == 0)
                            scans.each {|t|t.join;}
                            scans = []
                            count = 0
                        end   
                    end
                end
                
            end
        else
            error_msg('-d source path directory/file does not exist. It can be either a path definition file or a source directory.')
        end

        get_url(targeturl,sslkey,sslcert,'head')
        puts "\n# waiting for child threads to finish .."
        scans.each {|t|t.join;print  "."}

        select(nil,nil,nil,2)

        logcontent = IO.readlines($logpath)
        found = logcontent.to_s.scan("[html_source]").size 
        win = false
        
        if found > 0

           bs = logcontent.to_s.scan(/home\/([0-9a-zA-Z\.\_\-\+]+)\//)[0]
           if bs.class.to_s == 'Array'
                  server_user_name = bs[0].to_s
           end
          
           # check for user name in windows path
           if server_user_name == ''    
                bs = logcontent.to_s.scan(/[a-z]:\\\\(Documents and Settings|Users)\\\\([^<^\\]+)\\\\/i)
                if bs.size > 0
                    if bs[0][1].class.to_s == 'String'
                           server_user_name = bs[0][1]
                          
                    end
                end
           end
            
            # check if there is windows path pattern           
            if logcontent.to_s.scan(/[a-z]:\\\\([^<]+)/i).size > 0
                 win = true 
            end
             
           if win == false
                
                if logcontent.to_s.scan(/<b>([^<]+)<\/b>/).length > 0 
                    
                    server_root = logcontent.to_s.scan(/<b>(\/[^<]+)<\/b>/)[0].to_s
                    if server_root =~ /htdocs/
                        server_root = server_root[0,server_root.index(/htdocs/)+6].to_s
                    elsif server_root =~ /wwwroot/
                        server_root = server_root[0,server_root.index(/wwwroot/)+8].to_s
                    elsif server_root =~ /www/
                        server_root = server_root[0,server_root.index(/www/)+4].to_s
                    elsif server_root =~ /public_html/
                        server_root = server_root[0,server_root.index(/public_html/)+12].to_s
                    elsif server_root.scan(/\/[\w]+\/[\w]+\//).length > 0
                        server_root = server_root.scan(/\/[\w]+\/[\w]+\//)[0].to_s
                    end
                    
                elsif logcontent.to_s.scan(/in (\/[^<]+) on line/).length > 0 
                    
                    server_root = logcontent.to_s.scan(/in (\/[^<]+) on line/)[0]
                    
                end
                
            else
                
                if server_root == ''                
                    sr = logcontent.to_s.scan(/([a-z]:\\\\([^<^\\\\]+)\\\\([^<^\\\\]+))/i)   
                    sr2 = logcontent.to_s.scan(/([a-z]:\\\\([^<^\\\\]+)\\\\([^<^\\\\]+)\\\\([^<^\\\\]+))/i)   
                    if sr2.size > 0
                        if sr2[0][0].class.to_s == 'String'
                            server_root = sr2[0][0].to_s
                            server_root.gsub!('\\\\','\\') 
                            if server_root =~ /File names for monitoring must/
                                server_root.gsub!('~.aspx\'. File names for monitoring must have absolute paths, and no wildcards.','')
                            end
                        end
                    elsif sr.size > 0
                        if sr[0][0].class.to_s == 'String'
                            server_root = sr[0][0].to_s
                            server_root.gsub!('\\\\','\\') 
                        end
                    end
                end
            end
        end
        
        server_user_name = '' if found == 0
        server_root = '' if found == 0

        puts "\n\n"
        puts 
        
        puts "! Username detected = #{server_user_name}" if user_check(server_user_name)
        if win == false
            if (path_check(server_root))  
                server_root = correct_path(server_root,server_user_name)
                
                puts "! Server path extracted = #{server_root}" unless server_root  == ''
            end    
            
        else
            puts "! Server path extracted = #{server_root}"  unless server_root  == ''       
        end
        
        cleanvlog()
        
        puts "\n# vulnerable url(s) = #{found}"
        puts "# total requests = #{reqcount}"
        puts "# done at #{Time.now.strftime("%H:%M:%S %m-%d-%Y")}"
        puts "\nSend bugs, suggestions, contributions to inspathx[at]yehg.net"
        log("! Username detected = #{server_user_name}")  if user_check(server_user_name)
        log("! Server path extracted = #{server_root}") if (path_check(server_root))
        log("Vulnerable url(s) = #{found}")
        log("Total requests = #{reqcount}")
        log("Generated by inspathx, path disclosure finder tool")
        log("by Aung Khant, http://yehg.net/lab\n\n")
        log("\nSend bugs, suggestions, contributions to inspathx[at]yehg.net")
        puts "\a"
    rescue Exception=>err
        puts err.message
    end

end


if __FILE__ == $0
  main()
end

