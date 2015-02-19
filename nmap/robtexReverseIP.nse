description = [[
This script is inspired from http-reverse-ip to do a reverse ip lookup 
using robtex website by parsing http://www.robtex.com/ip/ and return 
maximum of 100 domains
]]

---
-- @usage
-- nmap -p80 --script=http-robtex-reverse-ip <host>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-robtex-info-ip: 
-- | *.insecure.org
-- | *.nmap.com
-- | *.nmap.org
-- | *.seclists.org
-- | insecure.com
-- | insecure.org
-- | lists.insecure.org
-- | nmap.com
-- | nmap.net
-- | nmap.org
-- | seclists.org
-- | sectools.org
-- | web.insecure.org
-- | www.insecure.org
-- | www.nmap.com
-- | www.nmap.org
-- | www.seclists.org
-- | _images.insecure.org

-- @args http-robtex-reverse-ip.host Host to check. 
---

author = "riemann"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "external"}

require "http"
require "shortport"

portrule = shortport.http

--- get reverse ip informations from robtex website
---() param data
---() return table
function parse_robtex_response(data)
	local data = string.gsub(data,"\r?\n","")
	local result = {}
	for num,href,link in string.gmatch(data,"<span id=\"dns(%d+)\"><a href=\"(.-)\">(.-)</a></span>") do
		table.insert(result,link)
	end
	return result
end

action = function(host, port)
	if(stdnse.get_script_args("http-robtex-reverse-ip.host")) then
		target = stdnse.get_script_args("http-robtex-reverse-ip.host")
	else
		target = host.ip
	end
 
	local link = "http://www.robtex.com/ip/"..target..".html"
	local htmldata = http.get_url(link)
	local domains = parse_robtex_response(htmldata.body)
	if #domains > 0 then
	    return "\n" .. stdnse.format_output(true, domains)
	end	
end
