description = [[
This is an nmap script to search for accessible JMX web consoles.
]]

author = "David Shaw" -- hello, Toorcon!
license = "Same as nmap -- see http://nmap.org/book/man-legal.htm"
categories = {"default", "discovery", "safe"}

require "shortport"
require "http"

portrule = shortport.port_or_service({80, 443, 8080}, {"http", "https"})

action = function(host, port)
	-- we only care about the HTTP status (quick demo!)
	local stat = http.get( host, port, '/jmx-console/' ).status
	
	-- HTTP 200 (OK) means we probably found a JMX console!
	if stat == 200 then
		return "[+] Found possible JMX Console!"
	end		
end
