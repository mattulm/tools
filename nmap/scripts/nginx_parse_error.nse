local http=require "http"
local shortport=require "shortport"
local strbuf=require "strbuf"
local table = require "table"

description=[[
Attempts to scan website file]]
author="m0zh3"
categories= {"default","discovery"}

-- The Rule Section --
portrule = shortport.http
-- The Action Section --

action = function(host, port)
		local output=strbuf.new()
                local answer1=http.get(host,port,"/robots.txt")
                	if answer1.status == 200 then
				local answer2=http.get(host,port,"/robots.txt/robots.php")
				if answer1.header['content-type'] ~= answer2.header['content-type'] then
					return table.concat({"[!] Nginx File Parse Error Vulnerable","Reference:http://www.80sec.com/nginx-securit.html"},"\n")
				end
                	else
                        	return nil
                	end
end
