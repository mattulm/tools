local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local base64 = require "base64"

description = [[
Attempts to force NTLM authentication on a remote server and retrieve an authenticate response
]]

---
-- @output
-- Interesting ports on scanme.nmap.org (64.13.134.52):
-- PORT   STATE SERVICE
-- 80/tcp open  http    syn-ack
-- |  http-ntlm:  
-- |  |  ConteTODOnt-Type: text/html
-- |_ |_ (Request type: HEAD)
-- 
--@args path The path to request, such as <code>/index.php</code>. Default <code>/</code>. 

author = "Dean Jerkovich"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}


portrule = shortport.http

action = function(host, port)
	local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
	local request_type = "GET"
	local status = false
	local result

	local header = {
		["Authorization"]  = 'NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAFASgKAAAADw==',
	}
	result = http.get(host, port, path, {header = header})

	if(result == nil) then
		if(nmap.debugging() > 0) then
			return "ERROR: HTTP request failed"
		else
			return nil
		end
	end

	local www_authenticate = result.header["www-authenticate"]
	if not www_authenticate then
		return nil
	end

	return stdnse.format_output(true, www_authenticate)
end

