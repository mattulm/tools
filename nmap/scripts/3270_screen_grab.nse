-- Mainframe Screen Grab
-- Grabs the first screen upon connecting to a mainframe

local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"


description = [[
Grabs the first screen when an IBM OS/390 or OS/400 mainframe is found
]]

---
-- @usage
-- nmap -sV 
-- @output
-- PORT   STATE SERVICE VERSION
-- 23/tcp open  telnet  IBM OS/390 or SNA telnetd
-- | 3270_screen_grab:
-- |_  IBM Mainframe screenshot grabbed to 3270-nmap-IPADDRESS:PORT.html
---
 
author = "Soldier of Fortran <@mainframed767>"
license = "GPL 2.0"
categories = {"default","discovery", "safe"}


portrule = shortport.port_or_service({23, 992}, {'telnet', 'ssl/telnet', 'telnets'})

action = function(host, port)
	local out = "Not an IBM 3270 connection (OS/400 or z/OS aka OS/390)"
	if string.match(port.version.product,"IBM OS") then

        -- Screens will be called 3270-nmap-<IP>:<port>.html
	        local filename = "3270-nmap-" .. host.ip .. ":" .. port.number .. ".html"
 
        -- Execute the the program s3270, connect to a machine then print the first screen to a file
		local s3270 = io.popen("s3270 &>/dev/null","w")
		stdnse.print_debug( "Connecting to %s ...", host.ip  )
		local mf = 'connect(' .. host.ip .. ':' .. port.number .. ')\n'
		stdnse.print_debug( "Saving screenshot" )
		local gotchya = 'printtext(html,' .. filename .. ')\n'
		local frame = s3270:write(mf)
		frame = s3270:write(gotchya)
		frame = s3270:write("quit\n")
		local f = s3270:close()	
		out = "Script Error: this script requires s3270 to run"
		if f == true then
	                out = "IBM Mainframe screenshot grabbed to " .. filename
		end
	end
	return stdnse.format_output(true, out)
end
