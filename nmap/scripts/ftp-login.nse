local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"

description=[[check ftp weakpassword]]
author = "sincoder"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "external", "intrusive"}
portrule = shortport.portnumber(21, "tcp", "open")
action = function(host, port)
		stdnse.print_debug(1,"test host %s ",host)
		CheckFTP(host.ip,"admin","admin")
end

function CheckFTP(host,user,pass)
	local socket = nmap.new_socket()
	local status, err = socket:connect(host, 21)
	socket:set_timeout(5*1000)
	if(not(status)) then
		return false, stdnse.print_debug(1, "Couldn't connect to host: " .. err )
	end
	status, err = socket:send("USER " .. user .. "\r\n")
	if(not(status)) then
		stdnse.print_debug(1,"Couldn't send login: " .. err)
		socket:close()
		return false
	end
	status, err = socket:send("PASS " .. pass .. "\n\n")
	if(not(status)) then
		stdnse.print_debug(1,"Couldn't send login: " .. err)
		socket:close()
		return false
	end
	-- Create a buffer and receive the first line
	local buffer = stdnse.make_buffer(socket, "\r?\n")
	local line = buffer()
	-- Loop over the lines
	while(line)do
		stdnse.print_debug("Received: %s", line)
		if(string.match(line, "^230")) then
			stdnse.print_debug(1, "ftp-brute: Successful login: %s/%s", user, pass)
			write_log(host.."\t"..user.."\t"..pass)
			break
		elseif(string.match(line, "^530")) then
			stdnse.print_debug(1, "pass word error")
		elseif(string.match(line, "^220")) then
		elseif(string.match(line, "^331")) then
		else
			stdnse.print_debug(1, "ftp-brute: WARNING: Unhandled response: %s", line)
			socket:close()
			return false
		end

		line = buffer()
	end

	socket:close()
	return true
end

function write_log(log)
local file = io.open ("results.txt","a+")
file:write (log.."\n")
file:flush()
file:close()
end
