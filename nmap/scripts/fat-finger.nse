-- Released as open source by NCC Group Plc - http://www.nccgroup.com/

-- OpenSSH Username enumeration 
-- Developed by Ed Williams <Ed.Williams@nccgroup.com>
-- https://github.com/nccgroup/fat-finger

-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Affero General Public License as
-- published by the Free Software Foundation, either version 3 of the
-- License, or (at your option) any later version.

-- You should have received a copy of the GNU Affero General Public License
-- along with this program (in the LICENSE file).  If not, see
-- <http://www.gnu.org/licenses/>.

local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"

description = [[
Extends the orginal finger.nse and attempts to enumerate current logged on users through a full match of the username and a partical match of the GECOS field in /etc/passwd
]]

author = "Ed Williams"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

---
-- @output
-- PORT   STATE SERVICE
-- 79/tcp open  finger
-- | fat-finger: finger: admin: no such user.
-- | finger: unix: no such user.
-- | finger: dba: no such user.
-- | finger: oracle: no such user.
-- | finger: sybase: no such user.
-- | finger: ingres: no such user.
-- | finger: db: no such user.
-- | finger: help: no such user.
-- | finger: IT: no such user.
-- | finger: test: no such user.
-- | Login: root                                   Name: root
-- | Directory: /root                      Shell: /bin/bash
-- | Last login Thu Nov 26 16:05 2009 (GMT) on pts/1 from 192.168.226.1
-- | No mail.
-- | No Plan.
-- |
-- | Login: mysql                                  Name: MySQL Server
-- | Directory: /var/lib/mysql             Shell: /bin/false
-- | Never logged in.
-- | No mail.
-- | No Plan.
-- |
-- | Login: ftp                                    Name: ftp daemon
-- | Directory: /srv/ftp                   Shell: /bin/false
-- | Never logged in.
-- | No mail.
-- | No Plan.
-- |
-- | Login: hplip                                  Name: HPLIP system user
-- | Directory: /var/run/hplip             Shell: /bin/false
-- | Never logged in.
-- | No mail.
-- | No Plan.
-- |
-- | Login: gnats                                  Name: Gnats Bug-Reporting System (admin)
-- | Directory: /var/lib/gnats             Shell: /bin/sh
-- | Never logged in.
-- | No mail.
-- |_No Plan.


portrule = shortport.port_or_service(79, "finger")

action = function(host, port)
	local try = nmap.new_try()

	return try(comm.exchange(host, port, "root admin system unix dba oracle mysql sybase ingres db ftp help IT user test\r\n",
        	{lines=100, proto=port.protocol, timeout=5000}))
end
