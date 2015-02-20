local brute = require "brute"
local creds = require "creds"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local stdnse = require "stdnse"
local io = require "io"

description = [[
check basic authentication weakpassword.
]]

---
-- @usage
-- nmap --script http-brute -p 80 <host>
--
-- This script uses the unpwdb and brute libraries to perform password
-- guessing. Any successful guesses are stored in the nmap registry, under
-- the nmap.registry.credentials.http key for other scripts to use.
--
-- @output
-- PORT     STATE SERVICE REASON
-- 80/tcp   open  http    syn-ack
-- | http-brute:
-- |   Accounts
-- |     Patrik Karlsson:secret => Valid credentials
-- |   Statistics
-- |_    Perfomed 60023 guesses in 467 seconds, average tps: 138
--
-- Summary
-- -------
--   x The Driver class contains the driver implementation used by the brute
--     library
--
-- @args http-brute.path points to the path protected by authentication (default: <code>/</code>)
-- @args http-brute.hostname sets the host header in case of virtual hosting
-- @args http-brute.method sets the HTTP method to use (default: <code>GET</code>)

--
-- Version 0.1
-- Created 07/30/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Version 0.2
-- 07/26/2012 - v0.2 - added digest auth support (Piotr Olma)
-- change by sincoder
--

author = "sincoder"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "external", "intrusive"}

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function( host, port )
	local response = http.generic_request( host, port, "GET", "/", { no_cache = true } )

	if ( response.status ~= 401 ) then
		return false
	end

  -- check if digest auth is required
	local digestauth = false
	local h = response.header['www-authenticate']
	if h then
		h = h:lower()
		if string.find(h, 'digest.-realm') then
			digestauth = true
		end
	end

	local pass = {"admin","","123456","123321","111111"}
	for i = 1,#pass do
		if http_auth(host,port,"admin",pass[i],digestauth) then
			break;
		end
	end
end

function http_auth(host,port,username,password,digestauth)
	local response
	local opts_table

	if not digestauth then
	-- we need to supply the no_cache directive, or else the http library
	-- incorrectly tells us that the authentication was successful
		opts_table = { auth = { username = username, password = password }, no_cache = true }
	else
		opts_table = { auth = { username = username, password = password, digest = true }, no_cache = true }
	end
    response = http.generic_request( host, port, "GET", "/", opts_table)

    if not response.status then
      return false
    end

	-- Checking for ~= 401 *should* work to
	-- but gave me a number of false positives last time I tried.
	-- We decided to change it to ~= 4xx.
	if ( response.status < 400 or response.status > 499 ) then
		write_log(host.ip.."\t"..username.."\t"..password)
		return true
	end
	return false
end

function write_log(log)
local file = io.open ("results.txt","a+")
file:write (log.."\n")
file:flush()
file:close()
end

