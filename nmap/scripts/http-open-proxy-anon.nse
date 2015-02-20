local proxy = require "proxy"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local url = require "url"

description=[[
Checks if an HTTP proxy is open.

The script attempts to connect to www.google.com through the proxy and
checks for a valid HTTP response code. Valid HTTP response codes are
200, 301, and 302. If the target is an open proxy, this script causes
the target to retrieve a web page from www.google.com.
]]

---
-- @args proxy.url Url that will be requested to the proxy
-- @args proxy.pattern Pattern that will be searched inside the request results
-- @output
-- Interesting ports on scanme.nmap.org (64.13.134.52):
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- |  proxy-open-http: Potentially OPEN proxy.
-- |_ Methods successfully tested: GET HEAD CONNECT

-- Arturo 'Buanzo' Busleiman <buanzo@buanzo.com.ar> / www.buanzo.com.ar / linux-consulting.buanzo.com.ar
-- Changelog: Added explode() function. Header-only matching now works.
--   * Fixed set_timeout
--   * Fixed some \r\n's
-- 2008-10-02 Vlatko Kosturjak <kost@linux.hr>
--   * Match case-insensitively against "^Server: gws" rather than
--     case-sensitively against "^Server: GWS/".
-- 2009-05-14 Joao Correa <joao@livewire.com.br>
--   * Included tests for HEAD and CONNECT methods
--   * Included url and pattern arguments
--   * Script now checks for http response status code, when url is used
--   * If google is used, script checks for Server: gws
-- 
-- @usage
-- nmap --script http-open-proxy.nse \

author = "Arturo 'Buanzo' Busleiman"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "external", "safe"}

--- Performs the default test
-- First: Default google request and checks for Server: gws
-- Seconde: Request to wikipedia.org and checks for wikimedia pattern
-- Third: Request to computerhistory.org and checks for museum pattern
--
-- If any of the requests is succesful, the proxy is considered open
-- If all get requests return the same result, the user is alerted that
-- the proxy might be redirecting his requests (very common on wi-fi
-- connections at airports, cafes, etc.)
--
-- @param host The host table
-- @param port The port table
-- @return status (if any request was succeded
-- @return response String with supported methods

function anon_test(host, port)
  local fstatus = false
  local cstatus = false
  local response = ""
  local get_status, head_status, conn_status, anon_status
  local get_r1, get_r2, get_r3
  local get_cstatus, head_cstatus

  -- Start test n1
  -- making requests	
  local test_url = "http://www.xxxxxxxxxx.net/ip.php"
  local hostname = "www.xxxxxxxxxx.net"
  local pattern  = "Your IP is"
  get_status, get_r1, get_cstatus = proxy.test_get(host, port, "http", test_url, hostname, pattern)
  local _
  head_status, _, head_cstatus = proxy.test_head(host, port, "http", test_url, hostname, pattern)
  conn_status = proxy.test_connect(host, port, "http", hostname)
  anon_status = string.match (get_r1, "Your IP is (%d+.%d+.%d+.%d+)")

  -- checking results
  -- conn_status use a different flag (cstatus)
  -- because test_connection does not use patterns, so it is unable to detect
  -- cases where you receive a valid code, but the response does not match the
  -- pattern.
  -- if it was using the same flag, program could return without testing GET/HEAD
  -- once more before returning

  if get_status then fstatus = true; response = response .. " GET" end
  if head_status then fstatus = true; response = response .. " HEAD" end
  if conn_status then cstatus = true; response = response .. " CONNECTION" end
  if anon_status then fstatus = true; response = response .. " IP:" .. anon_status end
 
  -- if proxy is open, return it!
  if fstatus then return fstatus, "Methods supported: " .. response end

  -- if we receive a invalid response, but with a valid 
  -- response code, we should make a next attempt.
  -- if we do not receive any valid status code,
  -- there is no reason to keep testing... the proxy is probably not open
  if not (get_cstatus or head_cstatus or conn_status) then return false, nil end
  stdnse.print_debug("Received valid but something goes bad")

  -- Check if GET is being redirected
  if proxy.redirectCheck(get_r1, get_r2) and proxy.redirectCheck(get_r2, get_r3) then
    return false, "Proxy might be redirecting requests"
  end

  -- Check if at least CONNECTION worked
  if cstatus then return true, "Methods supported:" .. response end

  -- Nothing works...
  return false, nil
end

portrule = shortport.port_or_service({8123,3128,8000,8080},{'polipo','squid-http','http-proxy'})

action = function(host, port)
  local supported_methods = "\nMethods successfully tested: "
  local fstatus = false
  local test_url, pattern

  test_url, pattern = proxy.return_args() 
 
  if(pattern) then pattern = ".*" .. pattern .. ".*" end
  fstatus, supported_methods = anon_test(host, port);	

  -- If any of the tests were OK, then the proxy is potentially open
  if fstatus then
    return "Potentially OPEN proxy.\n" .. supported_methods
  elseif not fstatus and supported_methods then
    return supported_methods
  end
  return

end
