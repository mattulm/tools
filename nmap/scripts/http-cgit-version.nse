local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Displays the version number of a cgit (default: /) instance.
]]

author = "Fabian Affolter"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

---
-- @usage
-- nmap --script http-cgit-version [--script-args http-cgit.path=<path>,http-cgit.redirects=<number>,...] <host>
--
-- @output
-- PORT    STATE SERVICE
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- |_http-cgit-version: 0.10.1-8-c4a2e
--
-- @args http-cgit.path Specify the path you want to check (default to '/').
-- @args http-cgit.redirects Specify the maximum number of redirects to follow (defaults to 3).
--
-- Changelog:
-- 2014-02-15 Fabian Affolter <fabian@affolter-engineering.ch>:
--   + Initial version (based on http-generator script)


-- Helper function
local follow_redirects = function(host, port, path, n)
  local pattern = "^[hH][tT][tT][pP]/1.[01] 30[12]"
  local response = http.get(host, port, path)

  while (response['status-line'] or ""):match(pattern) and n > 0 do
    n = n - 1
    local loc = response.header['location']
    response = http.get_url(loc)
  end

  return response
end

portrule = shortport.http

action = function(host, port)
  local response, loc, generator
  local path = stdnse.get_script_args('http-cgit.path') or '/'
  local redirects = tonumber(stdnse.get_script_args('http-cgit.redirects')) or 3

  -- We are looking for something like the generator meta tag below
  -- <meta name='generator' content='cgit v0.10.1-8-g4d1b'/>
  local pattern = 'v([a-z0-9%.%-]+)'

  response = follow_redirects(host, port, path, redirects)
  if ( response and response.body ) then
    return response.body:match(pattern)
  end
end
