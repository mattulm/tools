description = [[
Attempts to detect the listening web interface on HP Procurve equipment
]]

-- @output
-- Nmap scan report for 1.1.1.1
-- Host is up (0.028s latency).
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_switch: Admin web interface for HP Procurve switch found!
--
-- @output 
-- Nmap scan report for 2.2.2.2
-- Host is up (0.029s latency).
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_switch: Admin web interface for HP Procurve wireless access point found!



author = "John Babio"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe"}

local http = require "http"
local shortport = require "shortport"
portrule = shortport.http

action = function(host, port)
local resp_sw = "ProCurve"
local resp_wap = "HP Wireless Access Point"
local get_sw = http.get(host, port, '/home.html')
local get_wap = http.get(host, port, '/')

if get_sw.status == 401 and http.response_contains(get_sw, resp_sw) then
    return "Admin web interface for HP Procurve network switch found!"
elseif get_wap.status == 200 and http.response_contains(get_wap, resp_wap) then
    return "Admin web interface for HP Procurve wireless access point found!"
  end
end

