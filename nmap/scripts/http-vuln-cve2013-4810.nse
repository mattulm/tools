local coroutine=require "coroutine"
local http=require "http"
local stdnse = require "stdnse"
local shortport=require "shortport"
local vulns = require "vulns"

description=[[
Attempts to scan website file]]
author="m0zh3"
categories= {"vuln","safe"}

-- The Rule Section --
portrule = shortport.portnumber({80,8080,8081})
-- The Action Section --

local StatusCode1
local StatusCode2

local function thread1(host,port,request)
	local ret=http.post(host,port,"/invoker/JMXInvokerServlet/")
	StatusCode1=ret.status
end

local function thread2(host,port,request)
	local ret=http.post(host,port,"/invoker/EJBInvokerServlet")
	StatusCode2=ret.status
end

action = function(host, port)
	local vuln_table = {
		title = "CVE-2013-4810",
		reference = "http://www.exploit-db.com/exploits/28713/",
        }
	local report = vulns.Report:new(SCRIPT_NAME, host, port)
        vuln_table.state = vulns.STATE.VULN
	local t1 = stdnse.new_thread(thread1, host, port)
        local t2 = stdnse.new_thread(thread2, host, port)
        while true do -- wait for both threads to die
                if coroutine.status(t1) == "dead" and  coroutine.status(t2) == "dead" then
                        break
                end
                stdnse.sleep(1)
        end
	stdnse.print_debug("bababa........%d",StatusCode1)
	stdnse.print_debug("lalala........%d",StatusCode2)
        if StatusCode1 == 200 then
		return report:make_output(vuln_table)
        end
	if StatusCode2 == 200 then
		return report:make_output(vuln_table)
        end
end
