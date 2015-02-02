description = [[
2wire 4011G and 5012NV Directory Traversal Vulnerability List Only.

Solo hace una lista de posibles modems vulnerables en el archivo ./http-2wire-temp.txt
]]

---
-- @usage
-- nmap --script http-2wire-list -p 8080 <target>
-- @usage
-- nmap -T4 -n --open --script http-2wire-list -p 8080 <target>
-- @output
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- | http-2wire-list: 
-- |_  192.168.1.254 es 2wire.

author = "Abraham Diaz"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln"}


local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
http = require "http"


prerule = function()
	stdnse.print_verbose(1,"%s INICIANDO ARCHIVO http-2wire-temp.txt para esta sesion.",SCRIPT_NAME)
	local archivo = io.open("http-2wire-temp.txt","w+")
	if archivo then
		archivo:close()
	end
end


portrule = shortport.portnumber({8080},"tcp","open")


action = function(host,port)
	local respuesta
	respuesta = http.get(host,port,"/")
	if respuesta.status == 302 and respuesta.header.server == "rhttpd" then
		stdnse.print_verbose(1,"%s A - %s:%d rhttpd server detectado, a archivo http-2wire-temp",SCRIPT_NAME,host.ip,port.number)
		local archivo = io.open("http-2wire-temp.txt","a+")
		if archivo then
			archivo:write(host.ip.."\n")
			archivo:flush()
			archivo:close()
		end
		return host.ip.." es 2wire."
	else
		nmap.set_port_state(host,port,"closed")
	end
end