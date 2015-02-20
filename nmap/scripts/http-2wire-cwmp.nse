description = [[
Script que identifica y marca modems 2wire por su puerto 3479, usado por CWMP.

Puede buscar a un modem en especifico si se da su numero de serie.
]]

---
-- @usage
-- nmap -p 3479 --script http-2wire-cwmp <target>
-- @usage
-- nmap -n -sT -T4 -p 3479 --open --script http-2wire-cwmp --script-args h2c.serial=<serial_no> <target>
-- @args h2c.serial Numero de serie
-- @args h2c.htout HTTP timeout
-- @output
-- PORT     STATE SERVICE
-- 3479/tcp open  2Wire TR-069
-- |_http-2wire-cwmp:  192.168.1.254 es el 2wire buscado.

author = "Abraham Diaz (@adiaz_32)"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"version"}


local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"


portrule = shortport.portnumber({3479},"tcp","open")


action = function(host,port)
	local serialnum = stdnse.get_script_args("h2c.serial") or ""
	local htout = stdnse.get_script_args("h2c.htout") or 90000 --si no se usa -sT tarda hasta 1 minuto en responder, aunque es lento
	local respuesta = http.get(host,port,"/tr069_connreq_00D09E-"..serialnum,{timeout=htout})

	--server conocido es "2Wire TR-069"
	if respuesta.status and respuesta.header.server and string.find(respuesta.header.server, "2[Ww][Ii][Rr][Ee]") then
		port.version.name=respuesta.header.server
		nmap.set_port_version(host,port)
		if serialnum ~= "" then
			if respuesta.status == 401 then
				stdnse.print_verbose(1,"%s - %s:%d %s server, 2wire encontrado",SCRIPT_NAME,host.ip,port.number,respuesta.header.server)
				local archivo = io.open("http-2wire-encontrado.txt","w+")
				if archivo then
					stdnse.print_verbose(1,"%s - %s:%d Guardando en archivo http-2wire-encontrado.txt",SCRIPT_NAME,host.ip,port.number)
					archivo:write("https://"..host.ip..":50001\n")
					archivo:flush()
					archivo:close()
				end
				return host.ip.." es el 2wire buscado."
			else
				stdnse.print_debug(1,"%s - %s:%d %s server %s status, no es el 2wire que se busca.",SCRIPT_NAME,host.ip,port.number,respuesta.header.server,respuesta.status)
				nmap.set_port_state(host,port,"closed")
			end
		end
	end
end