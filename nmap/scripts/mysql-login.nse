local mysql = require "mysql"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local io = require "io"
local openssl = stdnse.silent_require "openssl"

description = [[
crack mysql weak password
]]

author = "sincoder"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "external", "intrusive"}
portrule = shortport.port_or_service( 3306, "mysql", "tcp", "open")

action = function( host, port )
	local pass = {"root","","root","123456","mysql","admin","12345678"}
	for i = 1,#pass do
		local ret = mysql_login(host,port,"root",pass[i])
		if  ret == 0 or ret == 2 or ret == 1 then
			break;
		end
	end
end

--返回 0 连接失败
--返回 1 认证成功
--返回 2 不允许连接
--返回 3 密码错误
--
function mysql_login(host,port,username,password)
	local socket = nmap.new_socket()
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)
	local status,response,err
	local version

	stdnse.print_debug( "try login use %s/%s",username,password )
	-- set a reasonable timeout value
	socket:set_timeout(5000)
	status, err = socket:connect(host, port)
	if(not(status)) then
		stdnse.print_debug( "connect %s failed err: %s",host.ip,err )
		return 0
	end
	status, response = mysql.receiveGreeting( socket )
	if(not(status)) then
		stdnse.print_debug("recv greet error !!")
		socket:close()
		return 2
	end
	if response.version then
		version = response.version
	else
		version = "unknown"
	end
	status, response = mysql.loginRequest( socket, { authversion = "post41", charset = response.charset }, username, password, response.salt )
	if status and response.errorcode == 0 then
		write_log(host.ip.."\t"..username.."\t"..password.."\t"..version)
		return 1
	end
	socket:close()
	return 3
end

function write_log(log)
local file = io.open ("results.txt","a+")
file:write (log.."\n")
file:flush()
file:close()
end
