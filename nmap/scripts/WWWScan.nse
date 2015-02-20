local http=require "http"
local nmap=require "nmap"
local shortport=require "shortport"
local stdnse=require "stdnse"
local table = require "table"

description=[[
Attempts to scan website file]]
author="m0zh3"
categories= {"recon","web"}

-- The Rule Section --
portrule = shortport.http
-- The Action Section --

local results={}

local function htpget(host,port,url)
      local socket,status
      local content = "GET /" .. url .. " HTTP/1.1\r\n" .."Host: " .. host.targetname .. ":"  .. port.number .. "\r\n" .. "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET4.0C; .NET4.0E)\r\n\r\n"
      socket = nmap.new_socket()
      socket:connect(host.ip,port)
      socket:send(content)
      local response,data=socket:receive()
      table.insert(results,string.format("%s %s\n",url,string.match(data,'HTTP/1.1%s(%d%d%d%s%a+)')))
end

action = function(host, port)
                local f=io.open(stdnse.get_script_args("data"),'r')
                while true do
                        local i=f:read("*line")
                        if(not(i)) then
                                break
                        end
                        htpget(host,port,i)
                
                end
                if #results>0 then
                        return stdnse.format_output(true,results)
                else
                        return "Oops! Nothing~~~"
                end
end