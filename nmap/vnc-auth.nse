description = [[
Enumerates supported security types on each discovered VNC server.
]]
author = "Steve Ocepek <socepek@trustwave.com>" 
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"auth"}

--require "stdnse"
require "shortport"

portrule = shortport.port_or_service(5900, "vnc")

action = function(host, port)
    local socket = nmap.new_socket()
    local result
    local status = true
    local mode
    local version

    --Table from RFB Protocol Spec
    sectype = {}
    sectype[1] = "None"
    sectype[2] = "VNC Authentication"
    sectype[5] = "RA2"
    sectype[6] = "RA2ne"
    sectype[16] = "Tight"
    sectype[17] = "Ultra"
    sectype[18] = "TLS"
    sectype[19] = "VeNCrypt"
    sectype[20] = "GTK-VNC SASL"
    sectype[21] = "MD5 hash authentication"

    socket:connect(host.ip, port.number, port.protocol)
        
    status, result = socket:receive_bytes(12)
    --String minus newline
    version = string.sub(result, 1, -2)
    if (status) then
        if (version == "RFB 003.003") then
            --This one is special, it doesn't have a "number of security types" field
            mode = 1
        elseif (string.sub (version, 1, 3) == "RFB") then
            --Otherwise it's 3.7 or newer
            mode = 2
        else
            --Something's wrong
            socket:close()
            return "No RFB protocol detected"
        end

        --Send whatever version it is back as client supported
        socket:send(result)
        if (mode == 1) then
            status, result = socket:receive_bytes(4)
            if (result == "\000\000\000\001") then
                socket:close()
                text = version .. ", Security Types: 01(None)"
                return text
            --Use string.sub to grab first 4
            --receive_bytes grabs AT LEAST number specified, more present if auth req'd
            elseif (string.sub(result,1,4) == "\000\000\000\002") then
                socket:close()
                text = version .. ", Security Types: 02(VNC Authentication)"
                return text
            else
                socket:close()
                text = "Handshake Error: " .. version .. ": " .. result 
                return text
            end
        else 
            --RFB 3.7+ uses number-of-security-types byte
            status, result = socket:receive_bytes(2)
            if (status) then
                sectypes = string.byte(result, 1)
                text = version .. ", Security Types: "
                for i=1, sectypes do
                    local sec = string.byte(result, i+1)
                    text = text .. string.format("%02X",sec) .. "(" .. (sectype[sec] or "Unknown") .. "), " 
                end
                socket:close()
                rtext = string.sub(text,1,-3)
                return rtext
            else
                socket:close() 
                text = "Handshake Error: " .. version .. ": " .. result 
                return text 
            end
        end
        
    else
        socket:close()
        return "Error connecting to VNC server"
    end
end
