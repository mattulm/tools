description = [[
Determines if host is running Poison Ivy C&C server.
]]

---
-- @usage -p 3460 --script poisony-ivy <ip>
--
-- @output
-- 3461/tcp open  unknown
-- | poison-ivy: 
-- |_  CamelliaKey: $camellia$gcgSpySHve+hGhANGgsr9Q==
--

author = "jeremy@sensepost.com"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

require 'nmap'
require 'shortport'
-- require 'base64'

local stdnse = require('stdnse')
local nsedebug = require('nsedebug')
local base64 = require('base64')

local shortport = require "shortport"

portrule = shortport.port_or_service(3460, 'PoisonIvy')

local function fail(err) return ("\n  ERROR: %s"):format(err or "") end

local function connect(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    -- connect socket
    local status, err = socket:connect(host, port)
    if ( not (status) ) then
        return false, "Failed to connect to server" 
    end

    -- send data
    data_to_send = string.rep("\000", 256)
--    nsedebug.print_hex(data_to_send)
    local status, err = socket:send(data_to_send)
    if ( not (status) ) then
        return false, "Failed to send data to server"
    end

    -- 'response1' contains auth_key and 'response2' contains PI server fingerprint
    local status, response1 = socket:receive_bytes(100)
    local status, response2 = socket:receive_bytes(4)
    if ( not (status2) ) then
--        nsedebug.print_hex(response2)
        return false, "Failed to receive data from server"
    end

    -- check if 'response2' matches the PI fingerprint
    if ( (response2:match("\xd0\x15\x00\x00")) ) then
--        nsedebug.print_hex(response2)
        return true, response1
    end

    return false, "Incorrect data received from server"
end

-- Convert response2 (which contains the camellia key) to a format usable by John the Ripper 
local function get_camellia_hash(response)
    auth_key = string.sub(response, 0, 16)
--    nsedebug.print_hex(auth_key)
    return true, "$camellia$" .. base64.enc(auth_key)
end

action = function(host, port)

-- main part of the script
    local status, response = connect(host, port)
    if ( not(status) ) then
        return fail(response)
    else
        local status, hash = get_camellia_hash(response)
        output_str = stdnse.format_output(true, 
        {
        'CamelliaKey: ' .. hash,
        })
    end
    return output_str 
end
