local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"

description = [[
This script preforms an TLS1.0 connection to an end point setting all extensions in the Client Hello.  It then looks at the extensions sent back in the Server Hello To enumerate what extensions are supported.
]]

---
-- @usage
-- nmap --script ssl-enum-extension -p 443 <host>
--
-- @output
-- PORT    STATE SERVICE REASON
-- 443/tcp open  https   syn-ack
-- | ssl-enum-extension:
-- |   ec_point_formats
-- |   heartbeat
-- |   renegotiation_info
-- |_  server_name
--
-- @xmloutput
-- <elem>ec_point_formats</elem>
-- <elem>heartbeat</elem>
-- <elem>renegotiation_info</elem>
-- <elem>server_name</elem>

author = "John Bond <mail@johnbond.org>"

license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"

categories = {"discovery", "intrusive"}

-- Function lifted from ssl-enum-ciphers
local function try_params(host, port, t)
  local buffer, err, i, record, req, resp, sock, status

  -- Create socket.
  sock = nmap.new_socket()
  sock:set_timeout(5000)
  status, err = sock:connect(host, port, "tcp")
  if not status then
    stdnse.print_debug(1, "Can't connect: %s", err)
    sock:close()
    return nil
  end

  -- Send request.
  req = tls.client_hello(t)
  status, err = sock:send(req)
  if not status then
    stdnse.print_debug(1, "Can't send: %s", err)
    sock:close()
    return nil
  end

  -- Read response.
  buffer = ""
  record = nil
  while true do
    local status
    status, buffer, err = tls.record_buffer(sock, buffer, 1)
    if not status then
      stdnse.print_debug(1, "Couldn't read a TLS record: %s", err)
      local nsedebug = require "nsedebug"
      nsedebug.print_hex(req)
      return nil
    end
    -- Parse response.
    i, record = tls.record_read(buffer, 1)
    if record and record.type == "alert" and record.body[1].level == "warning" then
      stdnse.print_debug(1, "Ignoring warning: %s", record.body[1].description)
      -- Try again.
    elseif record then
      sock:close()
      return record
    end
    buffer = buffer:sub(i+1)
  end
end

local function keys(t)
  local ret = {}
  for k, _ in pairs(t) do
    ret[#ret+1] = k
  end
  return ret
end

portrule = shortport.ssl

action = function(host, port)
  local name, result, results


  -- lets just check one protocol for now
  protocol = 'TLSv1.0'
  -- Support all ciphers
  ciphers =  keys(tls.CIPHERS)
  local t = {
        ["protocol"] = protocol,
        ["ciphers"] = ciphers,
        ["extensions"] = {},
      }
  t["extensions"]["server_name"] = tls.EXTENSION_HELPERS["server_name"]('localhost')
  t["extensions"]["max_fragment_length"] = 3
  t["extensions"]["client_certificate_url"] = ''
  -- t["extensions"]["trusted_ca_keys"] = ''
  t["extensions"]["truncated_hmac"] = ''
  -- t["extensions"]["status_request"] = ''
  t["extensions"]["user_mapping"] = 255
  t["extensions"]["client_authz"] = 65535
  t["extensions"]["server_authz"] = 65535
  t["extensions"]["cert_type"] = 255
  t["extensions"]["elliptic_curves"] = tls.EXTENSION_HELPERS["elliptic_curves"](keys(tls.ELLIPTIC_CURVES))
  t["extensions"]["ec_point_formats"] = tls.EXTENSION_HELPERS["ec_point_formats"](keys(tls.EC_POINT_FORMATS))
  t["extensions"]["srp"] = 'nmap'
  -- t["extensions"]["signature_algorithms"] = string.char(0x01)
  -- Only avalible for DTLS
  -- t["extensions"]["use_srtp"] = string.char(0x00) 
  t["extensions"]["heartbeat"] = string.char(0x01)
  -- t["extensions"]["application_layer_protocol_negotiation"] = 65535
  t["extensions"]["status_request_v2"] = string.char(0x00) 
  t["extensions"]["signed_certificate_timestamp"] = ''
  t["extensions"]["client_certificate_type"] = 255
  t["extensions"]["server_certificate_type"] = 255
  t["extensions"]["padding"] = string.char(0x00, 0x00)
  t["extensions"]["renegotiation_info"] = string.char(0x00)

  if host.targetname then
    t["extensions"]["server_name"] = tls.EXTENSION_HELPERS["server_name"](host.targetname)
  end
  results = {}
  record = try_params(host, port, t)
  for name, value in pairs(record.body) do
    stdnse.print_debug(2, "%s: %s", name, value)
    for name_b, value_b in pairs(value) do
      stdnse.print_debug(2, " -- %s: %s", name_b, value_b)
    end
  end
  if record.body[1].extensions then
    for name, value in pairs(record.body[1].extensions) do 
      stdnse.print_debug(1, "extension:  %s", name)
      table.insert(results, tostring(name))
    end
    table.sort(results)
    return results
  end
end
