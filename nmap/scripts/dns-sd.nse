local dns = require "dns"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates DNS services using the DNS-SD
<code>dns-sd</code>.
]]

---
-- @args dns-sd.domains The domain or list of domains to
-- enumerate. If not provided, the script will make a guess based on the
-- name of the target.
--
-- @usage
-- nmap -sSU -p 53 --script dns-sd --script-args dns-sd.domains=example.com <target>
--
-- @output
-- 53/udp open  domain  udp-response
-- | dns-sd:
-- |_ 

author = "John R. Bond"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"

categories = {"discovery", "intrusive"}

local argNS = stdnse.get_script_args(SCRIPT_NAME .. '.nameserver')
local argDomains = stdnse.get_script_args(SCRIPT_NAME .. '.domains')
local argTCP = stdnse.get_script_args(SCRIPT_NAME .. '.tcp') or { 'http', 'ftp' }
local argUDP = stdnse.get_script_args(SCRIPT_NAME .. '.udp') or { 'dns' }

prerule = function()
    return argDomains and nmap.address_family() == "inet" 
end

portrule = function (host, port)
  if not shortport.port_or_service(53, "domain", {"tcp", "udp"})(host, port) then
    return false
  end
  -- only check tcp if udp is not open or open|filtered
  if port.protocol == 'tcp' then
    local tmp_port = nmap.get_port_state(host, {number=port.number, protocol="udp"})
    if tmp_port then
      return not string.match(tmp_port.state, '^open')
    end
  end
  return true
end

function force_table(table)
  if type(table) ~= 'table' then
    return { table } 
  else
    return table
  end
end

function getPTR(qname, nameserver)
  local status, resp = dns.query(qname, {host = nameserver, retAll=true, dtype='PTR', proto='tcp'})
  return force_table(resp)
end

function getService(qname, nameserver)
  local status, resp = dns.query(qname, {host = nameserver, retAll=true, dtype='SRV' })
  return force_table(resp)
end

function getDetails(qname, nameserver)
  local status, resp = dns.query(qname, {host = nameserver, retAll=true, dtype='TXT' })
  return force_table(resp)
end


action = function(host, port)
  local output = {}
  local nameserver = argNS or (host and host.ip)

  if ( argNS and host ) or ( not(argNS) and not(host) ) then
    return
  end

  if not argDomains then
    return string.format("%s.domains script arg is mandatory.", SCRIPT_NAME)
  end

  argDomains = force_table(argDomains)
  argTCP = force_table(argTCP)
  argUDP = force_table(argUDP)
  
  for _, domain in ipairs(argDomains) do
    for _, service in ipairs(argTCP) do
      qname = ("_%s._tcp.%s"):format(service, domain)
      stdnse.print_debug("QNAME: %s", qname)
      for _, ptr in ipairs(getPTR(qname, nameserver)) do
        stdnse.print_debug("Service: %s", ptr)
        for _, ans in ipairs(getService(ptr, nameserver)) do
          stdnse.print_debug("SRV: %s", ans)
        end
        for _, ans in ipairs(getDetails(ptr, nameserver)) do
          stdnse.print_debug("TXT: %s", ans)
        end
      end
    end
  end
end
