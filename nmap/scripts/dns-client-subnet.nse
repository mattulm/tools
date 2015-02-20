description = [[
Implements the edns-client-subnet IETF draft[1].  Can be used to find what ip
address CDN networks provide when serving different client ip/subnet.  not sure
who has implmented this yet other then google.
[1]http://tools.ietf.org/html/draft-vandergaast-edns-client-subnet-00
]]

---
-- @args dns-client-subnet.domain The domain to lookup
-- @args dns-client-subnet.address the client address to use
-- @args dns-client-subnet.nameserver nameserver to use.  (default = host.ip)
-- 
-- @usage
-- nmap -sU -p 53 --script dns-client-subnet  --script-args \
-- dns-client-subnet.domain=www.example.com,dns-client-subnet.address=192.168.0.1 \
-- [,dns-client-subnet.nameserver=8.8.8.8] <target>
--
-- @output
-- 53/udp open  domain  udp-response
-- | dns-client-subnet: 
-- |_  A : 127.0.0.1,127.0.0.2,127.0.0.3
---

author = "John Bond"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"

categories = {"discovery" }

require "stdnse"
require "shortport"
require "dns"

portrule = shortport.port_or_service(53, "domain", {"tcp", "udp"})


local function rr_filter(pktRR, label)
	for _, rec in ipairs(pktRR, label) do
		if ( rec[label] and 0 < #rec.data ) then
			if ( dns.types.OPT == rec.dtype ) then
				local ip = {}
				local client_subnet = {}
				local pos, _
				pos, _, len, client_subnet.family, client_subnet.src_mask, client_subnet.scope_mask  = bin.unpack(">SSSCC", rec.data)
				pos,  ip[1], ip[2], ip[3], ip[4] =  bin.unpack(">C4", rec.data, pos)
				client_subnet.address = table.concat(ip, ".")
				return client_subnet	
			end
		end
	end
end

action = function(host, port)	
	local result = {}
	local nameserver = stdnse.get_script_args('dns-client-subnet.nameserver')
	local domain =  stdnse.get_script_args('dns-client-subnet.domain')
	local address =  stdnse.get_script_args('dns-client-subnet.address')
	local mask =  stdnse.get_script_args('dns-client-subnet.mask')
	if not domain then
		return string.format("dns-client-subnet.domain missing")
	end
	if not address then
		return string.format("dns-client-subnet.address missing")
	end
	if not nameserver then
		nameserver = host.ip
	end
	if not mask then
		mask = 24
	end
	local addr = stdnse.strsplit("%.",address)
	local addr_no
	-- use this so we can pass addresses as dotted quade or int
	if #addr > 1 then
		addr_no = (tonumber(addr[1])*16777216 + tonumber(addr[2])*65536 
			+ tonumber(addr[3])*256 + tonumber(addr[4]))	
	else
		addr_no = tonumber(addr[1])
	end
	address = addr_no

	local client_subnet = {}
	client_subnet.family = 1
	client_subnet.address = address
	client_subnet.mask = mask
	local status, resp = dns.query(domain, {host = nameserver,  retAll=true, retPkt=true, client_subnet=client_subnet})
	if ( status ) then
		local status, answer = dns.findNiceAnswer(dns.types.A, resp, true)
		if ( status ) then
			if type(answer) == "table" then
				table.insert(result, ("A : %s"):format(table.concat(answer,",")))
			else
				table.insert(result, ("A : %s"):format(answer))
			end
		end
		local client_subnet_resp = rr_filter(resp.add,'OPT')
		if client_subnet_resp then
			table.insert(result, ("details : %s/%s/%s"):format(client_subnet_resp.src_mask,client_subnet_resp.scope_mask,client_subnet_resp.address))
		end
	end
	return stdnse.format_output(true, result)
end
