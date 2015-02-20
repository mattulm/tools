local dns = require "dns"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local string = require "string"
local ipOps = require "ipOps"

description = [[
Detects whether the remote host is running the ptunnel service. It does that by
sending a packet that ptunnel should interpret as "connect to 127.0.0.1:22".
Next, the script sniffs for ICMP traffic from this host, expecting a packet
with sequence number equal to zero.

In order to use the scanned host as default gateway Nmap needs to send a custom
ICMP packet. This requires Nmap to be run in privileged mode.

This script was based on ip-forwarding.nse by Patrik Karlsson.
]]

---
-- @usage
-- sudo nmap -sn <target> --script ptunnel
--
-- @output
-- | ip-forwarding:
-- |_  ptunnel detected on <target IP>

author = "Jacek Wielemborek"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}


hostrule = function(host)
	return true
end

action = function(host)

	local ifname = nmap.get_interface() or host.interface
	if ( not(ifname) ) then
		return "ERROR: Failed to determine the network interface name"
	end

	local iface = nmap.get_interface_info(ifname)
	local dnet, pcap = nmap.new_dnet(), nmap.new_socket()

	pcap:set_timeout(2000)
	pcap:pcap_open(iface.device, 128, false, ("icmp and ( icmp[0] = 0 or "
		.. "icmp[0] = 5 ) and dst %s"):format(iface.address))
	dnet:ip_open()
	
	local probe = packet.Frame:new()
	probe.ip_bin_src = packet.iptobin(iface.address)
	probe.ip_bin_dst = packet.iptobin(host.ip)
	probe.echo_id = 0x1234
	probe.echo_seq = 6

	math.randomseed(os.time())
	local random_byte = string.char(math.random(255))
	probe.echo_data = "\xd5\x20\x08\x80\x7f\x00\x00\x01\x00\x00\x00"
			.. "\x16\x40\x00\x00\x00\x00\x00\xff\xff\x00\x00"
			.. "\x00\x00\x00\x00\x53" .. random_byte

	probe:build_icmp_echo_request()
	probe:build_icmp_header()
	probe:build_ip_packet()
	
	dnet:ip_send(probe.buf)

	function find_ptunnel_packet()
		local status, _, _, data = pcap:pcap_receive()
		if not status or not data then
			return false
		end
		p = packet.Packet:new(data, #data)
                if (data:byte(p.icmp_offset+7) == 0x00
				and data:byte(p.icmp_offset+8) == 0x00) then
			return true
		end
		return false
	end
	local found = find_ptunnel_packet()
	found = found or find_ptunnel_packet()

	dnet:ip_close()
	if found then
		stdnse.print_debug(("ptunnel detected on %s"):format(host.ip))
		return ("ptunnel detected on %s"):format(host.ip)
	end

end
