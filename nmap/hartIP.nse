local bin = require "bin"
local comm = require "comm"
local nmap = require "nmap"
local os = require "os"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local nsedebug = require "nsedebug"

description = [[
HART-IP slave gateway RTU devices scan NSE script.
The HART Communications Protocol (Highway Addressable Remote Transducer Protocol) is
a digital industrial automation protocol. HART is used for communicating between master 
(i.e. host computer with HART modem, PLC or HART field communicator) and slave (RTU 
device, Remote Transmitter Unit, like transmitter or actuator). The main task of HART
is configuring and monitoring state of field devices. HART-IP is a HART protocol lower 
level. HART-IP using standard HART master-slave communication scheme, i.e. master device 
sends commands to slave devices. Slave devices are listening for master commands on UDP 
or TCP port. This script is intended for checking opened HART port whether gateway or 
RTU is running on it. 
]]

author = "Alexander Bolshev"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.port_or_service(5094, "hart-ip", {"udp", "tcp"})
portrule = shortport.port_or_service(20004, "hart-ip", {"udp", "tcp"})

local TIMEOUT = 5000

action = function(host, port)
  local status
  local buftres, bufrlres
  local output = {}
  
  local hartip_enq = string.char(0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0D, 0x01, 0x00, 0x00, 0x4E, 0x20)
  
  status, buftres = comm.exchange(host, port, hartip_enq, {proto=port.protocol, timeout=TIMEOUT})
  if not status then
    return nil
  else
	
	local msg_ver, msg_type, msg_seq
	
	_, msg_ver, msg_type, _, _, msg_seq = bin.unpack(">CCCCS", buftres, 1)
	
	-- nsedebug.print_hex(buftres)
	
	if msg_ver == 1 and msg_type == 1 and msg_seq == 1 then
	  table.insert(output, "detected HART RTU gateway")
	else
	  return nil
	end
	
  end
  
  if(#output > 0) then
    nmap.set_port_state(host, port, "open")
    return stdnse.format_output(true, output)
  else
    return nil
  end
 end
