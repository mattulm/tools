--- Simple RPC Library supporting a very limited subset of operations
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html
--
--
-- @author = "Patrik Karlsson <patrik@cqure.net>"
--
-- Version 0.1
--
-- Created 01/24/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net> 
--
--
-- All encoding/decoding is based on packet captures between a Mac OS NFS Client and Linux Server where
-- not explcitly stated otherwise
--

module(... or "rpc", package.seeall)

AuthType =
{
	Null = 0
}	

MessageType =
{
	Call = 0,
	Reply = 1
}

Procedure = 
{
	MOUNT = 1,
	EXPORT = 5,
	READDIR = 16,
	STATFS = 17
}

--
-- Calculates the number of fill bytes needed
-- @param length contains the length of the string
-- @return the amount of pad needed to be divideable by 4
local function calcFillBytes(length)

    -- calculate fill bytes
    if math.mod( length, 4 ) ~= 0 then
    	return (4 - math.mod( length, 4))
    else
    	return 0
    end

end

--- Checks if data contains enough bytes to read the <code>needed</code> amount
--  If it doesn't it attempts to read the remaining amount of bytes from the socket
--
-- @param socket socket already connected to the server
-- @param data string containing the current buffer
-- @param pos number containing the current offset into the buffer
-- @param needed number containing the number of bytes needed to be available
-- @return status success or failure
-- @return data string containing the data passed to the function and the additional data appended to it
local function getAdditionalBytes( socket, data, pos, needed )

	local status = true
	local tmp

	if data:len() - pos + 1 < needed then
		local toread =  needed - ( data:len() - pos + 1 )
		status, tmp = socket:receive_bytes( toread )
		
		if status then
			data = data .. tmp
		else
			return false, string.format("getAdditionalBytes() failed to read: %d bytes from the socket", needed - ( data:len() - pos ) )
		end
	end
	
	return status, data
	
end

--- Decodes the RPC header (without the leading 4 bytes as received over TCP)
--
-- @param socket socket already connected to the remote service
-- @param data string containing the buffer of bytes read so far
-- @param pos number containing the current offset into data
-- @return pos number containing the offset after the decoding
-- @return header table containing <code>xid</code>, <code>type</code>, <code>state</code>,
-- <code>verifier</code> and <code>accept_state</code>
local function decodeHeader( socket, data, pos )
	
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)
	local header = {}
	local status

	header.verifier = {}
	
	status, data = getAdditionalBytes( socket, data, pos, 20 )
	
	if not status then
		return -1, nil
	end
	
	pos, header.xid, header.type, header.state = bin.unpack(">III", data, pos)
	pos, header.verifier.flavor = bin.unpack(">I", data, pos)
	pos, header.verifier.length = bin.unpack(">I", data, pos) 
		
	if header.verifier.length - 8 > 0 then
		data = try( getAdditionalBytes( socket, data, pos, header.verifier.length - 8 ) )
		pos, header.verifier.data = bin.unpack("A" .. header.verifier.length - 8, data, pos )
	end
	
	pos, header.accept_state = bin.unpack(">I", data, pos )

	return pos, header
	
end

--- Requests a list of NFS export from the remote server
--
-- @param socket connected to the mountd program over either UDP or TCP
-- @param proto string containing either "udp" or "tcp"
-- @param options table containing <code>xid</code>, <code>version</code> and <code>auth</code>
-- @param status success or failure
-- @param entries table containing a list of directories and groups suitable for output by <code>stdnse.format_output</code>
function mountExportCall( socket, proto, options )
		
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)
	
	local xid = options.xid or 0x2100464c
	local msg_type, rpc_ver = 0, 2
	local prg_mount, prg_ver = 100005, options.version
	local packet
	local pos = 1
	local header = {}
	local entries = {}
	local data = ""
	local status
	local auth = options.auth
	local version = options.version or -1
	
	local REPLY_ACCEPTED, SUCCESS, PROC_EXPORT = 0, 0, 5
	
	if version ~= 1 then
		return false, "Support for version 1 only"
	end
	
	if proto ~= "tcp" and proto ~= "udp" then
		return false, "Protocol should be either udp or tcp"
	end
	
	if not auth or auth.type ~= AuthType.Null then
		return false, "Authtype not supported"
	end
	
	----
    -- XID: 0x2100464c; (32-bit)
    -- Message type: Call(0); (32-bit)
    -- RPC Version: 2; (32-bit)
    -- Program: MOUNT(100005); (32-bit)
    -- Program Version: 1; (32-bit)
    -- Procedure: EXPORT(5); (32-bit)
    -- Credentials
    	-- Flavor: AUTH_NULL (0); (32-bit)
    	-- Length: 0; (32-bit)
    -- Verifier
    	-- Flavor: AUTH_NULL; (32-bit)
    	-- Length: 0; (32-bit)
	----
	
	status, packet = createHeader( xid, prg_mount, prg_ver, PROC_EXPORT, auth )
	
	if not status then
		return false, packet
	end
	
	if auth.type == AuthType.Null then
		packet = packet .. bin.pack( "IIII", 0, 0, 0, 0 )
	end
	
	if proto == "tcp" then
		packet = bin.pack( "I", 0x80000028 ) .. packet
	end
	
	try( socket:send( packet ) )
	
	-- if were running over UDP make sure the other end is really there
	if proto == "udp" then
		status, data = socket:receive_bytes(1)
		if not status then
			return false, "Failed to read from UDP socket"
		end
	end

	--- Start parsing the response ---

	-- with TCP we can get all the data in advance, this way we don't need to
	-- do additional reading down the way
	if proto == "tcp" then
		data = decodeRpcTcpPacket( socket )
	end

	-- make sure we have atleast 24 bytes to unpack the header
	data = try( getAdditionalBytes( socket, data, pos, 24 ) )
	pos, header = decodeHeader( socket, data, pos )
	
	if not header then
		return false, "Failed to decode header"
	end
		
	if header.xid ~= xid then
		return false, string.format("Packet contained incorrect XID: %d ~= %d", header.xid, xid )
	end
		
	if header.type ~= MessageType.Reply then
		return false, string.format("Packet was not a reply")
	end
		
	if header.state ~= REPLY_ACCEPTED then
		return false, string.format("Reply state was not Accepted(0) as expected")
	end
		
	if header.accept_state ~= SUCCESS then
		return false, string.format("Accept State was not Successful")
	end
		
	---
	--  Decode directory entries
	--
	--  [entry]
	--     4 bytes   - value follows (1 if more data, 0 if not)
	--     [Directory]
	--  	  4 bytes   - value len
	--  	  len bytes - directory name
	--  	  ? bytes   - fill bytes (@see calcFillByte)
	--     [Groups]
	--		   4 bytes  - value follows (1 if more data, 0 if not)
	--         [Group] (1 or more)
	--            4 bytes   - group len
	--			  len bytes - group value	
	-- 	          ? bytes   - fill bytes (@see calcFillByte)		  
	---
	while true do
		-- make sure we have atleast 4 more bytes to check for value follows
		data = try( getAdditionalBytes( socket, data, pos, 4 ) )
	
		local data_follows
		pos, data_follows = bin.unpack( ">I", data, pos )
		
		if data_follows ~= 1 then
			break
		end
	
		--- Export list entry starts here
		local entry = {}
		local len	
		
		-- make sure we have atleast 4 more bytes to get the length
		data = try( getAdditionalBytes( socket, data, pos, 4 ) )
		pos, len = bin.unpack(">I", data, pos )

		data = try( getAdditionalBytes( socket, data, pos, len ) )
		pos, entry.name = bin.unpack("A" .. len, data, pos )
		pos = pos + calcFillBytes( len )
				
		-- decode groups
		while true do
			local group 
			
			data = try( getAdditionalBytes( socket, data, pos, 4 ) )
			pos, data_follows = bin.unpack( ">I", data, pos )
			
			if data_follows ~= 1 then
				break
			end

			data = try( getAdditionalBytes( socket, data, pos, 4 ) )
			pos, len = bin.unpack( ">I", data, pos )
			data = try( getAdditionalBytes( socket, data, pos, len ) )
			pos, group = bin.unpack( "A" .. len, data, pos )

			table.insert( entry, group )
			pos = pos + calcFillBytes( len )
		end		
		table.insert(entries, entry)
	end
		
	return true, entries
end

--
-- Ruthlessly ripped, and modified, from Sven Klemm's rpcinfo.nse script
--
function getPortsForProgram(host, prog_name, prog_version)
	
  local socket = nmap.new_socket()
  local catch = function() socket:close() end
  local try = nmap.new_try(catch)
  local rpc_numbers = try(datafiles.parse_rpc())

  socket:set_timeout(5000)
  try(socket:connect(host.ip, 111))

  -- build rpc dump call packet
  local transaction_id = math.random(0x7FFFFFFF)
  local request = bin.pack('>IIIIIIILL',0x80000028,transaction_id,0,2,100000,2,4,0,0)
  try(socket:send(request))

  local answer = try(socket:receive_bytes(1))

  local _,offset,header,length,tx_id,msg_type,reply_state,accept_state,value,payload,last_fragment
  last_fragment = false; offset = 1; payload = ''

  -- extract payload from answer and try to receive more packets if
  -- RPC header with last_fragment set has not been received
  -- If we can't get further packets don't stop but process what we
  -- got so far.
  while not last_fragment do
    if offset > #answer then
      local status, data = socket:receive_bytes(1)
      if not status then break end
      answer = answer .. data
    end
    offset,header = bin.unpack('>I',answer,offset)
    last_fragment = bit.band( header, 0x80000000 ) ~= 0
    length = bit.band( header, 0x7FFFFFFF )
    payload = payload .. answer:sub( offset, offset + length - 1 )
    offset = offset + length
  end
  socket:close()

  offset,tx_id,msg_type,reply_state,_,_,accept_state = bin.unpack( '>IIIIII', payload )

  -- transaction_id matches, message type reply, reply state accepted and accept state executed successfully
  if tx_id == transaction_id and msg_type == 1 and reply_state == 0 and accept_state == 0 then
    local dir = { udp = {}, tcp = {}}
    local protocols = {[6]='tcp',[17]='udp'}
    local prog, version, proto, port
    local ports = {}
    offset, value = bin.unpack('>I',payload,offset)
    while value == 1 and #payload - offset >= 19 do
      offset,prog,version,proto,port,value = bin.unpack('>IIIII',payload,offset)
      proto = protocols[proto] or tostring( proto )

      if rpc_numbers[prog] == prog_name and version == prog_version then
        ports[proto] = port
      end

    end

    return ports

  end

  return

end

-- Attempts to mount a remote export in order to get the filehandle
--
-- @param socket socket already connected to the port of the mountd program
-- @param proto string containing either "udp" or "tcp"
-- @param path string containing the path to mount
-- @param options table containing <code>xid</code>, <code>version</code> and <code>auth</code>
-- @param status success or failure
-- @param fhandle string containing the filehandle of the remote export
function mountCall( socket, proto, path, options )
	
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)
	local packet = ""
	local rpc_version, program_id = 2, 100005
	local _, pos, data, header, fhandle = "", 1, "", "", {}
	local status

	local REPLY_ACCEPTED, SUCCESS, PROC_MNT, MOUNT_OK = 0, 0, 1, 0

	if not options then
		return false, "No options specified"
	end

	local auth = options.auth

	status, packet = createHeader( options.xid, program_id, options.version, PROC_MNT, auth )
	
	if not status then
		return false, packet
	end
	
	packet = packet .. bin.pack(">I", path:len())
	packet = packet .. bin.pack("A", path)
	
	for i=1, calcFillBytes( path:len() ) do
		packet = packet .. string.char( 0x00 )
	end
	
	-- set the high bit as this is our last fragment
	local len = 0x80000000
	len = len + packet:len()
	
	packet = bin.pack(">I", len) .. packet
	
	try( socket:send( packet ) )

	if proto == "tcp" then
		data = decodeRpcTcpPacket( socket )
	end

	pos, header = decodeHeader( socket, data, pos )

	if not header then
		return false, "Failed to decode header"
	end

	if header.xid ~= options.xid then
		return false, string.format("Packet contained incorrect XID: %d ~= %d", header.xid, options.xid )
	end
		
	if header.type ~= MessageType.Reply then
		return false, string.format("Packet was not a reply")
	end
		
	if header.state ~= REPLY_ACCEPTED then
		return false, string.format("Reply state was not Accepted(0) as expected")
	end
		
	if header.accept_state ~= SUCCESS then
		return false, string.format("Accept State was not Successful")
	end

	local mount_status
	data = try( getAdditionalBytes( socket, data, pos, 4 ) )
	pos, mount_status = bin.unpack(">I", data, pos )

	if mount_status ~= MOUNT_OK then
		return false, string.format("Mount failed: %d", mount_status)
	end
	
	data = try( getAdditionalBytes( socket, data, pos, 32 ) )
	pos, fhandle = bin.unpack( "A32", data, pos )
	
	return true, fhandle
	
end


function nfsLookup( socket, file_handle, dir, options )


end

--- Reads the contents inside a NFS directory
--
-- @param socket socket connected to the NFS program
-- @param proto string containing either "udp" or "tcp"
-- @param file_handle string containing the filehandle to query
-- @param options table containing <code>xid</code>, <code>version</code> and <code>auth</code>
-- @return table of file table entries as described in <code>decodeReadDir</code>
function nfsReadDir( socket, proto, file_handle, options )

	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)
	local auth = options.auth
	local status, packet = createHeader( options.xid, 100003, options.version, Procedure.READDIR, auth )
	local cookie, count = 0, 8192
	local pos, data, _ = 1, "", ""
	local header, entries = {}, {}

	if not status then
		return false, packet
	end
	
	if not file_handle or file_handle:len() ~= 32 then
		return false, "Incorrect filehandle recieved"
	end
	
	packet = packet .. bin.pack("A", file_handle)
	packet = packet .. bin.pack(">I", cookie)
	packet = packet .. bin.pack(">I", count)

	-- set the high bit as this is our last fragment
	local len = 0x80000000
	len = len + packet:len()
	
	packet = bin.pack(">I", len) .. packet

	try( socket:send( packet ) )

	if proto == "tcp" then
		data = decodeRpcTcpPacket( socket )
	end

	pos, header = decodeHeader( socket, data, pos )
	
	if not header then
		return false, "Failed to decode header"
	end
	
	pos, entries = decodeReadDir( socket, data, pos )
	
	
	return true, entries
end

--- Decodes the READDIR section of a NFS ReadDir response
--
-- @param socket already connected to the NFS program
-- @param data string containing the buffer of bytes read so far
-- @param pos number containing the current offset into data
-- @return pos number containing the offset after the decoding
-- @return entries table containing <code>file_id</code>, <code>name</code> and <code>cookie</code>
function decodeReadDir( socket, data, pos )

	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)
	local entries, entry = {}, {}
	local value_follows
	local status

	local NFS_OK = 0

	data = try( getAdditionalBytes( socket, data, pos, 4 ) )
	pos, status = bin.unpack(">I", data, pos)

	if status ~= NFS_OK then
		return -1, nil
	end


	while true do
		entry = {}
		data = try( getAdditionalBytes( socket, data, pos, 4 ) )
		pos, value_follows = bin.unpack(">I", data, pos)
	
		if value_follows == 0 then
			break
		end

		data = try( getAdditionalBytes( socket, data, pos, 8 ) )
		pos, entry.file_id, entry.length = bin.unpack(">I>I", data, pos)
		data = try( getAdditionalBytes( socket, data, pos, entry.length ) )
		pos, entry.name = bin.unpack("A" .. entry.length, data, pos)
		pos = pos + calcFillBytes( entry.length )
		pos, entry.cookie = bin.unpack(">I", data, pos)
		
		table.insert( entries, entry )
	end
	
	
	return pos, entries	
	
end


--- Gets filesystem stats (Total Blocks, Free Blocks and Available block) on a remote NFS share
--
-- @param socket socket connected to the NFS program
-- @param proto string containing either "udp" or "tcp"
-- @param file_handle string containing the filehandle to query
-- @param options table containing <code>xid</code>, <code>version</code> and <code>auth</code>
-- @returns status true on success, false on failure
-- @returns statfs table with the fields <code>transfer_size</code>, <code>block_size</code>, 
-- 	<code>total_blocks</code>, <code>free_blocks</code> and <code>available_blocks</code>
-- @returns errormsg if status is false
function nfsStatFs( socket, proto, file_handle, options )

	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)
	local auth = options.auth
	local status, packet = createHeader( options.xid, 100003, options.version, Procedure.STATFS, auth )
	local pos, data, _ = 1, "", ""
	local header, statfs = {}, {}
	
	if not status then
		return false, packet
	end
	
	if not file_handle or file_handle:len() ~= 32 then
		return false, "Incorrect filehandle recieved"
	end
	
	packet = packet .. bin.pack("A", file_handle )

	-- set the high bit as this is our last fragment
	local len = 0x80000000
	len = len + packet:len()
	
	packet = bin.pack(">I", len) .. packet

	try( socket:send( packet ) )

	if proto == "tcp" then
		data = decodeRpcTcpPacket( socket )
	end

	pos, header = decodeHeader( socket, data, pos )
	
	if not header then
		return false, "Failed to decode header"
	end
	
	pos, statfs = decodeStatFs( socket, data, pos )

	if not statfs then
		return false, "Failed to decode statfs structure"
	end
	
	return true, statfs

end

--- Attempts to decode the StatFS section of the reply
--
-- @param socket socket already connected to the server
-- @param data string containing the full statfs reply
-- @param pos number pointing to the statfs section of the reply
-- @return pos number containing the offset after decoding
-- @return statfs table with the following fields: <code>transfer_size</code>, <code>block_size</code>, 
-- 	<code>total_blocks</code>, <code>free_blocks</code> and <code>available_blocks</code>
--
function decodeStatFs( socket, data, pos )

	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)
	local statfs = {}
	local NFS_OK, NSFERR_ACCESS = 0, 13

	data = try( getAdditionalBytes( socket, data, pos, 4 ) )
	pos, statfs.status = bin.unpack(">I", data, pos)

	if statfs.status ~= NFS_OK then
		if statfs.status == NSFERR_ACCESS then
			stdnse.print_debug("STATFS query recieved NSFERR_ACCESS")
		end
		return -1, nil
	end

	data = try( getAdditionalBytes( socket, data, pos, 20 ) )
	pos, statfs.transfer_size, statfs.block_size, 
	statfs.total_blocks, statfs.free_blocks, 
	statfs.available_blocks = bin.unpack(">IIIII", data, pos )
	
	return pos, statfs
	
end

--- Creates a RPC header
--
-- @param xid number
-- @param program_id number containing the program_id to connect to
-- @param program_version number containing the version to query
-- @param procedure number containing the procedure to call
-- @param auth table containing the authentication data to use
-- @return string of bytes
function createHeader( xid, program_id, program_version, procedure, auth )
	
	local RPC_VERSION = 2
	local packet
	
	if not xid then
		return false, "Xid may not be empty"
	end
		
	if not auth or auth.type ~= AuthType.Null then
		return false, "No or invalid authentication type specified"
	end
	
	packet = bin.pack( ">IIIIII", xid, MessageType.Call, RPC_VERSION, program_id, program_version, procedure )
	
	if auth.type == AuthType.Null then
		packet = packet .. bin.pack( "IIII", 0, 0, 0, 0 )
	end		
	

	return true, packet
end

--- Strips the additional RCP headers used over TCP
--
-- @param socket already connected to the RPC program
-- @return data stripped from RPC TCP headers
function decodeRpcTcpPacket( socket )

	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)
	
	local tmp, lastfragment, length
	local data, pos = "", 1

	repeat
		lastfragment = false
		data = try( getAdditionalBytes( socket, data, pos, 4 ) )
		pos, tmp = bin.unpack(">i", data, pos )
		length = bit.band( tmp, 0x7FFFFFFF )
	
		if bit.band( tmp, 0x80000000 ) == 0x80000000 then
			lastfragment = true
		end

		data = try( getAdditionalBytes( socket, data, pos, length ) )
		
		--
		-- When multiple packets are recieved they look like this
		-- H = Header data
		-- D = Data
		-- 
		-- We don't want the Header
		--
		-- HHHHDDDDDDDDDDDDDDHHHHDDDDDDDDDDD
		-- ^   ^             ^   ^
		-- 1   5             18  22
		--
		-- eg. we want
		-- data:sub(5, 18) and data:sub(22)
		-- 
		
		local bufcopy = data:sub(pos)
		
		if 1 ~= pos - 4 then
			bufcopy = data:sub(1, pos - 5) .. bufcopy
			pos = pos - 4
		else
			pos = 1
		end
					
		pos = pos + length
		data = bufcopy
		
	until lastfragment == true	

	pos = 1
	
	return data
	
end

--- Lists the NFS exports on the remote host
-- This function abstracts the RPC communication with the portmapper from the user
--
-- @param host table
-- @return result table of string entries
function getNfsExports( host )
	
    local data, ports = {}, {}
    local status, result, mounts 
	local socket = nmap.new_socket()
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)

	math.randomseed( os.time() )
	
	-- if the response is large, we need some time
	-- set a reasonable timeout value
	socket:set_timeout(10000)
	
	-- get ports for mountd RPC program
	ports = getPortsForProgram(host, "mountd", 1)
	
	-- if we failed to get a table of ports from the rpc service abort
	if ports == nil then
		return false, "Failed to retrieve ports from RPC service"
	end

	for _, proto in pairs({"tcp","udp"}) do

		if ports[proto] ~= nil then
	
			status, result = socket:connect(host.ip, ports[proto], proto)
			
			-- if the socket was successfully connected try to get the exports
			if status then
				status, mounts = rpc.mountExportCall( socket, proto, { xid=math.random(1234567890), version=1, auth={ type=rpc.AuthType.Null } } )
			end

			socket:close()
			break
		end
		
	end
	
	return true, mounts
	
end

--- Retrieves NFS storage statistics
--
-- @param host table
-- @param path string containing the nfs export path
-- @returns statfs table with the fields <code>transfer_size</code>, <code>block_size</code>, 
-- 	<code>total_blocks</code>, <code>free_blocks</code> and <code>available_blocks</code>
function getNfsExportStats( host, path )

	local socket = nmap.new_socket()
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)
	local fhandle, xid
	local options, stats, status

	socket:set_timeout(5000)

	math.randomseed( os.time() )
	
	xid = math.random(1234567890)
	options = {['xid']=xid, version=1, auth={ type=rpc.AuthType.Null } }
	-- get ports for mountd RPC program
	local mountd_ports = getPortsForProgram(host, "mountd", 2)
	local nfs_ports = getPortsForProgram(host, "nfs", 2)
	
	-- if we failed to get a table of ports from the rpc service abort
	if not mountd_ports or not nfs_ports then
		return false, "Failed to query RPC for mountd and nfs ports"
	end

	for _, proto in pairs({"tcp","udp"}) do
		if mountd_ports[proto] ~= nil then
			try ( socket:connect( host.ip, mountd_ports[proto], proto ) )
	 		fhandle = try ( rpc.mountCall( socket, proto, path, options ) )
 			try ( socket:close() )
			break
		end
	end
	
	for _, proto in pairs({"tcp","udp"}) do
		if nfs_ports[proto] ~= nil then
			try ( socket:connect( host.ip, nfs_ports[proto], proto ) )
			options.version = 2
			status, stats = nfsStatFs( socket, proto, fhandle, options )
			try ( socket:close() )
			
			if status then
				break
			end
		end
	end

	if not status then
		return false, string.format("Failed to retrieve stats for export: %s", path ) 
	end

	return true, stats
end

--- Retrieves a list of files from the NFS export
--
-- @param host table
-- @param path string containing the nfs export path
-- @return table of file table entries as described in <code>decodeReadDir</code>
function getNfsDirList( host, path )

	local socket = nmap.new_socket()
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)
	local fhandle, xid
	local options, dirs, status

	socket:set_timeout(5000)

	math.randomseed( os.time() )
	
	xid = math.random(1234567890)
	options = {['xid']=xid, version=1, auth={ type=rpc.AuthType.Null } }

	local mountd_ports = getPortsForProgram(host, "mountd", 2)
	local nfs_ports = getPortsForProgram(host, "nfs", 2)
	
	if not mountd_ports or not nfs_ports then
		return false, "Failed to query RPC for mountd and nfs ports"
	end

	for _, proto in pairs({"tcp","udp"}) do
		if mountd_ports[proto] ~= nil then
			try ( socket:connect( host.ip, mountd_ports[proto], proto ) )
	 		fhandle = try ( rpc.mountCall( socket, proto, path, options ) )
 			try ( socket:close() )
			break
		end
	end
	
	for _, proto in pairs({"tcp","udp"}) do
		if nfs_ports[proto] ~= nil then
			try ( socket:connect( host.ip, nfs_ports[proto], proto ) )
			options.version = 2
			status, dirs = nfsReadDir( socket, proto, fhandle, options )
			try ( socket:close() )
			
			if status then
				break
			end
		end
	end

	if not status then
		return false, string.format("Failed to retrieve a directory listing for export: %s", path ) 
	end

	return true, dirs
	
end
