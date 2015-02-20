description = [[
Retrieves disk space statistics from the remote NFS share
]]

---
-- @output
-- PORT    STATE SERVICE
-- 111/tcp open  rpcbind
--
-- Host script results:
-- | nfs-get-stats:  
-- |   /home/storage/backup
-- |     Block size: 512
-- |     Total blocks: 1901338728
-- |     Free blocks: 729769328
-- |     Available blocks: 633186880
-- |   /home
-- |     Block size: 512
-- |     Total blocks: 1901338728
-- |     Free blocks: 729769328
-- |_    Available blocks: 633186880
--

-- Version 0.1

-- Created 01/25/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>


author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require 'datafiles'
require 'rpc'

hostrule = function(host)

    local port_t111 = nmap.get_port_state(host, {number=111, protocol="udp"})
    local port_u111 = nmap.get_port_state(host, {number=111, protocol="tcp"})

    return  ( port_t111 ~= nil and port_t111.state == "open" ) or
			( port_u111 ~= nil and ( port_u111.state == "open" or port_u111.state == "open|filtered" ) )

end

action = function(host)

	local status, mounts = rpc.getNfsExports( host )
	local result, stats = {}, {}

	for _, v in ipairs( mounts ) do
		local entry = {}
		local status, stats = rpc.getNfsExportStats(host, v.name)
		entry.name = v.name
		
		if status and stats then
			table.insert( entry, string.format("Block size: %d", stats.block_size) )
			table.insert( entry, string.format("Total blocks: %d", stats.total_blocks) )
			table.insert( entry, string.format("Free blocks: %d", stats.free_blocks) )
			table.insert( entry, string.format("Available blocks: %d", stats.available_blocks) )
			table.insert( result, entry )
		end
	end	

	return stdnse.format_output( true, result )
	
end

