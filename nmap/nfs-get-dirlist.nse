description = [[
Does a directory listing of a remote NFS share
]]

---
-- @output
-- PORT    STATE SERVICE
-- 111/tcp open  rpcbind
--
-- Host script results:
-- | nfs-get-dirlist:  
-- |   /home/storage/backup
-- |     freepbx
-- |     ofw.cqure.net
-- |   /home
-- |     admin
-- |     lost+found
-- |     patrik
-- |     storage
-- |_    web
--

-- Version 0.1
--
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
	local result, files = {}, {}
	local hasmore = false

	for _, v in ipairs( mounts ) do
		local files = {}
		local status, dirlist = rpc.getNfsDirList(host, v.name)
			
		if status and dirlist then
			local max_files = tonumber(nmap.registry.args.nfs_max_files) or 10
			hasmore = false
			for _, v in ipairs( dirlist ) do
				if #files >= max_files then
					hasmore = true
					break
				end

				if v.name ~= ".." and v.name ~= "." then
					table.insert(files, v.name)
				end				
			end

			table.sort(files)
			
			if hasmore then
				files.name = v.name .. string.format(" (Output limited to %d files)", max_files )
			else
				files.name = v.name
			end

			table.insert( result, files )
		end
		
	end	

	return stdnse.format_output( true, result )
	
end

