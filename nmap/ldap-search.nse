description = [[
Attempts to perform an LDAP search and returns all matches.
]]

---
-- @usage
-- nmap -p 389 --script ldap-search --script-args username="'cn=ldaptest,cn=users,dc=cqure,dc=net'",password=ldaptest,filter=users,attrib=sAMAccountName <host>
--
-- @output
-- PORT    STATE SERVICE REASON
-- 389/tcp open  ldap    syn-ack
-- | ldap-search:  
-- |   DC=cqure,DC=net
-- |     dn: CN=Administrator,CN=Users,DC=cqure,DC=net
-- |         sAMAccountName: Administrator
-- |     dn: CN=Guest,CN=Users,DC=cqure,DC=net
-- |         sAMAccountName: Guest
-- |     dn: CN=SUPPORT_388945a0,CN=Users,DC=cqure,DC=net
-- |         sAMAccountName: SUPPORT_388945a0
-- |     dn: CN=EDUSRV011,OU=Domain Controllers,DC=cqure,DC=net
-- |         sAMAccountName: EDUSRV011$
-- |     dn: CN=krbtgt,CN=Users,DC=cqure,DC=net
-- |         sAMAccountName: krbtgt
-- |     dn: CN=Patrik Karlsson,CN=Users,DC=cqure,DC=net
-- |         sAMAccountName: patrik
-- |     dn: CN=VMABUSEXP008,CN=Computers,DC=cqure,DC=net
-- |         sAMAccountName: VMABUSEXP008$
-- |     dn: CN=ldaptest,CN=Users,DC=cqure,DC=net
-- |_        sAMAccountName: ldaptest
--
--
-- @args username If set, the script will attempt to perform an LDAP bind using the username and password
-- @args password If set, used together with the username to authenticate to the LDAP server
-- @args filter If set, specifies what kind of objects to retrieve. The script does not yet support real LDAP filters.
--       The following values are valid for the filter parameter: computer, users or all. If no value is specified it defaults to all.
-- @args base If set, the script will use it as a base for the search. By default the defaultNamingContext is retrieved and used.
--       If no defaultNamingContext is available the script iterates over the available namingContexts
-- @args attrib If set, the search will include only the attributes specified. For a single attribute a string value can be used, if
--       multiple attributes need to be supplied a table should be used instead.
--
--
-- Credit goes out to Martin Swende who provided me with the initial code that got me started writing this.
--

-- Version 0.2
-- Created 01/12/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/20/2010 - v0.2 - added SSL support

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

require "ldap"
require 'shortport'

portrule = shortport.port_or_service({389,636}, {"ldap","ldapssl"})

function action(host,port)

	local status
	local socket = nmap.new_socket()
	
	local username = nmap.registry.args.username
	local password = nmap.registry.args.password
	local objtype  = nmap.registry.args.filter
	local base     = nmap.registry.args.base
	local attribs  = nmap.registry.args.attrib
	
	-- set a reasonable timeout value
	socket:set_timeout(10000)
	
	-- do some exception handling / cleanup
	local catch = function()
		socket:close()
	end
	
	local try = nmap.new_try(catch)

	-- first attempt to connect over SSL and then fallback to TCP
	if nmap.have_ssl() then
		status = socket:connect(host.ip, port.number, "ssl")
	
		-- no dice, SSL ain't available
		if not status then
			try( socket:connect(host.ip, port.number, "tcp") )
		end
	else
		-- no ssl is available in Nmap
		try( socket:connect(host.ip, port.number, "tcp") )
	end

	-- perform a bind only if we have valid credentials
	if ( username ) then
		local bindParam = { version=3, ['username']=username, ['password']=password}
		try( ldap.bindRequest( socket, bindParam ) )
	end
	
	local req
	local searchResEntries
	local contexts = {}
	local result = {} 
	local filter

	if base == nil then
		req = { baseObject = "", scope = ldap.SCOPE.base, derefPolicy = ldap.DEREFPOLICY.default, attributes = { "defaultNamingContext", "namingContexts" } }
		searchResEntries = try( ldap.searchRequest( socket, req ) )				

		contexts = ldap.extractAttribute( searchResEntries, "defaultNamingContext" )

		-- OpenLDAP does not have a defaultNamingContext
		if #contexts == 0 then
			contexts = ldap.extractAttribute( searchResEntries, "namingContexts" )
		end
	else
		table.insert(contexts, base)
	end

	
	if objtype == "users" then
		filter = { op=ldap.FILTER._or, val= 
						{ 
							{ op=ldap.FILTER.equalityMatch, obj='objectClass', val='user' }, 
							{ op=ldap.FILTER.equalityMatch, obj='objectClass', val='posixAccount' } 
						}
				   }
	elseif objtype == "computers" or objtype == "computer" then
		filter = { op=ldap.FILTER.equalityMatch, obj='objectClass', val='computer' }
	elseif objtype == "all" or objtype == nil then
		filter = nil -- { op=ldap.FILTER}
	else
		assert( filter~=nil, string.format("Unknown object type: %s", objtype) )
	end
	
	if type(attribs) == 'string' then
		local tmp = attribs
		attribs = {}
		table.insert(attribs, tmp)
	end
	
	for _, context in ipairs(contexts) do
	
		req = { baseObject = context, scope = ldap.SCOPE.sub, derefPolicy = ldap.DEREFPOLICY.default, filter = filter, attributes = attribs }
		searchResEntries = try( ldap.searchRequest( socket, req ) )
				
		local result_part = ldap.searchResultToTable( searchResEntries )
		result_part.name = context
		
		table.insert( result, result_part )

		-- catch any softerrors
		if searchResEntries.resultCode ~= 0 then
			local output = stdnse.format_output(true, result )
			output = output .. string.format(" \n\n\n=========== %s ===========", searchResEntries.errorMessage )
			
			return output
		end

	end

	-- perform a unbind only if we have valid credentials
	if ( username and password ) then
		try( ldap.unbindRequest( socket ) )
	end
	
	socket:close()
	
	-- if taken a way and ldap returns a single result, it ain't shown....
	result.name = "LDAP Results"
	
	return stdnse.format_output(true, result )
end
