description = [[
Attempts to enumerate DNS hostnames by brute force guessing of common subdomains.
]]
-- 2011-01-26

---
-- @usage
-- nmap --script dns-brute --script-args dns-brute.domain=foo.com,dns-brute.threads=6,dns-brute.cclass,dns-brute.hostlist=./hostfile.txt,newtargets -sS -p 80
-- nmap --script dns-brute www.foo.com
-- nmap -6 --script dns-brute --script-args dns-brute.cclass,dns-brute.domain=foo.com,dns-brute.ipv6=only,newtargets -v -p 80
-- @args dns-brute.hostlist The filename of a list of host strings to try.
-- @args dns-brute.threads Thread to use (default 5).
-- @args dns-brute.cclass If specified, adds the reverse DNS for the c-class of all discovered IP addresses. cclass can 
--	 also be set to the value 'printall' to print all reverse DNS names instead of only the ones matching the base domain
-- @args dns-brute.ipv6 Perform lookup for IPv6 addresses as well. ipv6 can also be se to the value 'only' to only lookup IPv6 records
-- @args dns-brute.srv Perform lookup for SRV records
-- @args dns-brute.domain Domain name to brute force if no host is specified
-- @args newtargets Add discovered targets to nmap scan queue. 
--	 If dns-brute.ipv6 is used don't forget to set the -6 Nmap flag, if you require scanning IPv6 hosts.
-- @output
-- Pre-scan script results:
-- | dns-brute: 
-- |   DNS Brute-force hostnames
-- |     www.foo.com - 127.0.0.1
-- |     mail.foo.com - 127.0.0.2
-- |     blog.foo.com - 127.0.1.3
-- |     ns1.foo.com - 127.0.0.4
-- |     admin.foo.com - 127.0.0.5
-- |   Reverse DNS hostnames
-- |     srv-32.foo.com - 127.0.0.16
-- |     srv-33.foo.com - 127.0.1.23
-- |   C-Classes
-- |     127.0.0.0/24
-- |_    127.0.1.0/24

author = "cirrus [0x0lab.org]"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"intrusive", "discovery"}

prerule = function()
    if not stdnse.get_script_args("dns-brute.domain") then
      stdnse.print_debug(3,
        "Skipping '%s' %s, 'dns-brute.domain' argument is missing.",
        SCRIPT_NAME, SCRIPT_TYPE)
      return false
    end
    return true
end

hostrule = function(host)
	return true
end


require 'dns'
require 'stdnse'
require 'target'

local HOST_LIST = {
	'www', 'mail', 'blog', 'ns0', 'ns1', 'mail2', 'mail3', 'admin', 'ads', 'ssh',
	'voip', 'sip', 'dns', 'ns2', 'ns3', 'dns0', 'dns1', 'dns2', 'eshop', 'shop',
	'forum', 'ftp', 'ftp0', 'host', 'log', 'mx0', 'mx1', 'mysql', 'sql', 'news',
	'noc', 'ns', 'auth', 'administration', 'adserver', 'alerts', 'alpha', 'ap',
	'app', 'apache', 'apps' , 'appserver', 'gw', 'backup', 'beta', 'cdn', 'chat',
	'citrix', 'cms', 'erp', 'corp', 'intranet', 'crs', 'svn', 'cvs', 'git', 'db',
	'database', 'demo', 'dev', 'devsql', 'dhcp', 'dmz', 'download', 'en', 'f5',
	'fileserver', 'firewall', 'help', 'http', 'id', 'info', 'images', 'internal',
	'internet', 'lab', 'ldap', 'linux', 'local', 'log', 'ipv6', 'syslog',
	'mailgate', 'main', 'manage', 'mgmt', 'monitor', 'mirror', 'mobile', 'mssql',
	'oracle', 'exchange', 'owa', 'mta', 'mx', 'mx0', 'mx1', 'ntp', 'ops', 'pbx',
	'whois', 'ssl', 'secure', 'server', 'smtp', 'squid', 'stage', 'stats', 'test',
	'upload', 'vm', 'vnc', 'vpn', 'wiki', 'xml', 'direct',
}

local SRV_LIST = {
	'_afpovertcp._tcp', '_ssh._tcp', '_autodiscover._tcp', '_caldav._tcp',
	'_client._smtp', '_gc._tcp', '_h323cs._tcp', '_h323cs._udp', '_h323ls._tcp',
	'_h323ls._udp', '_h323rs._tcp', '_h323rs._tcp', '_http._tcp', '_iax.udp',
	'_imap._tcp', '_imaps._tcp', '_jabber-client._tcp', '_jabber._tcp',
	'_kerberos-adm._tcp', '_kerberos._tcp', '_kerberos._tcp.dc._msdcs',
	'_kerberos._udp', '_kpasswd._tcp', '_kpasswd._udp', '_ldap._tcp',
	'_ldap._tcp.dc._msdcs', '_ldap._tcp.gc._msdcs', '_ldap._tcp.pdc._msdcs',
	'_msdcs', '_mysqlsrv._tcp', '_ntp._udp', '_pop3._tcp', '_pop3s._tcp',
	'_sip._tcp', '_sip._tls', '_sip._udp', '_sipfederationtls._tcp',
	'_sipinternaltls._tcp', '_sips._tcp', '_smtp._tcp', '_stun._tcp',
	'_stun._udp', '_tcp', '_tls', '_udp', '_vlmcs._tcp', '_vlmcs._udp',
	'_wpad._tcp', '_xmpp-client._tcp', '_xmpp-server._tcp',
}

local function guess_domain(host)
	local name

	name = stdnse.get_hostname(host)
	if name and name ~= host.ip then
		return string.match(name, "%.([^.]+%..+)%.?$") or string.match(name, "^([^.]+%.[^.]+)%.?$")
	else
		domainname = host
		return nil
 	end
	return domainname
end

--- Remove the last octet of an IP address
--@param ip IP address to parse
--@return IP address without the last octet
local function iptocclass(ip)
	local o1, o2, o3, o4 = ip:match("^(%d*)%.(%d*)%.(%d*)%.(%d*)$")
	return o1..'.'..o2..'.'..o3
end

--- Check if an element is inside a table
--@param table Table to check
--@param element Element to find in table
--@return boolean Element was found or not
function table.contains(table, element)
	if(type(table) == "table") then
		for _, value in pairs(table) do
			if value == element then
				return true
			end
		end
	end
	return false
end

local function resolve(host, dtype)
	if dtype=='PTR' then
		host = dns.reverse(host)
	end
	local status, result = dns.query(host, {dtype=dtype,retAll=true})
	return status and result or false
end

--- Verbose printing function when -v flag is specified
--@param msg The message to print
local function print_verb(msg)
	local verbosity, debugging = nmap.verbosity, nmap.debugging
	if verbosity() >= 2 or debugging() > 0 then
		print(msg)
	end
end

local function array_iter(array, i, j)
	return coroutine.wrap(function ()
		while i <= j do
			coroutine.yield(array[i])
			i = i + 1
		end
	end)
end

local function thread_main(domainname, results, name_iter)
	local condvar = nmap.condvar( results )
	for name in name_iter do
		if not (ipv6 == 'only') then
			local res = resolve(name..'.'..domainname,"A")
			if(res) then
				for _,addr in ipairs(res) do
					local hostn = name..'.'..domainname
					if target.ALLOW_NEW_TARGETS then
						stdnse.print_debug("Added target: "..hostn)
						local status,err = target.add(hostn)
					end
					print_verb("Hostname: "..hostn.." IP: "..addr)
					results[#results+1] = { hostname=hostn, address=addr }
				end
			end
		end
		if ipv6 then
			local res = resolve(name..'.'..domainname,"AAAA")
			if(res) then
				for _,addr in ipairs(res) do
					local hostn = name..'.'..domainname
					if target.ALLOW_NEW_TARGETS then
						stdnse.print_debug("Added target: "..hostn)
						local status,err = target.add(hostn)
					end
					print_verb("Hostname: "..hostn.." IP: "..addr)
					results[#results+1] = { hostname=hostn, address=addr }
				end
			end
		end
	end
	--condvar("signal")
end

local function srv_main(domainname, srvresults, srv_iter )
	local condvar = nmap.condvar( srvresults )
	for name in srv_iter do
		local res = resolve(name..'.'..domainname,"SRV")
		if(res) then
			for _,addr in ipairs(res) do
				local hostn = name..'.'..domainname
				addr = stdnse.strsplit(":",addr)
				if not (ipv6 == 'only') then
					local srvres = resolve(addr[4],"A")
					if(srvres) then
						for srvhost,srvip in ipairs(srvres) do
							print_verb("Hostname: "..hostn.." IP: "..srvip)
							srvresults[#srvresults+1] = { hostname=hostn, address=srvip }
							if nmap.registry.args['dns-brute.domain'] and target.ALLOW_NEW_TARGETS then
								stdnse.print_debug("Added target: "..srvip)
								local status,err = target.add(srvip)
							end
						end
					end
				end
				if ipv6 then
					local srvres = resolve(addr[4],"AAAA")
					if(srvres) then
						for srvhost,srvip in ipairs(srvres) do
							print_verb("Hostname: "..hostn.." IP: "..srvip)
							srvresults[#srvresults+1] = { hostname=hostn, address=srvip }
							if nmap.registry.args['dns-brute.domain'] and target.ALLOW_NEW_TARGETS then
								stdnse.print_debug("Added target: "..srvip)
								local status,err = target.add(srvip)
							end
						end
					end

				end
			end
		end
	end
	--condvar("signal")
end

local function reverse_main(domainname, revresults, rev_iter)
	local condvar = nmap.condvar( revresults )
	for name in rev_iter do
		local res = resolve(name,"PTR")
		if(res) then
			for _,host in ipairs(res) do
				if(revcclass == 'printall') then
					if(not string.match(host,'addr.arpa$')) then
						if nmap.registry.args['dns-brute.domain'] and target.ALLOW_NEW_TARGETS then
							stdnse.print_debug("Added target: "..name)
							local status,err = target.add(name)
						end
						print_verb("Hostname: "..host.." IP: "..name)
						revresults[#revresults+1] = { hostname=host, address=name }
					end
				else
					if(string.match(host,domainname..'$')) then
						if nmap.registry.args['dns-brute.domain'] and target.ALLOW_NEW_TARGETS then
							stdnse.print_debug("Added target: "..name)
							local status,err = target.add(name)
						end
						print_verb("Hostname: "..host.." IP: "..name)
						revresults[#revresults+1] = { hostname=host, address=name }
					end
				end
			end
		end
	end
	--condvar("signal")
end

action = function(host)
	local domainname = stdnse.get_script_args('dns-brute.domain')
	if not domainname then
		domainname = guess_domain(host)
	end
	if not domainname then
		return string.format("Can't guess domain of \"%s\"; use %s.domain script argument.", stdnse.get_hostname(host), SCRIPT_NAME)
	end

	if not nmap.registry.bruteddomains then
		nmap.registry.bruteddomains = {}
	end
	if(not table.contains(nmap.registry.bruteddomains,domainname)) then
		table.insert(nmap.registry.bruteddomains, domainname)
		print_verb("Starting dns-brute at: "..domainname)
		local max_threads = stdnse.get_script_args('dns-brute.threads') and tonumber( stdnse.get_script_args('dns-brute.threads') ) or 5		
		ipv6 = stdnse.get_script_args("dns-brute.ipv6") or false
		dosrv = stdnse.get_script_args("dns-brute.srv") or false
		if(ipv6 == 'only') then
			revcclass = false
		else
			revcclass = stdnse.get_script_args("dns-brute.cclass") or false
		end
		stdnse.print_debug("THREADS: "..max_threads)
		local fileName = stdnse.get_script_args('dns-brute.hostlist')
		local hostlist
		if fileName then
			local file = io.open(fileName)
			if file then
				hostlist = {}
				while true do
					local l = file:read()
					if not l then
						break
					end
					if not l:match("#!comment:") then
						table.insert(hostlist, l)
					end
				end
				file:close()
			else
				if fileName then
					print("dns-brute: Hostlist file not found. Will use default list.")
				end
			end
		end
		if (not hostlist) then hostlist = HOST_LIST end
		local srvlist = SRV_LIST

		local threads, results, revresults, srvresults = {}, {}, {}, {}
		results['name'] = "Result:"
		local condvar = nmap.condvar( results )
		local i = 1
		local howmany = math.floor(#hostlist/max_threads)+1
		stdnse.print_debug("Hosts per thread: "..howmany)
		repeat
			local j = math.min(i+howmany, #hostlist)
			local name_iter = array_iter(hostlist, i, j)
			threads[stdnse.new_thread(thread_main, domainname, results, name_iter)] = true
			i = j+1
		until i > #hostlist
		local done
		-- wait for all threads to finish
		while( not(done) ) do
			condvar("wait")
			done = true
			for thread in pairs(threads) do
				if (coroutine.status(thread) ~= "dead") then done = false end
			end
		end

		if(dosrv) then
			local i = 1
			local threads = {}
			local howmany_ip = math.floor(#srvlist/max_threads)+1
			local condvar = nmap.condvar( srvresults )
			stdnse.print_debug("SRV's per thread: "..howmany_ip)
			repeat
				local j = math.min(i+howmany_ip, #srvlist)	
				local name_iter = array_iter(srvlist, i, j)
				threads[stdnse.new_thread(srv_main, domainname, srvresults, name_iter)] = true
				i = j+1
			until i > #srvlist
			local done
			-- wait for all threads to finish
			while( not(done) ) do
				condvar("wait")
				done = true
				for thread in pairs(threads) do
					if (coroutine.status(thread) ~= "dead") then done = false end
				end
			end
		end

		if (revcclass and not (ipv6=='only')) then
			cclasses = {}
			ipaddresses = {}
			local i = 1
			for _, res in ipairs(results) do
				if res['address']:match(":") then
					print_verb("IPv6 class detected skipping: "..res['address'])
				else
					local class = iptocclass(res['address'])
					if(not table.contains(cclasses,class)) then
						print_verb("C-Class: "..class..".0/24")
						table.insert(cclasses,class)
					end
				end
			end
			if(dosrv) then
				for _, res in ipairs(srvresults) do
					if res['address']:match(":") then
						print_verb("IPv6 class detected skipping: "..res['address'])
					else
						local class = iptocclass(res['address'])
						if(not table.contains(cclasses,class)) then
							print_verb("C-Class: "..class..".0/24")
							table.insert(cclasses,class)
						end
					end
				end
			end
			for _,class in ipairs(cclasses) do
				for v=1,254,1 do
					table.insert(ipaddresses, class..'.'..v)
				end
			end
			stdnse.print_debug("Will reverse lookup "..#ipaddresses.." IPs")
			print_verb("Starting reverse DNS in c-classes")
			local threads = {}
			local howmany_ip = math.floor(#ipaddresses/max_threads)+1
			local condvar = nmap.condvar( revresults )
			stdnse.print_debug("IP's per thread: "..howmany_ip)
			repeat
				local j = math.min(i+howmany_ip, #ipaddresses)	
				local name_iter = array_iter(ipaddresses, i, j)
				threads[stdnse.new_thread(reverse_main, domainname, revresults, name_iter)] = true
				i = j+1
			until i > #ipaddresses
			local done
			-- wait for all threads to finish
			while( not(done) ) do
				condvar("wait")
				done = true
				for thread in pairs(threads) do
					if (coroutine.status(thread) ~= "dead") then done = false end
				end
			end
		end
		response = {}
		t_dns = {}
		t_dns['name'] = "DNS Brute-force hostnames"
		if(#results==0) then
			table.insert(t_dns,"No results.")
		end
		for _, res in ipairs(results) do
			table.insert(t_dns, res['hostname'].." - "..res['address'])
		end
		response[#response + 1] = t_dns
		if(dosrv) then
			t_srv = {}
			t_srv['name'] = "SRV results"
			if(#srvresults==0) then
				table.insert(t_srv,"No results.")
			end
			for _, res in ipairs(srvresults) do
				table.insert(t_srv, res['hostname'].." - "..res['address'])
			end
			response[#response + 1] = t_srv
		end
		if revcclass then
			t_rev = {}
			t_rev['name'] = "Reverse DNS hostnames:"									
			if(#revresults==0) then
				table.insert(t_rev,"No results.")
			end
			for _, res in ipairs(revresults) do
				table.insert(t_rev, res['hostname'].." - "..res['address'])
			end
			response[#response + 1] = t_rev
			if(#cclasses>0) then
				t_cclass = {}
				t_cclass['name'] = "C-Classes:"
				for _, res in ipairs(cclasses) do
					table.insert(t_cclass, res..".0/24")
				end
				response[#response + 1] = t_cclass
			end
		end
		return stdnse.format_output(true, response)
	end
end

