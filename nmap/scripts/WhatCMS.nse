local http=require "http"
local shortport=require "shortport"
local stdnse=require "stdnse"
local table = require "table"
local openssl = stdnse.silent_require "openssl"
local io = require "io"

description=[[
Attempts to scan website file]]
author="m0zh3"
categories= {"recon","web"}

-- The Rule Section --
portrule = shortport.http
-- The Action Section --

local cms_path = stdnse.get_script_args('cms.path')
local cms_fp = stdnse.get_script_args('cms.fp')
local input={}
local result={}
local output={}
local response
local url='www.114best.com'
local path='/ip/114.aspx?w='

local function get_links(body)
        links={}
        body=string.lower(body)
        for s in string.gmatch(body,">(%w+%.%w+%.%w+)</a>") do
                table.insert(links,s)
        end
        return links
end

local function identify_CMS(host,port,uri)
	local response = http.get(host,port,uri,{no_cache = true})
	if response.status == 200 then
		stdnse.print_debug(uri.." - "..stdnse.tohex(openssl.md5(response.body)))
		table.insert(output,stdnse.tohex(openssl.md5(response.body)))
	end
	return output
end

local function remove_dup(arr)
	local pos = {}
	for i = 1,#arr do
		table.insert(pos,'f')
	end
	for i = 1,#pos do
		if pos[i] == 'f' then
			for j = 2, #arr do
				if arr[i] == arr[j] then
					pos[j] = 't'
					break
				end
			end
		end
	end
	for i = #pos,1,-1 do
		if pos[i] == 'f' then
			table.remove(arr,i)
		end
	end
	return arr
end

action = function(host, port)
		response=http.get(url,port,path..(host.targetname or host.ip),{no_cache = true})
                input=get_links(response.body)
		--[[
		for i=1,#input,1 do
			local code=http.get(input[i],'80','/')
			if code.status==200 then stdnse.print_debug("yes") end
		end]]--
		local file1 = io.open(cms_path,'r')
		local file2 = io.open(cms_fp,'r')
		if not file1 then return false, "C4nt 0p3n file1: " .. cms_path end
		if not file2 then return fales, "C4nt 0p3n file1: " .. cms_fp end
		while true do
			local path=file1:read("*line")
			if(not(path)) then
				break
			end
			--identify_CMS(host,port,path)
			--for i=1,#input,1 do
			for _,url in ipairs(input) do
				identify_CMS(url,port,path)
			end
		end
		file1:close()
		--[[
		local tmp = remove_dup(output)
		for fp in file2:lines() do
			for i=1,#tmp do
				if string.find(fp,tmp[i]) then
					stdnse.print_debug(tmp[i])
					table.insert(result,("[+] bingo~~~~~~.CMS is %s"):format(string.sub(fp,0,string.find(fp," ")-1)))
				end
			end
                end
		file2:close()
		local tmp = remove_dup(result)
		if #tmp > 0 then
			return stdnse.format_output(true,tmp)
		else
			return "0op5! C4nt 1d3nt1fy CMS V3rs10n......"
		end]]
end
