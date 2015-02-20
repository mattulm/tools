local dns = require "dns"
local http = require "http"
local ipOps = require "ipOps"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local url = require "url"

description = [[
HTTP directory scanner

Single threaded directory bruter, specify dictionary through --script-args=dict=/pentest/dictionary/web-paths.txt
]]

---
--@output
-- Nmap scan report for localhost.localdomain (127.0.0.1)
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-path: 
-- |_  /icy

author = "Aaron Lewis"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.http

action = function(host, port)

    function file_exists(file)
        local f = io.open(file, "rb")
        if f then f:close() end
        return f ~= nil
    end

    function lines_from(file)
        if not file_exists(file) then return {} end
        lines = {}
        for line in io.lines(file) do 
            lines[#lines + 1] = line
        end
        return lines
    end

    function get404()
        local resp = http.get (host, port, '/idontexist_mapper')
        return resp.status, resp.body
    end

    local dictionary         = stdnse.get_script_args('dict')
    local code_404, body_404 = get404 ()
    local result = {}

    for i, path in ipairs (lines_from (dictionary)) do
        local resp   = http.get(host, port, path)
        local status = resp.status
        local body   = resp.body

        if status and status == 200 then
            -- no 404 page defined
            if code_404 == 404 then
                table.insert (result, path)
            else
                -- 404 page defined
                if body and body ~= body_404 then
                    table.insert (result, path)
                end
            end
        end
    end

    return stdnse.format_output (true, result)
end
