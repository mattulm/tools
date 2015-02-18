#!/usr/bin/python

"""


        This Python Script Uses Core's Impacket Library to get the password policy from a windows machine

                Testing has been limited so Let me know if it works/fails

        Version 0.2
                        
        Usage:./polenum.py [username[:password]@]<address> [protocol list...]

                Available protocols: ['445/SMB', '139/SMB']     
                        
        example: polenum aaa:bbb@127.0.0.1 
        
        Copyright (C) 20/08/2008 - deanx <RID[at]portcullis-secuirty.com>
        
        Version 0.2 
        
        * "This product includes software developed by
        *          CORE Security Technologies (http://www.coresecurity.com/)."

"""

import socket
import string
import sys
import types

from impacket import uuid
from impacket.dcerpc import dcerpc_v4, dcerpc, transport, samr
from impacket import ImpactPacket
from impacket.dcerpc.samr import * 
from impacket.smb import SessionError

def get_obj(name): return eval(name)

version = '0.2'


def usage(): # Self explanitory
    print __doc__
    
def d2b(a):
        bin = []
        while a:
                bin.append(a%2)
                a /= 2
        return bin[::-1]


class ExtendInplace(type):
        def __new__(self, name, bases, dict):
                prevclass = get_obj(name)
                del dict['__module__']
                del dict['__metaclass__']

                # We can't use prevclass.__dict__.update since __dict__
                # isn't a real dict
                for k,v in dict.iteritems():
                        setattr(prevclass, k, v)
                return prevclass

def display_time(filetime_high, filetime_low, minutes_utc=0):
        import __builtins__
        d = filetime_low + (filetime_high)*16**8 # convert to 64bit int
        d *= 1.0e-7 # convert to seconds
        d -= 11644473600 # remove 3389 years?
        try:
                return strftime("%a, %d %b %Y %H:%M:%S +0000ddddd", localtime(d)) # return the standard format day
        except ValueError,e:
                return "0"              

def convert(low, high, no_zero):

        if low == 0 and hex(high) == "-0x80000000":
                return "Not Set"
        if low == 0 and high == 0:
                return "None"
        if no_zero: # make sure we have a +ve vale for the unsined int
                if (low != 0):
                        high = 0 - (high+1)
                else:
                        high = 0 - (high)
                low = 0 - low
        tmp = low + (high)*16**8 # convert to 64bit int
        tmp *= (1e-7) #  convert to seconds
        try:
                minutes = int(strftime("%M", gmtime(tmp)))  # do the conversion to human readable format
        except ValueError, e:
                return "BAD TIME:"
        hours = int(strftime("%H", gmtime(tmp)))
        days = int(strftime("%j", gmtime(tmp)))-1
        time = ""
        if days > 1:
         time = str(days) + " days "
        elif days == 1:
                time = str(days) + " day "
        if hours > 1:
                time += str(hours) + " hours "
        elif hours == 1:
                time = str(days) + " hour "     
        if minutes > 1:
                time += str(minutes) + " minutes"
        elif minutes == 1:
                time = str(days) + " minute "
        return time


class MSRPCPassInfo:
        ITEMS = {'Minimum password':0,
                         'Password history':1,
                         'Maximum password age (d)':2,
                         'Password must meet complexity requirements':3,
                         'Minimum password age (d)':4,
                         'Forced logoff time (s)':5,
                         'Locked account time (s)':6,
                         'Time between failed logon (s)':7,
                         'Number of invalid logon before locked out (s)':8
                         }
                         
        PASSCOMPLEX = { 5:'Domain Password Complex:',
                                        4:'Domain Password No Anon Change:',
                                        3:'Domain Password No Clear Change:',
                                        2:'Domain Password Lockout Admins:',
                                        1:'Domain Password Store Cleartext:',
                                        0:'Domain Refuse Password Change:'
                                        }
                                


        def __init__(self, data = None):
                self._min_pass_length = 0
                self._pass_hist = 0
                self._pass_prop= 0
                self._min_age_low = 0
                self._min_age_high = 0
                self._max_age_low = 0
                self._max_age_high = 0
                self._pwd_can_change_low = 0
                self._pwd_can_change_high = 0
                self._pwd_must_change_low = 0
                self._pwd_must_change_high = 0
                self._max_force_low = 0
                self._max_force_high = 0
                self._role = 0
                self._lockout_window_low = 0
                self._lockout_window_high = 0
                self._lockout_dur_low = 0
                self._lockout_dur_high = 0
                self._lockout_thresh = 0
        

                if data: self.set_header(data, 1)

        def set_header(self,data,level):
                index = 8
                if level == 1: 
                        self._min_pass_length, self._pass_hist, self._pass_prop, self._max_age_low, self._max_age_high, self._min_age_low, self._min_age_high = unpack('<HHLllll',data[index:index+24])
                        bin = d2b(self._pass_prop)
                        if len(bin) != 8:
                                for x in xrange(6 - len(bin)):
                                        bin.insert(0,0)
                        self._pass_prop =  ''.join([str(g) for g in bin])       
                if level == 3:
                        self._max_force_low, self._max_force_high = unpack('<ll',data[index:index+8])
                if level == 7:
                        self._role = unpack('<L',data[index:index+4])
                if level == 12:
                        self._lockout_dur_low, self._lockout_dur_high, self._lockout_window_low, self._lockout_window_high, self._lockout_thresh = unpack('<llllH',data[index:index+18])
                

                
                
        def print_friendly(self):
        
                print "\n\t[+] Minimum password length: " + str(self._min_pass_length or "None")
                print "\t[+] Password history length: " + str(self._pass_hist or "None" )
                print "\t[+] Maximum password age: " + str(convert(self._max_age_low, self._max_age_high, 1))
                print "\t[+] Password Complexity Flags: " + str(self._pass_prop or "None") + "\n"
                i = 0
                for a in self._pass_prop:
                        #print "BIT " +str(i) + a
                        print "\t\t[+] " + self.PASSCOMPLEX[i] + " " + str(a)
                        i+= 1
                print "\n\t[+] Minimum password age: " + str(convert(self._min_age_low, self._min_age_high, 1))
                print "\t[+] Reset Account Lockout Counter: " + str(convert(self._lockout_window_low,self._lockout_window_high, 1)) 
                print "\t[+] Locked Account Duration: " + str(convert(self._lockout_dur_low,self._lockout_dur_high, 1)) 
                print "\t[+] Account Lockout Threshold: " + str(self._lockout_thresh or "None")
                #print "Server Role: " + str(self._role[0])
                print "\t[+] Forced Log off Time: " + str(convert(self._max_force_low, self._max_force_high, 1))
                return
        

class SAMREnumDomainsPass(ImpactPacket.Header):
        OP_NUM = 0x2E

        __SIZE = 22

        def __init__(self, aBuffer = None):
                ImpactPacket.Header.__init__(self, SAMREnumDomainsPass.__SIZE)


                if aBuffer: self.load_header(aBuffer)

        def get_context_handle(self):
                return self.get_bytes().tolist()[:20]
        def set_context_handle(self, handle):
                assert 20 == len(handle)
                self.get_bytes()[:20] = array.array('B', handle)

        def get_resume_handle(self):
                return self.get_long(20, '<')
        def set_resume_handle(self, handle):
                self.set_long(20, handle, '<')

        def get_account_control(self):
                return self.get_long(20, '<')
        def set_account_control(self, mask):
                self.set_long(20, mask, '<')

        def get_pref_max_size(self):
                return self.get_long(28, '<')
        def set_pref_max_size(self, size):
                self.set_long(28, size, '<')

        def get_header_size(self):
                return SAMREnumDomainsPass.__SIZE
        
        def get_level(self):
                return self.get_word(20, '<')
        def set_level(self, level):
                self.set_word(20, level, '<')


class SAMRRespLookupPassPolicy(ImpactPacket.Header):
        __SIZE = 4

        def __init__(self, aBuffer = None):
                ImpactPacket.Header.__init__(self, SAMRRespLookupPassPolicy.__SIZE)
                if aBuffer: self.load_header(aBuffer)

        def get_pass_info(self):
                return MSRPCPassInfo(self.get_bytes()[:-4].tostring())
        def set_pass_info(self, info, level):
                assert isinstance(info, MSRPCPassInfo)
                self.get_bytes()[:-4] = array.array('B', info.rawData())

        def get_return_code(self):
                return self.get_long(-4, '<')
        def set_return_code(self, code):
                self.set_long(-4, code, '<')
        def get_context_handle(self):
                return self.get_bytes().tolist()[:12]


        def get_header_size(self):
                var_size = len(self.get_bytes()) - SAMRRespLookupPassPolicy.__SIZE
                assert var_size > 0
                return SAMRRespLookupPassPolicy.__SIZE + var_size

class DCERPCSamr:
        __metaclass__=ExtendInplace
                
        def enumPass(self,context_handle): # needs to make 3 requests to get all pass policy
                enumpas = SAMREnumDomainsPass()
                enumpas.set_context_handle(context_handle)
                enumpas.set_level(1)
                self._dcerpc.send(enumpas)
                data = self._dcerpc.recv()
                retVal = SAMRRespLookupPassPolicy(data)
                pspol = retVal.get_pass_info()
                enumpas = SAMREnumDomainsPass()
                enumpas.set_context_handle(context_handle)
                enumpas.set_level(3)
                self._dcerpc.send(enumpas)
                data = self._dcerpc.recv()
                pspol.set_header(data,3)
                enumpas = SAMREnumDomainsPass()
                enumpas.set_context_handle(context_handle)
                enumpas.set_level(7)
                self._dcerpc.send(enumpas)
                data = self._dcerpc.recv()
                pspol.set_header(data,7)

                enumpas = SAMREnumDomainsPass()
                enumpas.set_context_handle(context_handle)
                enumpas.set_level(12)
                self._dcerpc.send(enumpas)
                data = self._dcerpc.recv()
                pspol.set_header(data,12)
                #return retVal
                return pspol 
        
        def opendomain(self,context_handle,domain_sid):
                opendom = SAMROpenDomainHeader()
                opendom.set_access_mask(0x305)
                opendom.set_context_handle(context_handle)
                opendom.set_domain_sid(domain_sid)
                self._dcerpc.send(opendom)
                data = self._dcerpc.recv()
                retVal = SAMRRespOpenDomainHeader(data)
                return retVal



class ListUsersException(Exception):
        pass

class SAMRDump:
        KNOWN_PROTOCOLS = {
                '139/SMB': (r'ncacn_np:%s[\pipe\samr]', 139),
                '445/SMB': (r'ncacn_np:%s[\pipe\samr]', 445),
                }


        def __init__(self, protocols = None,
                                 username = '', password = ''):
                if not protocols:
                        protocols = SAMRDump.KNOWN_PROTOCOLS.keys()

                self.__username = username
                self.__password = password
                self.__protocols = protocols


        def dump(self, addr):
                """Dumps the list of users and shares registered present at
                addr. Addr is a valid host name or IP address.
                """

                encoding = sys.getdefaultencoding()
                print
                if (self.__username and self.__password):
                        print '[+] Attaching to ' + addr + ' using ' + self.__username + ":" + self.__password
                elif (self.__username):
                        print '[+] Attaching to ' + addr + ' using ' + self.__username
                else:
                        print '[+] Attaching to ' + addr + ' using a NULL share'

                # Try all requested protocols until one works.
                entries = []
                for protocol in self.__protocols:
                        try:
                                protodef = SAMRDump.KNOWN_PROTOCOLS[protocol]
                                port = protodef[1]
                        except KeyError,e:
                                print "\n\t[!] Invalid Protocol \'%s\'\n" % protocol
                                usage()
                                sys.exit(1)
                        print "\n\t[+] Trying protocol %s..." % protocol
                        rpctransport = transport.SMBTransport(addr, port, r'\samr', self.__username, self.__password)

                        try:
                                entries = self.__fetchList(rpctransport)
                        except Exception, e:
                                print '\n\t[!] Protocol failed: %s' % e
                                #raise
                        else:
                                # Got a response. No need for further iterations.
                                break

        def __fetchList(self, rpctransport):
                dce = dcerpc.DCERPC_v5(rpctransport)
                #dce.set_auth_level(2)
                encoding = sys.getdefaultencoding()
                entries = []
                try:
                        dce.connect()
                        #sys.exit()
                        dce.bind(samr.MSRPC_UUID_SAMR)
                        #sys.exit()
                        rpcsamr = samr.DCERPCSamr(dce)
                        resp = rpcsamr.connect()
                        if resp.get_return_code() != 0:
                                raise ListUsersException, 'Connect error'

                        _context_handle = resp.get_context_handle()
                        resp = rpcsamr.enumdomains(_context_handle)
                        if resp.get_return_code() != 0:
                                raise ListUsersException, 'EnumDomain error'

                        domains = resp.get_domains().elements()

                        print '\n[+] Found domain(s):\n'
                        for i in range(0, resp.get_entries_num()):
                                print "\t[+] %s" % domains[i].get_name()

                        print "\n[+] Password Info for Domain: %s" % domains[0].get_name()
                        resp = rpcsamr.lookupdomain(_context_handle, domains[0])
                        if resp.get_return_code() != 0:
                                raise ListUsersException, 'LookupDomain error'
                        resp = rpcsamr.opendomain(_context_handle, resp.get_domain_sid())
                        if resp.get_return_code() != 0:
                                raise ListUsersException, 'OpenDomain error'
                        domain_context_handle = resp.get_context_handle()
                        resp = rpcsamr.enumPass(domain_context_handle)
                        resp.print_friendly()
                except ListUsersException, e:
                        print "Error Getting Password Policy: %s" % e
                        dce.disconnect()
                return entries

__doc__ = '\n  polenum ' + version + ' - (C) 2008 deanx\n\n' 
__doc__ += '\t\t\t RID[at]Portcullis-Security.com\n\n' 
__doc__ += '  Usage:' + sys.argv[0] + ' [username[:password]@]<address> [protocol list...]'
__doc__ += '\n\n\t\tAvailable protocols: ' + str(SAMRDump.KNOWN_PROTOCOLS.keys()) + '\n'

# Process command-line arguments.
if __name__ == '__main__':
        if len(sys.argv) <= 1:
                usage()
                sys.exit(1)

        import re

        username, password, address = re.compile('(?:([^@:]*)(?::([^@]*))?@)?(.*)').match(sys.argv[1]).groups('')

        if len(sys.argv) > 2:
                dumper = SAMRDump(sys.argv[2:], username, password)
        else:
                dumper = SAMRDump(username = username, password = password)
        try:
                dumper.dump(address)
                print
        except KeyboardInterrupt:
                print
                print "\n\t[!] Ctrl-C Caught, ByeBye\n"
                sys.exit(2)
