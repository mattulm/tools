#!/usr/bin/perl
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
# Get it at http://www.remote-exploit.org
#
# (c) 2003 Max Moser, mmo@remote-exploit.org
#
#
use strict;
use POSIX;
use IO::Socket;
use Net::Pcap;
#-- Non-buffered output --#
$|=1;

# optionshandling
use Getopt::Long;

#-- GTK standart initialisation --#
use Gtk;
set_locale Gtk;
init Gtk;



#--------- global constants ----------#
# define all global constants in here #
#-------------------------------------#

# Boolean values definition
	use constant FALSE => 0;
	use constant TRUE => 1;

# Card types 
	use constant TYPE_UNKNOWN => 0;
	use constant TYPE_CISCO1 => 1;
	use constant TYPE_CISCO2 => 2;
	use constant TYPE_LUCENT => 3;
	use constant TYPE_HOSTAP => 4;
	use constant TYPE_WLANNG => 5;

use constant VERSION => '1.9';
#----------- global variable declaration --------#
# this file contains all the used global variable# 
#------------------------------------------------#
my $gl_debugon = 0; 
my $gl_savedir = $ENV{HOME};
my $gl_sniff_dev;
my $gl_screenwidth;
my $gl_screenheight;
my $gl_is_sniffing;
my $gl_pcap_descrip;
my $gl_cap_save_descrip;

my $gl_conf;
my %gl_conf;

my $gl_do_soundevents = 1;

my $channel_icon;
my $channel_mask;

my $gl_sound_Window;

my $gl_savefilename;

my $teststyle;

my $mainwindow;

#Holding all the channelroottrees
my @gl_channeltrees;
my $gl_defaultstyle;
my $gl_redstyle;

my $sniffertextbox;

#used for the detail window
my $gl_detail_ap_name;
my $gl_detail_ap_windows;
my $gl_detail_ap_clist;

# for the detail window
my @gl_logo_detail;

#Hold all the accesspoints discovered
my @gl_accesspoints;
my @gl_objects;
my %gl_clist_objects;
my $gl_clist_objects;

# Gps informations
my $gl_lat;
my $gl_long;
my $gl_speed;
my $gl_sockettogpsd;
my $gl_gpschecker;

#For the traffic window
my $gl_Traffic_Window;
my $gl_Traffic_clist;
my $gl_Traffic_style=0;

#For the logwindow
my @gl_LOGWINDOW_TEXT_BUFFER_ARRAY;
my $gl_logtextbox;
my $gl_LOGWINDOW_WINDOW;

#For the scannerwindow
my $gl_tree;
my $gl_clist;
my $gl_statusbar;
my $gl_statusbar_context;
my $gl_sniffnumtotalpackets;
my $gl_net_count = 0;
my $gl_ap_count = 0;
my $gl_client_count = 0;
my $gl_status;
my $gl_pixledoff;
my $gl_pixledon;

#Packet decoding /processing
my $gl_child;
my %hdr;
my $pkt;
my $gl_channelswitch;
my $gl_sniffchannel = 1;
my $gl_packet_pos = 0;
my $gl_tmphashref;

# Accousic beacon indicator
my $gl_accoustic_beacon = 0;

#decode_beacons
my @gl_beacon_check1;

# Variables that are holding the pixmaps
my @gl_greenled;
my @gl_blackled;
my @gl_logo;
my @gl_logo_start;
my @gl_logo_stop;
my @gl_logo_save;
my @gl_logo_load;
my @gl_logo_reset;
my @gl_logo_close;
my @gl_logo_channel;
my @gl_logo_accesspoint;
my @gl_logo_accesspoint_wep;
my @gl_logo_adhoc;
my @gl_logo_adhoc_wep;
my @gl_logo_network_broadcasting;
my @gl_logo_network_nonbroadcasting;
my @gl_logo_encrypted;
my @gl_accesspoint_icon;
my @gl_wireless_card_icon;
my $gl_pixwepon;
my @gl_nowep;
my $tmppixmap1;
my $tmpmask1;

# Pcap and sniffing
my $gl_idlefunction;

# Sniffing pipes
pipe (PIPE_READ,PIPE_WRITE);	#-- Pipe for sending packets from child to parent --#
PIPE_WRITE->autoflush(1);	   #-- sets autoflush to on --#
PIPE_WRITE->blocking(0);		#-- sets to non-blocking --#
PIPE_READ->autoflush(1);	    #-- sets autoflush to on --#
PIPE_READ->blocking(0);		 #-- sets to non-blocking --#

pipe (PIPE_READ2,PIPE_WRITE2); #-- Pipe for sending the sniffprocess a termination request
PIPE_WRITE2->autoflush(1);	   #-- sets autoflush to on --#
PIPE_WRITE2->blocking(0);		#-- sets to non-blocking --#
PIPE_READ2->autoflush(1);	    #-- sets autoflush to on --#
PIPE_READ2->blocking(0);		 #-- sets to non-blocking --#
#----------- global subfunction prototyping -#
# Prototype all the used subfunction in here #   
#--------------------------------------------#
sub show_dialog;
sub getwlan_dev;
sub detect_gpsd;
sub mainwindow;
sub load_leds;
sub build_about;

# For the cardhandling
sub get_channels;

sub readin_conf;
sub check_conf;
sub write_conf;


sub build_popupmenu;
sub add_comment;
sub del_comment;
sub build_textentry_dialog;

sub hex_to_IP;

sub decode_probe_response;
sub decode_dhcp;

sub toggle_accoustic_events;

sub build_sound_window;

sub load_file;
sub save_file;

sub export_as_csv;
sub export_as_mappoint;

#For the treeobject
sub tree_object_selected;

sub reset;

sub toggle_accoustic_beacon;

sub auto_save;

#for the clist stuff
sub add_accesspoint;
sub rebuild_clist;

sub get_manuf;

# Menu subfunctions
sub toggle_toolbar;
sub start_scan;
sub stop_scan;

#detailwindow
sub build_detail_window;
sub get_details;

# logwindow 
sub build_logwindow;
sub clean_logwin;
sub writetologwin;

#trafficwindow
sub build_traffic_window;

# Cardstuff
sub set_monitor_mode;
sub remove_monitormode;
sub check_monitor_mode;
sub check_promisc;
sub set_promisc;
sub remove_promisc;
sub check_up;
sub set_up;
sub set_monitormode;
sub start_scan;
sub switchchannel;

#decoding
sub read80211b_func;
sub decode_beacons;
sub decode_bytes;

# GPSD stuff
sub latitude;
sub longitude;
sub connect_gpsd;
sub close_gpsd;
sub get_gpsdata;
sub when_gps_pending;
# This file contains the 
# 802_11B constants etc.
# due the fact that constants in perl are not
# inline i use standard variables insted.
# Most of the following definitions are comming from
# the tcpdump sourcecode

# 802.11b decoding constants declaring

my $IEEE802_11_FC_LEN = 2; #Framecontrol length


#my $MAX_PACKET_LEN = 65532;
my $MAX_PACKET_LEN = 400;
# Type of 802.11b frames
my $TYP_MGTFRAME = '0000';
my $TYP_CTRLFRAME = '0010';
my $TYP_DATAFRAME = '0001';
my $TYP_RESERVED = '0011';

# All management frame subtypes	
my $FC_Association_Req = pack ('b8' , $TYP_MGTFRAME . '0000');
my $FC_Association_Resp = pack ('b8' ,$TYP_MGTFRAME . '1000');
my $FC_Re_Association_Req = pack ('b8' ,$TYP_MGTFRAME . '0100');
my $FC_Re_Association_Resp = pack ('b8' ,$TYP_MGTFRAME . '1100');
my $FC_Probe_Req = pack ('b8' ,$TYP_MGTFRAME . '0010');
my $FC_Probe_Resp = pack ('b8' ,$TYP_MGTFRAME . '1010');
my $FC_Beacon = pack ('b8' ,$TYP_MGTFRAME . '0001');
my $FC_ATIM = pack ('b8' ,$TYP_MGTFRAME . '1001');
my $FC_Disassociation = pack ('b8' ,$TYP_MGTFRAME . '0101');
my $FC_Authentication = pack ('b8' ,$TYP_MGTFRAME . '1101');
my $FC_Deauthentication = pack ('b8' ,$TYP_MGTFRAME . '0011');

# All control frame subtypes	
my $FC_Powersave_poll = pack ('b8' , $TYP_MGTFRAME . '0101');
my $FC_Request_to_send = pack ('b8' ,$TYP_MGTFRAME . '1101');
my $FC_Clear_to_send = pack ('b8' ,$TYP_MGTFRAME . '0011');
my $FC_Acknowledgment = pack ('b8' ,$TYP_MGTFRAME . '1011');
my $FC_Contention_Free = pack ('b8' ,$TYP_MGTFRAME . '0111');
my $FC_Contention_Free_End = pack ('b8' ,$TYP_MGTFRAME . '1111');

# All data frame subtypes	
my $FC_Data = pack ('b8' , $TYP_DATAFRAME. '0000');
my $FC_Data_CF_ACK = pack ('b8' ,$TYP_DATAFRAME. '1000');
my $FC_Data_CF_POLL = pack ('b8' ,$TYP_DATAFRAME. '0100');
my $FC_Data_CF_ACK_POLL = pack ('b8' ,$TYP_DATAFRAME. '1100');
my $FC_NULL = pack ('b8' ,$TYP_DATAFRAME. '0010');
my $FC_CF_ACK = pack ('b8' ,$TYP_DATAFRAME. '1010');
my $FC_CF_POLL = pack ('b8' ,$TYP_DATAFRAME. '0110');
my $FC_CF_ACK_CF_POLL = pack ('b8' ,$TYP_DATAFRAME. '1110');

# Frame position constant for better reading control flags code
my $FC_FLAG_FROM_DS = 0; 
my $FC_FLAG_TO_DS = 1; 
my $FC_FLAG_FRAGMENTS = 2;
my $FC_FLAG_RETRANS = 3;
my $FC_FLAG_PWR_MGT = 4;
my $FC_FLAG_MORE_DATA = 5;
my $FC_FLAG_WEP = 6;
my $FC_FLAG_STRIC_ORDER = 7;

# Beacon frame capabilities flags
my $CP_FLAG_IS_ASCCESSPOINT = 0;
my $CP_FLAG_IS_ADHOC = 1;
my $CP_FLAG_CF_POLLABLE = 2;
my $CP_FLAG_CF_POLLREQ = 3;
my $CP_FLAG_WEP_REQUIRED = 4;
my $CP_FLAG_SHORT_PREAMBLE = 5;
my $CP_FLAG_PBCC = 6;
my $CP_FLAG_CHANNEL_AGILITY = 7;

# Elemet IDS (TAG_TYPES)
my $TAG_TYPE_SSID = 0;
my $TAG_TYPE_RATES = 1;
my $TAG_TYPE_DS_PARAM_CHANNEL = 3;
my $TAG_TYPE_TIM = 5;



#- For dataframes decoding -#
my $LLC_ORG_ECAPS_ETHERNET = '000000';
my $LLC_TYPE_IP = '0800';
my $LLC_TYPE_ARP = '0806';
my $IP_PROTO_UDP = '0x11';
my $BOOTPS = '0043';
my $BOOTPC = '0044';
my $IP_HDR_LEN = 20;			
my $UDP_HDR_LEN = 8;
my $DHCP_LEN_MIN = 236; # length of minimal DHCP packet (with 0-byte options field).  This is UDP payload.
my $Magic_cookie = '63825363';
my $portBOOTPS = 67;
my $portBOOTPC = 68;

my @bootpOptions = (
	"pad",							# T0
	"subnetMask",					# T1  - IP Address List
	"timeOffset",					# T2  - signed32bit
	"routerList",					# T3  - IP Address List
	"timeServerList",				# T4  - IP Address List
	"ienServerList",				# T5  - IP Address List
	"dnsServerList",				# T6  - IP Address List
	"logServerList",				# T7  - IP Address List
	"cookieServerList",				# T8  - IP Address List
	"lprServerList",				# T9  - IP Address List
	"impressServerList",			# T10 - IP Address List
	"resourceLocationServerList",	# T11 - IP Address List
	"hostName",						# T12 - Text
	"bootFileSize",					# T13 - unsigned16bit
	"meritDumpFile",				# T14 - Text
	"domainName",					# T15 - Text
	"swapServer",					# T16 - IP Address List
	"rootPath",						# T17 - Text
	"extensionsPath",				# T18 - Text
	"ipForwarding",					# T19 - boolean
	"nonLocalSourceRouting",		# T20 - boolean
	"policyFilter",					# T21 - IP Address/Mask Pairs list
	"maxDgramReassemblySize",		# T22 - unsigned16bit
	"defaultTTL",					# T23 - unsigned8bit
	"pathMTUagingTimeout",			# T24 - unsigned32bit
	"pathMTUplateuaTable",			# T25 - unsigned16bit List
	"interfaceMTU",					# T26 - unsigned16bit
	"allSubnetsLocal",				# T27 - boolean
	"broadcastAddr",				# T28 - IP Address List
	"maskDiscovery",				# T29 - boolean
	"maskSupplier",					# T30 - boolean
	"routerDiscovery",				# T31 - boolean
	"routerSolicitationAddr",		# T32 - IP Address List
	"staticRouteList",				# T33 - IP Dest/Router List
	"trailerEncap",					# T34 - boolean
	"arpCacheTimeout",				# T35 - unsigned32bit
	"enetEncap",					# T36 - boolean
	"tcpTTL",						# T37 - unsigned8bit
	"tcpKeepaliveInterval",			# T38 - unsigned32bit
	"tcpKeepaliveGarbage",			# T39 - boolean
	"nisDomain",					# T40 - Text
	"nisServerList",				# T41 - IP Address List
	"ntpServerList",				# T42 - IP Address List
	"vendorSpecific",				# T43 - 8 bit Hex string
	"NETBIOSnbnsServerList",		# T44 - IP Address List
	"NETBIOSnbddServerList",		# T45 - IP Address List
	"NETBIOSnodeType",				# T46 - NetBIOS node type
	"NETBIOSscope",					# T47 - 8 bit Hex string
	"xFontServerList",				# T48 - IP Address List
	"xdmList",						# T49 - IP Address List
	"DHCPrequestedIPaddress",		# T50 - IP Address List
	"DHCPipAddressLeaseTime",		# T51 - unsigned32bit 
	"DHCPoptionOverload",			# T52 - DHCP option overload
	"DHCPmessageType",				# T53 - DHCP msg type
	"DHCPserverIdentifier",			# T54 - IP Address List
	"DHCPparamRequestList",			# T55 - unsigned8bit List
	"DHCPmessage",					# T56 - Text
	"DHCPmaxMessageSize",			# T57 - unsigned16bit
	"DHCPrenewalTimeValue",			# T58 - unsigned32bit
	"DHCPrebindingTimeValue",		# T59 - unsigned32bit
	"DHCPvendorclassIdentifier",	# T60 - unsigned8bit List
	"DHCPclientIdentifier",			# T61 - 8 bit Hex string
	"NetwareIPdomainName",			# T62 - Text
	"NetwareIPinformation",			# T63 - a complex structure we don't decode yet
	"nis+Domain",					# T64 - Text
	"nis+ServerList",				# T65 - IP Address List
	"tftpServerName",				# T66 - Text
	"bootFileName",					# T67 - Text
	"mobileIPHomeAgentList",		# T68 - IP Address List
	"smtpServerList",				# T69 - IP Address List
	"pop3ServerList",				# T70 - IP Address List
	"nntpServerList",				# T71 - IP Address List
	"wwwServerList",				# T72 - IP Address List
	"fingerServerList",				# T73 - IP Address List
	"ircServerList",				# T74 - IP Address List
	"streettalkServerList",			# T75 - IP Address List
	"streettalkDirAssistList",		# T76 - IP Address List
	"DHCPuserClass",				# T77 - Text (old interpretation, not RFC3004)
	"SLPdirectoryAgentList",		# T78 - byte value followed by IP Addr List
	"SLPserviceScope",				# T79 - byte value followed by optional UTF-8 string
	80,
	"clientFQDN_proposed",			# T81 - based on IETF-DRAFT-DHC-FQDN-OPTION-02 7/2001
	"relayAgentInformation",		# T82 - a structure we don't decode yet
	83,84,
	"NDSserverList",				# T85 - IP Address List
	"NDStreeName",					# T86 - UTF-8 string
	"NDSContext",					# T87 - UTF-8 string
	88,89,
	"DHCPauthentication",			# T90 - a structure we don't decode yet
	91,92,
	"clientSystemArchitecture",		# T93 - a structure we don't decode, defined in Intel PXE spec (not an RFC)
	"clientNetworkDeviceInterface",	# T94 - a structure we don't decode, defined in Intel PXE spec (not an RFC)
	95,96,
	"UUID/GUIDclientIdentifer",		# T97 - a structure we don't decode, see Intel PXE spec (not an RFC)
	"userAuthenticationProtocol",	# T98 - URL list
	99,
	100,101,102,103,104,105,106,107,108,109,
	110,111,
	"netinfoAddress",				# T112 - in IANA DHCP opts list, but not documented anywhere, so we don't decode
	"netinfoTag",					# T113 - in IANA DHCP opts list, but not documented anywhere, so we don't decode
	114,115,
	"autoconfiguration",			# T116 - byte code
	"nameServiceSearch",			# T117 - list of 16-bit option numbers
	"subnetSelection",				# T118 - IP Address List
	119,
	120,121,122,123,124,125,126,127,128,129,
	130,131,132,133,134,135,136,137,138,139,
	140,141,142,143,144,145,146,147,148,149,
	150,151,152,153,154,155,156,157,158,159,
	160,161,162,163,164,165,166,167,168,169,
	170,171,172,173,174,175,176,177,178,179,
	180,181,182,183,184,185,186,187,188,189,
	190,191,192,193,194,195,196,197,198,199,
	200,201,202,203,204,205,206,207,208,209,
	210,211,212,213,214,215,216,217,218,219,
	220,221,222,223,224,225,226,227,228,229,
	230,231,232,233,234,235,236,237,238,239,
	240,241,242,243,244,245,246,247,248,249,
	250,251,252,253,254,
	"end"							# T255
);








##------ Wellenreiter main application ------#
#  This the the main area of wellenreiter   # 
#-------------------------------------------#
# Detect the wireless device to use
GetOptions ( "savedir:s" => \$gl_savedir,
			 "debug:i" => \$gl_debugon);

##-- Check that the user is root / linux only--##
if (($> != 0 || $< != 0)) 
{
        show_dialog "-=[ Wellenreiter ]=-", " You should run this program as root, cannot continue ", TRUE;
        main Gtk;
        exit(FALSE);
}
getwlan_dev;
main Gtk;
exit;







#----------- subfunction getwlan_dev --------#
# autodetection of the wireless equipment    # 
#--------------------------------------------#
sub getwlan_dev 
{
	# Variables 
	my @net_dev;
	my $net_dev;
	my @wlan_dev;
	my $wlan_dev;
	my $procdirentry;

	# open /proc/net/dev to get all the network devices 
	open(PROCNETDEV, '</proc/net/dev') || die "Cannot open /proc/net/dev: $!\n";

	while(<PROCNETDEV>) 
	{
		if ($_ =~ /^\s+(\w+):/)	
		{
			if ($1 ne "lo")
			{
				push (@net_dev, $1);
			}
		}
	}
	close(PROCNETDEV);

	if (@net_dev < 1)
	{
		show_dialog "Wellenreiter","Did not find any network interfaces",TRUE;
	}

	# Getting the wireless interfaces from /proc/net/wireless
	# open /proc/net/wireless to get all the network devices 
	open(PROCWLANDEV, '</proc/net/wireless') || die "Cannot open /proc/net/wireless: $!\n";

	while(<PROCWLANDEV>) 
	{
		if ($_ =~ /^\s+(\w+):/)	
		{
				my $int_name = $1;

				# Cisco and lucent cards are named "eth1 / eth0 etc"
				if ($int_name =~ /^eth\w+/)
				{
					# Check if it is a CISCO CARD
					if (open(CISCOCONFIG, "</proc/driver/aironet/$int_name/Status"))
					{
						if (`cat /proc/net/wireless | grep wifi`)		
						{
							push (@wlan_dev, {dev_name =>$int_name,dev_type =>TYPE_CISCO2});
						}
						else
						{
							push (@wlan_dev, {dev_name =>$int_name,dev_type =>TYPE_CISCO1});
						}
						close(CISCOCONFIG);
					}
					else
					{
						# Must be a lucent card
						push (@wlan_dev, {dev_name =>$int_name,dev_type =>TYPE_LUCENT});
					}
				} # End of "When name starts with eth..."
		                elsif ($int_name =~ /^wlan\w+/) #When it is a wlan_ng / hostap
				{
					opendir(PROCNET, "/proc/net/p80211") || die "Cannot open any device in /proc/net/p80211/: $!\n";
					while($procdirentry=readdir(PROCNET))
					{
						if ( $procdirentry =~ /$int_name/)
						{
							# $int_name is a wlan-ng card
							push (@wlan_dev, {dev_name =>$int_name,dev_type =>TYPE_WLANNG});
						}

					}
					closedir(PROCNET);
				} # End of when its a wlan card


		}
	}
	close(PROCWLANDEV);

	if (@wlan_dev < 1)
	{
		show_dialog "Wellenreiter","Did not find any wireless interfaces",TRUE;
		return (FALSE);
	}
	elsif (@wlan_dev == 1)
	{
		#start the normal startup
		$gl_sniff_dev = $wlan_dev[0];
		readin_conf;
		mainwindow;
	}
	else
	{
		# Let the user choose which interface to use
		my $choosecard = new Gtk::Window("toplevel");
		$choosecard->signal_connect("delete_event",sub{Gtk->exit(0);});
		$choosecard->title("Wellenreiter");	
		$choosecard->border_width(0);
		$choosecard->set_default_size(100,100);
		# Make 3 part window
		my $table = new Gtk::Table(3,1,FALSE);
		$choosecard->add($table);
		my $topframe = new Gtk::Frame ();
		my $midframe = new Gtk::Frame ();
		my $botframe = new Gtk::Frame ();
		
		$table->attach_defaults($topframe, 0,1,0,1);
		$table->attach_defaults($midframe, 0,1,1,2);
		$table->attach_defaults($botframe, 0,1,2,3);
		$table->show();		
		my $label = new Gtk::Label (" Found multiple cards, please choose \none and click the \"OK\" button");
	        $topframe->add($label);
		$label->show();
		$topframe->show();
	
		#midframe got the interfaces
		my $num_devs = @wlan_dev;

		# Add a combobox to choose from
		my $combo = new Gtk::Combo();
		my @combobox_vals;		
		foreach my$ref (@wlan_dev)
		{
			if ($ref->{dev_type} == TYPE_CISCO1 || $ref->{dev_type} == TYPE_CISCO2 )
			{
				push (@combobox_vals,$ref->{dev_name} . " (Cisco wireless card)")
			}
			elsif ($ref->{dev_type} == TYPE_LUCENT)
			{
				push (@combobox_vals,$ref->{dev_name} . " (Lucent/Orinoco wireless card)")
			}
			elsif ($ref->{dev_type} == TYPE_WLANNG)
			{
				push (@combobox_vals,$ref->{dev_name} . " (PRISM/WLAN-NG wireless card)")
			}
			elsif ($ref->{dev_type} == TYPE_HOSTAP)
			{
				push (@combobox_vals,$ref->{dev_name} . " (PRISM/HOSTAP wireless card)")
			}
		}
		
		$combo->set_popdown_strings(@combobox_vals);
		$combo->set_value_in_list(TRUE, FALSE);
		$midframe->add($combo);
		$combo->show();
		$midframe->show();
		

		#botframe got the buttons
		# Two add two buttons need another table init
		my $buttontable = new Gtk::Table(1,2);
		$botframe->add($buttontable);
		my $buttonOK = new Gtk::Button('OK');
		my $buttonEXIT = new Gtk::Button('Exit');
		$buttonEXIT->signal_connect("clicked",sub{Gtk->exit(0);exit;});
		$buttonOK->signal_connect("clicked",sub{
			foreach my $ref2 (@wlan_dev)
			{
				my $text = $combo->entry->get_text();
				if ( $text =~ /^(\w+)\s+/ )
				{
					if ($ref2->{dev_name} eq $1)
					{
						$gl_sniff_dev = $ref2;
					}
				}
			}
			readin_conf;
			mainwindow;
			$choosecard->hide();
			});
		$buttontable->attach_defaults($buttonOK,0,1,0,1);
		$buttontable->attach_defaults($buttonEXIT,1,2,0,1);
	    $buttonOK->show();
	    $buttonEXIT->show();
		$buttontable->show();
	    $botframe->show();
		$choosecard->show();	
	}
	return(TRUE);
}
#----------- end of getwlan_dev --------#
#----------- subfunction detect_gpsd ------------#
# this function checks if port 2947 is listening # 
# 2947 is the port, where gpsd runs at normaly   #
#------------------------------------------------#
sub detect_gpsd
{	
	my $tmp_gps;
	open(NETSTAT, '</proc/net/tcp') || die "Cannot open /proc/net/tcp: $!\n";

	while(<NETSTAT>) 
	{
		if ( /:0B83\s+/ ) #0B83 is in decimal 2947
		{
			$tmp_gps = TRUE;
		}
		else
		{
			if ($tmp_gps != TRUE)
			{
				$tmp_gps = FALSE;
			}
		}
	}
	close(NETSTAT);	
	return($tmp_gps);
}


##-- Functions for getting the gps all the time --#

sub latitude {
	my ($deg, $min) = unpack "a2a*", $_[0];
	my $lat = $deg + $min / 60;
	$lat = - $lat if $_[1] =~ /[Ss]/;
	return $lat;
}

sub longitude {
	my ($deg, $min) = unpack "a3a*", $_[0];
	my $long = $deg + $min / 60;
	$long = - $long if $_[1] =~ /[Ww]/;
	return $long;
}

sub connect_gpsd
{
	# first remove any existing socket to the gpsd
	if ($gl_sockettogpsd)
	{
		 close($gl_sockettogpsd);
	};
	$gl_sockettogpsd = IO::Socket::INET->new(PeerAddr => 'localhost',
									   PeerPort => 2947,
									   Proto    => "tcp",
									   Type     =>  SOCK_STREAM)
	or die "Could not made the connection to the gpsd: $@\n";
	print $gl_sockettogpsd "ret\n";
	# Setting the socket to non-blocking. 
	$gl_sockettogpsd->blocking(0);
}

sub close_gpsd
{
	close($gl_sockettogpsd);
    Gtk::Gdk->input_remove($gl_gpschecker);
}

sub get_gpsdata
{
	connect_gpsd;
	#-- Add a handler that checks the socket for pending packets --#
	$gl_gpschecker = Gtk::Gdk->input_add($gl_sockettogpsd->fileno(),'read',\&when_gps_pending,undef);
}

sub when_gps_pending
{
	my $answer = <$gl_sockettogpsd>;
	chomp($answer);
	my @field = split /[,*]/, $answer;
	# latitude/longitude
	if ($field[0] eq '$GPGLL') 
	{
		$gl_lat = latitude(@field[1..2]);
		$gl_long = longitude(@field[3..4]);
	}
	elsif ($field[0] eq '$GPRMC') 
	{
		$gl_lat = latitude(@field[3..4]);
		$gl_long = longitude(@field[5..6]);
		$gl_speed = $field[7];
	}
	if ($gl_debugon == 1)
	{
		print "Longitude: $gl_long\n";
		print "Latitude: $gl_lat\n";
		print "Ground speed: $gl_speed\n";
	}
}#----------- subfunction show_dialog --------#
# this function create a generic info dialog # 
#--------------------------------------------#
sub show_dialog {
	my ($title,$message,$endprog) = @_;
	my $dialog = new Gtk::Window("toplevel");
	if ($mainwindow)
	{
		$dialog->set_transient_for ($mainwindow);
	}
	if ($endprog == TRUE) {
		$dialog->signal_connect("delete_event",sub{Gtk->exit(0);});
	}
	else {
		$dialog->signal_connect("delete_event",sub{$dialog->destroy();});
	}
	$dialog->title($title);
	$dialog->border_width(0);
	$dialog->set_default_size(100,80);
	my $table = new Gtk::Table(2,1,FALSE);
	$dialog->add ($table);
	my $topframe = new Gtk::Frame ();
    $table->attach_defaults($topframe, 0,1,0,1);
	$topframe->show();
	my $label = new Gtk::Label ($message);
    $topframe->add($label);
    $topframe->border_width(1);
	$label->show();
	my $botframe = new Gtk::Frame ();
	my $button;
	if ($endprog == TRUE) {
			$button = new Gtk::Button('Exit');
			$button->signal_connect("clicked",sub{Gtk->exit(0);});
	}
	else {
    		$button = new Gtk::Button('Close');
			$button->signal_connect("clicked",sub{$dialog->destroy();});
	}
    $button->signal_connect("clicked", sub{$dialog->destroy()});
	$button->border_width(3);
    $table->attach_defaults($botframe, 0,1,1,2);
	$botframe->add($button);
    $botframe->border_width(1);
	$botframe->show();
    $button->show();
	$table->show();
	$dialog->show();
}
#----------- end of show_dialog --------#
#---- new mainwindow of Wellenreiter ----#
#              scannerwindow             #   
#----------------------------------------#

sub mainwindow
{
	# Need to declare this on top of this windowcode
	my $toolbarframe;

	
	# load in all the pcitures
	load_leds;
    $gl_screenwidth = Gtk::Gdk->screen_width();
    $gl_screenheight = Gtk::Gdk->screen_height();

	#-- Build the mainwindow --#
		$mainwindow = new Gtk::Window("toplevel"); 
	#-- Set size to 80% of screen --#
		$mainwindow->set_usize((($gl_screenwidth * 90)/ 100),(($gl_screenheight * 80) / 100));	
	#-- Position the window in the center of the screen --#
		$mainwindow->set_position('center');	
	#-- Set the window properties --#
		$mainwindow->set_title( "-=[ Wellenreiter wireless scanner ]=-");
		$mainwindow->border_width(2);

	#-- Close the sniffer first if still sniffing, then exit --#
		$mainwindow->signal_connect("delete_event",sub{
								if ($gl_is_sniffing==TRUE)
								{
									stop_scan
								}
								exit;});

	#-- Generate the window but do not show it, needed for pixmap etc. --#												
		$mainwindow->realize(); 
	
	#-- Create the scrollwindow (used for small resolutions) --#
		my $mainscrollwin = new Gtk::ScrolledWindow("","");
		$mainscrollwin->set_policy("automatic", "automatic");
		$mainscrollwin->border_width(2);
		$mainwindow->add($mainscrollwin); 
		$mainscrollwin->show();

	#-- For faking a blinking led we need a special table --#
	#-- Initialize all the vars etc for the led led --#
		#my ($pixmap1,$pixmap2,$mask1,$mask2, $pixmapwid); #-- Vars declare --#
		#my $ledtable = new Gtk::Table(1,1,FALSE); #-- Create table --#
		my $style = $mainwindow->get_style()->bg('normal');	#-- Get the background --#
		#-- Create the pixmaps of the on and off state of the beacon led --#
		#	($pixmap1, $mask1) = Gtk::Gdk::Pixmap->create_from_xpm_d ($mainwindow->window,$style,@gl_greenled);
		#	   $gl_pixledon = new Gtk::Pixmap ($pixmap1, $mask1);
		#	($pixmap2, $mask2) = Gtk::Gdk::Pixmap->create_from_xpm_d ($mainwindow->window,$style,@gl_blackled);
		#	   $gl_pixledoff = new Gtk::Pixmap ($pixmap2, $mask2);
		#-- Attach the pixmap to the table , place the off pixmap ontop of the on pixmpa #
		#$ledtable->attach_defaults($gl_pixledon, 0,1,0,1);
		#$ledtable->attach_defaults($gl_pixledoff, 0,1,0,1);
		#-- Generating the on pixmap but only show the off...so the on is hidden and the led is off --#
		#$gl_pixledon->realized;
		#$gl_pixledoff->show;
		#$ledtable->show;	

	#-- Adding a vbox to the window for placement toolbar, tree and statusbar --#
		my $vbox = new Gtk::VBox(FALSE,1);
		$mainscrollwin->add_with_viewport($vbox);
		$vbox->show;
		

	##-- Making the menubar --#

		my @scan_menu_items = ( { path => '/File',type =>'<Branch>'},
								{ path => '/File/Load' ,type =>'<Item>', callback => \&load_file},
								{ path => '/File/Save' ,type =>'<Item>', callback => \&save_file},
								{ path => '/File/Export as' ,type =>'<Branch>'},
								{ path => '/File/Export as/Comma separated values' ,type =>'<Item>', callback => \&export_as_csv},
#								{ path => '/File/Export as/Gpsdrive waypoints' ,type =>'<Item>', callback => sub{exit}},
#								{ path => '/File/Export as/Netstumbler format' ,type =>'<Item>', callback => sub{exit}},
								{ path => '/File/Export as/Mappoint import format' ,type =>'<Item>', callback => \&export_as_mappoint},
								{ path => '/File/Exit' ,type =>'<Item>', callback => sub{stop_scan;exit}},
								{ path => '/Scan', type =>'<Branch>'},
								{ path => '/Scan/Start', type =>'<Item>', callback => \&start_scan},
								{ path => '/Scan/Stop', type =>'<Item>', callback => \&stop_scan},
								{ path => '/View', type =>'<Branch>'},
								{ path => '/View/Toggle Log Window',type => '<Item>', callback => sub{if ($gl_LOGWINDOW_WINDOW){$gl_LOGWINDOW_WINDOW->destroy();$gl_LOGWINDOW_WINDOW = undef;}else{build_logwindow}}},
								{ path => '/View/Toggle Traffic Window',type => '<Item>', callback => sub{if ($gl_Traffic_Window){$gl_Traffic_Window->destroy();$gl_Traffic_Window = undef;}else{build_traffic_window}}},
								{ path => '/View/Toggle Toolbar',type => '<Item>', callback => sub {toggle_toolbar \$toolbarframe}},
								{ path => '/View/Reset', type =>'<Item>', callback => \&reset},
								{ path => '/Options', type => '<Branch>' },
								{ path => '/Options/Accoustic beacon indicator', type => '<CheckItem>', callback => sub{toggle_accoustic_beacon}},
								{ path => '/Options/Accoustic events', type => '<Item>', callback => sub{toggle_accoustic_events}},
								{ path => '/Options/Configure soundevents', type => '<Item>', callback => \&build_sound_window},
								{ path => '/Help', type =>'<LastBranch>'},
								{ path => '/Help/About', type => '<Item>', callback => \&build_about}
							   );
		
		my $accel_group = new Gtk::AccelGroup;
		my $item_factory = new Gtk::ItemFactory('Gtk::MenuBar', '<main>',$accel_group);
		$item_factory->create_items(@scan_menu_items);
		my $menubar = ($item_factory->get_widget( '<main>'));
		$menubar->show;
		$vbox->pack_start($menubar,FALSE,TRUE,2);

	#-- Generating the statusbar and pack it on the botton of the window --#	
		$gl_statusbar = new Gtk::Statusbar();
		$vbox->pack_end($gl_statusbar,FALSE,TRUE,0);
		$gl_statusbar->show;
		$gl_statusbar_context = $gl_statusbar->get_context_id("Context_ID"); 
		$gl_statusbar->push($gl_statusbar_context, "Waiting for user interaction");	


	#-- The Toolbar --##
	my $toolbar;
	my $g_tb_start;
	my $g_tb_stop;
	my $g_tb_save;
	my $g_tb_load;
	my $g_tb_reset;
	my $g_tb_close;

	# Add first a frame #	
		$toolbarframe = new Gtk::Frame ();
		$vbox->pack_start($toolbarframe,FALSE,TRUE,0);	
		$toolbarframe->show();
	##-- Add a toolbar on the top of the window
	if ($gl_screenwidth < 640)  
	{
		#-- Show only the text.. not the icons on smallscreen devices --#
		$toolbar = new Gtk::Toolbar ('horizontal','text');
		$toolbarframe->hide();  
	}
	else
	{
		$toolbar = new Gtk::Toolbar ('horizontal','both');
	}
	$toolbar->set_space_size(20);
	$toolbar->set_space_style('line');
	$toolbar->set_button_relief('none');
	$toolbarframe->add($toolbar);	
    $toolbar->append_space();
	#-- Toolbar Startbutton --#
    my ($start_icon,$start_mask) = Gtk::Gdk::Pixmap->create_from_xpm_d($mainwindow->window,$style,@gl_logo_start);
	my $starticon = new Gtk::Pixmap($start_icon,$start_mask);
	$g_tb_start = $toolbar->append_item('Start','Starts the process of information gathering from 802.11b in promiscous mode','Privat',$starticon);
	$toolbar->append_space();
	#-- Toolbar Stopbutton --#
    ($start_icon,$start_mask) = Gtk::Gdk::Pixmap->create_from_xpm_d($mainwindow->window,$style,@gl_logo_stop);
	my $stopicon = new Gtk::Pixmap($start_icon,$start_mask);
	$g_tb_stop = $toolbar->append_item('Stop','Stops gathering and returns to non-promiscous mode','Privat',$stopicon);
	$toolbar->append_space();
	#-- Toolbar Savebutton --#
    ($start_icon,$start_mask) = Gtk::Gdk::Pixmap->create_from_xpm_d($mainwindow->window,$style,@gl_logo_save);
	my $saveicon = new Gtk::Pixmap($start_icon,$start_mask);
	$g_tb_save = $toolbar->append_item('Save','Saves the current informations to a file','Privat',$saveicon);
	$toolbar->append_space();
	#-- Toolbar Loadbutton --#
    ($start_icon,$start_mask) = Gtk::Gdk::Pixmap->create_from_xpm_d($mainwindow->window,$style,@gl_logo_load);
	my $loadicon = new Gtk::Pixmap($start_icon,$start_mask);
	$g_tb_load = $toolbar->append_item('Load','Load precaptured informations from a file','Privat',$loadicon);
	$toolbar->append_space();
	#-- Toolbar Resetbutton --#
    ($start_icon,$start_mask) = Gtk::Gdk::Pixmap->create_from_xpm_d($mainwindow->window,$style,@gl_logo_reset);
	my $reseticon = new Gtk::Pixmap($start_icon,$start_mask);
	$g_tb_reset = $toolbar->append_item('Reset','Resets all the informations','Privat',$reseticon);
	$toolbar->append_space();
	#-- Toolbar Closebutton --#
    ($start_icon,$start_mask) = Gtk::Gdk::Pixmap->create_from_xpm_d($mainwindow->window,$style,@gl_logo_close);
	my $closeicon = new Gtk::Pixmap($start_icon,$start_mask);
	$g_tb_close = $toolbar->append_item('Close','Closes this window','Privat',$closeicon);
	$toolbar->append_space();
	#-- Toolbar Beacon indicator --#
	#my $ledtext = new Gtk::Label(' Beacon traffic indicator');
	#$ledtext->show();
	#$toolbar->append_widget($ledtable,'The led starts to blink on beacon traffic','Privat');
	#$toolbar->append_widget($ledtext,'The led starts to blink on beacon traffic','Privat');
	#$toolbar->append_space();

	#Connect the signals to the buttons
	$g_tb_start->signal_connect("clicked", \&start_scan);
	$g_tb_stop->signal_connect("clicked", \&stop_scan);
	$g_tb_close->signal_connect("clicked", sub{stop_scan;exit;});
	$g_tb_reset->signal_connect("clicked", \&reset);
	$g_tb_save->signal_connect("clicked", \&save_file);
	$g_tb_load->signal_connect("clicked", \&load_file);

	$toolbar->show();	

	# This builds the right side of the main window
	#-- Build the panned window into the window --#
	my $panned = new Gtk::HPaned();
	$vbox->pack_start($panned,TRUE,TRUE,0);

	#$panned->set_handle_size (10);
	#$panned->set_gutter_size (20);
	
	#-- Add a scrolled area into the left and right part of the panned window --#
	my $leftpart = new Gtk::ScrolledWindow ("","");
	$leftpart->set_policy('automatic', 'automatic');
	$leftpart->set_usize( (($gl_screenwidth * 17)/ 100), undef ); 
	$panned->pack1($leftpart, FALSE,FALSE);


	my $rightpart= new Gtk::ScrolledWindow ("","");
	$rightpart->set_policy('automatic', 'automatic');
	$rightpart->show();
	$rightpart->set_usize( (($gl_screenwidth * 55) / 100), undef ); 	
	$panned->pack2($rightpart, FALSE,FALSE);		



	#Now we add a Textbox to the table and hide it and
	#We add also a clist to the table at the same position 
	#But visible.
	
	#-- Add a textbox to the rightside --#
	$sniffertextbox = new Gtk::Text(undef,undef);
	#$right_table->attach_defaults($sniffertextbox,0,1,0,1);
	$sniffertextbox->set_editable(FALSE);
	$sniffertextbox->set_line_wrap(TRUE);
	$sniffertextbox->set_word_wrap(TRUE);
	$sniffertextbox->realized;
	
	#-- Add the clist to the rightside --#
	$gl_clist = new_with_titles Gtk::CList( " State "," Chan "," Network ESSID "," MAC-Address "," WEP "," Manufactor "," Networktype "," Pkt "); 
	$gl_clist->set_selection_mode( 'single' ); #Only one can be selected 
	$gl_clist->set_shadow_type( 'etched_in' );
	$rightpart->add_with_viewport($gl_clist);
	$rightpart->show();
	
	$gl_clist->set_column_justification(0,'center');
	$gl_clist->set_column_justification(1,'center');
	$gl_clist->set_column_justification(2,'left');
	$gl_clist->set_column_justification(3,'left');
	$gl_clist->set_column_justification(4,'center');
	$gl_clist->set_column_justification(5,'center');
	$gl_clist->set_column_justification(6,'center');
	$gl_clist->set_column_justification(7,'center');
	$gl_clist->show();
	#$right_table->show();

	
	#-- Add the tree to the left side --#
	#-- Adds the roottree --#
	$gl_tree = new_with_titles Gtk::CTree(0,"Treeview");
	$leftpart->add_with_viewport($gl_tree);
	#--Add a signal to the mouseclick --#
	#$gl_tree->signal_connect('select_row', \&tree_object_selected);

	$gl_tree->signal_connect('select_row', \&tree_object_selected);

	#-- Add the 15 default channels to the root-tree --#
	#-- Generate the icons for the tree --#
    ($channel_icon,$channel_mask) = Gtk::Gdk::Pixmap->create_from_xpm_d($mainwindow->window,$style,@gl_logo_channel);
    my ($essid_bcast_icon,$essid_bcast_mask) = Gtk::Gdk::Pixmap->create_from_xpm_d($mainwindow->window,$style,@gl_logo_network_broadcasting);
    my ($essid_nbcast_icon,$essid_nbcast_mask) = Gtk::Gdk::Pixmap->create_from_xpm_d($mainwindow->window,$style,@gl_logo_network_nonbroadcasting);
	my ($accesspoint_icon,$accesspoint_mask) = Gtk::Gdk::Pixmap->create_from_xpm_d($mainwindow->window,$style,@gl_logo_accesspoint);
	my ($accesspoint_wep_icon,$accesspoint_wep_mask) = Gtk::Gdk::Pixmap->create_from_xpm_d($mainwindow->window,$style,@gl_logo_accesspoint_wep);
	my ($adhoc_wep_icon,$adhoc_wep_mask) = Gtk::Gdk::Pixmap->create_from_xpm_d($mainwindow->window,$style,@gl_logo_adhoc_wep);
	my ($adhoc_icon,$adhoc_mask) = Gtk::Gdk::Pixmap->create_from_xpm_d($mainwindow->window,$style,@gl_logo_adhoc);

	
	@gl_channeltrees[0] = $gl_tree->insert_node(undef,undef,["Show all channels"],2,$channel_icon,$channel_mask,$channel_icon,$channel_mask,FALSE,TRUE);
	
	# Get the default style type:
	$gl_defaultstyle = $gl_tree->get_style()->copy();
	
	# Prepare the modified one
	my $colorred=Gtk::Gdk::Color->parse_color('red');
	$gl_redstyle = Gtk::Style->new;
	$gl_redstyle->fg('normal',$colorred);

	#-- Need to get all the channels now --#
	get_channels;

	# Add the channels to the left
	foreach my $sup_channel (@{$gl_sniff_dev->{sup_channels}})
	{
		@gl_channeltrees[$sup_channel] = $gl_tree->insert_node(undef,undef,["Channel $sup_channel"],2,$channel_icon,$channel_mask,$channel_icon,$channel_mask,FALSE,FALSE);
	}
	#-- End tree definition --#	

	
	#-- Show them all in order --#
	$gl_tree->show();
	$leftpart->show();
	$rightpart->show();
	$panned->show();
	$mainscrollwin->show();
	

	#-- Display the mainwindow on the screen --#
	$mainwindow->show();

} # End mainwindow


#card_stuff

sub get_channels # Get the supported channels from the iwlist command
{
	my $tmpiwlist = `which iwlist`;
	chomp $tmpiwlist;
	my @freq = `$tmpiwlist $gl_sniff_dev->{dev_name} channel 2>&1`;
	my @tmpref;
	foreach my $frequency (@freq)
	{
		if ($frequency =~ /\s+Channel\s+(\d+)\s+/)
		{
			
			push (@tmpref,$1);
		}
	}
	$gl_sniff_dev->{sup_channels} = \@tmpref;;
}

sub set_monitor_mode
{
	if (check_up == FALSE)
	{
		set_up;
	}
	
	if (check_promisc == FALSE)
	{
		set_promisc;
	}
	
	if (check_promisc == FALSE || check_up == FALSE)
	{
		print "\nSorry i could not set flags on the interface, could not continue";
		exit;
	}
	
}

sub check_promisc
{
	if (`ifconfig $gl_sniff_dev->{dev_name}` !~ /\bPROMISC/)
	{
		return(FALSE);
	}
	else
	{
		return(TRUE);
	}
}

sub set_promisc
{
	`ifconfig $gl_sniff_dev->{dev_name} promisc`;
        if ($gl_sniff_dev->{dev_type} == TYPE_CISCO2)
        {
         `ifconfig wifi0 promisc`;
        }

}

sub remove_promisc
{
	`ifconfig $gl_sniff_dev->{dev_name} -promisc`;
}

sub check_up
{
	if (`ifconfig $gl_sniff_dev->{dev_name}` !~ /\bUP/)
	{
		return(FALSE);
	}
	else
	{
		return(TRUE);
	}
}

sub set_up
{
	`ifconfig $gl_sniff_dev->{dev_name} up`;
	if ($gl_sniff_dev->{dev_type} == TYPE_CISCO2)
	{
	 `ifconfig wifi0 up`;
	}
}

sub set_monitormode
{
	if (check_up == FALSE)
	{
		set_up;
	}
	if (check_promisc == FALSE)
	{
		set_promisc;
	}
	
	# Activate the monitoring mode
	if ($gl_sniff_dev->{dev_type} == TYPE_CISCO1 || $gl_sniff_dev->{dev_type} == TYPE_CISCO2)
	{
		# Write the correct stuff to the config file
		if (open (DRIVERCONFIGFILE,">/proc/driver/aironet/$gl_sniff_dev->{dev_name}/Config"))
		{
			print (DRIVERCONFIGFILE "Mode: r\n");		
			close(DIRVERCONFIGFILE);
		}

		# Write the correct stuff to the config file
		if (open (DRIVERCONFIGFILE,">/proc/driver/aironet/$gl_sniff_dev->{dev_name}/Config"))
		{
			print (DRIVERCONFIGFILE "Mode: y\n");		
			close(DIRVERCONFIGFILE);
		}
	}
	elsif ($gl_sniff_dev->{dev_type} == TYPE_LUCENT)
	{
		my $iwpath = `which iwpriv`;
		if ($iwpath)
		{  
	   	system ("iwpriv $gl_sniff_dev->{dev_name} monitor 2 1");
		}
		else
		{
			show_dialog "Wellenreiter","\nThe iwpriv command is not installed\nor not in you PATH, cannot continue\n",TRUE;
		}
	}
	elsif ($gl_sniff_dev->{dev_type} == TYPE_WLANNG)
	{
		my $wpath = `which wlanctl-ng`;
		chomp $wpath;
		if ($wpath)
		{  
	   	system ("$wpath $gl_sniff_dev->{dev_name} lnxreq_wlansniff channel=1 enable=true > /dev/null");
		}
		else
		{
			show_dialog "Wellenreiter","\nThe wlanctl-ng command is not installed\nor not in you PATH, cannot continue\n",TRUE;
		}

	}
} # End set_monitormode

sub remove_monitormode
{
	# Activate the monitoring mode
	if ($gl_sniff_dev->{dev_type} == TYPE_CISCO1 || $gl_sniff_dev->{dev_type} == TYPE_CISCO2)
	{
		
		# Write the correct stuff to the config file
		if (open (DRIVERCONFIGFILE,">/proc/driver/aironet/$gl_sniff_dev->{dev_name}/Config"))
		{
			system("echo \"Mode: Auto\" > /proc/driver/aironet/$gl_sniff_dev->{dev_name}/Config"); 
			close(DIRVERCONFIGFILE);
		}
		else
		{
			show_dialog "Wellenreiter","\nCannot write to /proc/driver/aironet/$gl_sniff_dev->{dev_name}/Config\ncannot continue",TRUE;
		}
	}
	elsif ($gl_sniff_dev->{dev_type} == TYPE_LUCENT)
	{
		my $iwpath = `which iwpriv`;
		if ($iwpath)
		{  
	   	system ("iwpriv $gl_sniff_dev->{dev_name} monitor 0 0");
		}
		else
		{
			show_dialog "Wellenreiter","\nThe iwpriv command is not installed\nor not in you PATH, cannot continue\n",TRUE;
		}
	}
	elsif ($gl_sniff_dev->{dev_type} == TYPE_WLANNG)
	{
		my $wpath = `which wlanctl-ng`;
		chomp $wpath;
		if ($wpath)
		{  
	   	system ("$wpath $gl_sniff_dev->{dev_name} lnxreq_wlansniff channel=1 enable=false > /dev/null");
		}
		else
		{
			show_dialog "Wellenreiter","\nThe wlanctl-ng command is not installed\nor not in you PATH, cannot continue\n",TRUE;
		}
	}

	if (check_promisc == TRUE)
	{
		remove_promisc;
	}
	
} # End set_monitormode

sub check_monitor_mode
{
	# check if in monitoring mode
	if ($gl_sniff_dev->{dev_type} == TYPE_CISCO1 || $gl_sniff_dev->{dev_type} == TYPE_CISCO2)
	{
		
		# Read the config file
		open (CONFIG,"</proc/driver/aironet/$gl_sniff_dev->{dev_name}/Config") or die 
		"Cannot read in the file /proc/driver/aironet/$gl_sniff_dev->{dev_name}/Config, cannot continue\n";
		
		while (<CONFIG>)
		{
			if ($_ =~ /Mode:\s+rfmon/i)
			{
				return TRUE;
			}			
			close(DIRVERCONFIGFILE);
		}
		close(CONFIG);
		return FALSE;
	}
	elsif ($gl_sniff_dev->{dev_type} == TYPE_LUCENT || $gl_sniff_dev->{dev_type} == TYPE_WLANNG)
	{
		if (`ifconfig $gl_sniff_dev->{dev_name}` =~ /\b[^:]+:UNSPEC\s+.*\d+-\d+/)
		{
			return(TRUE);
		}
		return (FALSE);		
	}
}

###################################
# Function to switch the channels #
###################################
sub switchchannel
{
                                                                                                               
                if ($gl_sniffchannel < @{$gl_sniff_dev->{sup_channels}})
                {
                        $gl_sniffchannel++;
			if ($gl_sniff_dev->{dev_type} == TYPE_CISCO1 || $gl_sniff_dev->{dev_type} == TYPE_CISCO2)
        		{
                		system("echo \"Channel: $gl_sniffchannel\" > /proc/driver/aironet/$gl_sniff_dev->{dev_name}/Config");
			}
			elsif ($gl_sniff_dev->{dev_type} == TYPE_LUCENT)
			{
				my $tmpiwpriv = `which iwpriv`;
				chomp $tmpiwpriv;
				`$tmpiwpriv $gl_sniff_dev->{dev_name} monitor 2 $gl_sniffchannel`;
			}
			elsif ($gl_sniff_dev->{dev_type} == TYPE_WLANNG)
			{	
				my $wpath = `which wlanctl-ng`;
				chomp $wpath;
				if ($wpath)
				{  
			   	system ("$wpath $gl_sniff_dev->{dev_name} lnxreq_wlansniff channel=$gl_sniffchannel enable=true > /dev/null");
				}
				else
				{
					show_dialog "Wellenreiter","\nThe wlanctl-ng command is not installed\nor not in you PATH, cannot continue\n",TRUE;
				}
			}
                }
                else
                {
                        $gl_sniffchannel = 1;
                        if ($gl_sniff_dev->{dev_type} == TYPE_CISCO1 || $gl_sniff_dev->{dev_type} == TYPE_CISCO2)                        {
                                system("echo \"Channel: $gl_sniffchannel\" > /proc/driver/aironet/$gl_sniff_dev->{dev_name}/Config");
                        }
                        elsif ($gl_sniff_dev->{dev_type} == TYPE_LUCENT)
                        {
                                my $tmpiwpriv = `which iwpriv`;
                                chomp $tmpiwpriv;
                                `$tmpiwpriv $gl_sniff_dev->{dev_name} monitor 2 $gl_sniffchannel`;
                        }
			elsif ($gl_sniff_dev->{dev_type} == TYPE_WLANNG)
			{	
				my $wpath = `which wlanctl-ng`;
				chomp $wpath;
				if ($wpath)
				{  
			   	system ("$wpath $gl_sniff_dev->{dev_name} lnxreq_wlansniff channel=$gl_sniffchannel enable=true > /dev/null");
				}
				else
				{
					show_dialog "Wellenreiter","\nThe wlanctl-ng command is not installed\nor not in you PATH, cannot continue\n",TRUE;
				}
			}
		}

#-- Debug print for controlling of channel switching --#
if ($gl_debugon == 1){print "\nScan on channel: $gl_sniffchannel";}
return(TRUE);
}

#-------------- Tree functions ----------------#
# Holds all the functions for the ctree object #
#----------------------------------------------#
sub tree_object_selected
{
  my ($ctree, $row, $column) = @_;
  $gl_tree->node_set_cell_style($ctree->selection,0,$gl_defaultstyle);
  my ($tmpnodename) = $ctree->get_node_info($ctree->selection);
  if ($row == 0)
  {
	# Show the clist and hide the sniffertextbox
	rebuild_clist 0;

  }
  else
  {

	if ($tmpnodename =~ /Channel\s+(\d+)/)
	{
		#do nothing for now, maybe later
		# i could add a filter for it
		my $channel = $1;
		rebuild_clist ($channel);
	}
	else
	{
		foreach my $objref (@gl_accesspoints)
  		{
			if ( $objref->{sendmac} eq $tmpnodename)
			{
				$gl_detail_ap_name = $tmpnodename;
				build_detail_window;
	
			}
		}
	}
  }
  
$gl_tree->unselect_recursive($ctree->selection);
  
}
#----------- Build the about window  --------#

sub build_about {
	#-- Defines the window --#
	my $scrollwin;
	my $aboutwindow = new Gtk::Window('toplevel');
	$aboutwindow->set_transient_for ($mainwindow);
	$aboutwindow->signal_connect("delete_event",sub{$aboutwindow->destroy();});
	$aboutwindow->title("-=[ About Wellenreiter ]=-");
	$aboutwindow->border_width(2);
	#$aboutwindow->set_modal(TRUE);

	#-- Without the realize the pixmap would not work --#
	$aboutwindow->realize();

	#-- create the top and bottom label --#
	my $labeltop = new Gtk::Label ("\nWellenreiter v.1.8\n");
	my $labelbot = new Gtk::Label ("\nBrought to you by:\n". '-=[ http://www.remote-exploit.org ]=- '."\n");
	
	#-- Insert the logo --#
	my ($style, $pixmap, $mask, $pixmapwid);
	$style = $aboutwindow->get_style()->bg('normal');
	($pixmap, $mask) = Gtk::Gdk::Pixmap->create_from_xpm_d ($aboutwindow->window,$style,@gl_logo);
	$pixmapwid = new Gtk::Pixmap ($pixmap, $mask);

	#-- Table definition --#
	my $table = new Gtk::Table(4,1,FALSE);
	
	$aboutwindow->add ($table);

	#-- Frame and the close button --#
		my $closeframe = new Gtk::Frame ();
		my $closebutton = new Gtk::Button ('Close');
		$closebutton->signal_connect("clicked",sub{$aboutwindow->destroy();});
		$closebutton->set_relief('none');
		$closebutton->show();
		$closeframe->add($closebutton);		

	#-- Place the items --#
	$table->attach_defaults($labeltop, 0,1,0,1);
	$table->attach_defaults($pixmapwid, 0,1,1,2);
	$table->attach_defaults($labelbot, 0,1,2,3);
	$table->attach_defaults($closeframe,0,1,3,4);
	
	#-- Show items --#
	$closeframe->show();
	$labeltop->show();
	$labelbot->show();
	$pixmapwid->show();
	$table->show();
	$aboutwindow->show();
}	
########################################
####------   Subfuntions   ------- ####
######################################

##-- Used to write a message into the logwindow --##
sub writetologwin    
{
	my ($text1, $text2) = @_;
	my $date=`date +%T-%d/%m/%Y`;
	chomp ($date);
	my $LOGWINDOW_TEXT_BUFFER = "$date - $text1\n";
	push (@gl_LOGWINDOW_TEXT_BUFFER_ARRAY, $LOGWINDOW_TEXT_BUFFER);
	if ($gl_logtextbox)
	{
			$gl_logtextbox->insert(undef,undef,undef,$LOGWINDOW_TEXT_BUFFER);
	}
	
}

sub clean_logwin
{
	if ($gl_logtextbox)
	{
	  $gl_logtextbox->freeze();
  	$gl_logtextbox->set_point(0);
  	my $del_len = $gl_logtextbox->get_length();
  	$gl_logtextbox->forward_delete($del_len);
	  $gl_logtextbox->thaw();
	 }
	 @gl_LOGWINDOW_TEXT_BUFFER_ARRAY = undef;
}


sub build_logwindow
{
		$gl_LOGWINDOW_WINDOW = new Gtk::Window( 'toplevel' );
		$gl_LOGWINDOW_WINDOW->set_transient_for ($mainwindow);
		$gl_LOGWINDOW_WINDOW->title("-=[ Log ]=-");
		$gl_LOGWINDOW_WINDOW->set_default_size(700,50);
		$gl_LOGWINDOW_WINDOW->set_usize( (($gl_screenwidth * 80)/ 100), (($gl_screenheight * 30)/ 100) ); 
		my $signals = $gl_LOGWINDOW_WINDOW->signal_connect( 'delete_event', sub{$gl_LOGWINDOW_WINDOW->destroy();$gl_LOGWINDOW_WINDOW=undef;} );
		$gl_LOGWINDOW_WINDOW->border_width( 5 );

		#-- Add a scrolled area --#
		my $scrollbox = new Gtk::ScrolledWindow ("","");
		$scrollbox->set_policy('automatic', 'automatic');
		$gl_LOGWINDOW_WINDOW->add($scrollbox);
		
		##-- Add a textbox to the rightside --#
		$gl_logtextbox = new Gtk::Text(undef,undef);
		$scrollbox->add($gl_logtextbox);
		$scrollbox->show();
		$gl_logtextbox->set_editable(FALSE);
		$gl_logtextbox->set_line_wrap(TRUE);
		$gl_logtextbox->set_word_wrap(TRUE);
		$gl_logtextbox->show();
		$gl_LOGWINDOW_WINDOW->show();
		foreach my $textline (@gl_LOGWINDOW_TEXT_BUFFER_ARRAY)
		{
			$gl_logtextbox->insert(undef,undef,undef,$textline);
		}
		
}
sub build_traffic_window
{
	# Generating the traffic window 
	$gl_Traffic_Window = new Gtk::Window( 'toplevel' );
	$gl_Traffic_Window->set_transient_for ($mainwindow);
	$gl_Traffic_Window->title("-=[ Active traffic ]=-");
	$gl_Traffic_Window->set_default_size(800,200);
	$gl_Traffic_Window->border_width( 5 );
	my $signals = $gl_Traffic_Window->signal_connect( 'delete_event', sub{$gl_Traffic_Window->destroy();$gl_Traffic_Window=undef;} );

	# Add a scrolled area
	my $scrollbox = new Gtk::ScrolledWindow ("","");
	$scrollbox->set_policy('automatic', 'automatic');
	$gl_Traffic_Window->add($scrollbox);

	# Add a columned list with 5 columns
	$gl_Traffic_clist = new_with_titles Gtk::CList ( "BssID","Src","Dest","Type");
	$gl_Traffic_clist->set_selection_mode ('single');
	$gl_Traffic_clist->set_shadow_type('etched_in');

	# The column titles should all have no action on click
	$gl_Traffic_clist->column_titles_passive();

#	$gl_Traffic_clist_color = new Gtk::Gdk::Color;
#	$gl_Traffic_clist_color->parse_color('yellow');


	$gl_Traffic_clist->set_column_width(0,200);
	$gl_Traffic_clist->set_column_width(1,200);
	$gl_Traffic_clist->set_column_width(2,200);
	$gl_Traffic_clist->set_column_width(3,200);

	# Place the clist into the scrollbox
	$scrollbox->add($gl_Traffic_clist);

	# Make all visible to the user
	$gl_Traffic_clist->show();
	$scrollbox->show();
	$gl_Traffic_Window->show();


} # End of sub build_active_traffic_window
#######################################################
# All the icons for the mainwindow are loaded here #
#######################################################

##################################
# Loads in the led xpm          #
################################
sub load_leds
{
	@gl_greenled = (
	'10 10 5 1',
	' 	c None',
	'.	c #FFFFFF',
	'+	c #99CC99',
	'-	c #00CC33',
	'#	c #009933',
	'...+###+..',
	'.+######+.',
	'.#-+-####+',
	'+#--######',
	'##########',
	'#######-##',
	'+#####--##',
	'.####--##+',
	'.+######+.',
	'..+####+..');

	@gl_blackled = (
	'10 10 5 1',
	' 	c None',
	'.	c #FFFFFF',
	'+	c #000099',
	'-	c #00CC00',
	'#	c #000000',
	'...+###+..',
	'.+######+.',
	'.#-+-####+',
	'+#--######',
	'##########',
	'#######-##',
	'+#####--##',
	'.####--##+',
	'.+######+.',
	'..+####+..');

@gl_logo_start = (
'24 24 49 1',
' 	c None',
'.	c #000000',
'+	c #E1EADF',
'k	c #FFFFFF',
'#	c #F0F4EF',
'$	c #D4E0D1',
'%	c #F3F7F3',
'&	c #EDF2EB',
'*	c #CEDCCB',
'=	c #F4F7F4',
'-	c #F1F5F0',
';	c #EFF3EE',
'>	c #EBF1EA',
',	c #C9D8C5',
'l	c #E5ECE3',
')	c #CBDAC7',
'!	c #181818',
'~	c #2B2B2B',
'{	c #E4EBE2',
']	c #DEE7DC',
'^	c #D7E3D5',
'/	c #EEF3ED',
'(	c #B1C7AC',
'_	c #9DBB90',
':	c #88AC80',
'<	c #83AA7C',
'[	c #85A879',
'}	c #7EA476',
'|	c #84A778',
'1	c #759B6C',
'2	c #59814F',
'3	c #3A5934',
'4	c #9ABB8F',
'5	c #83AA7A',
'6	c #87AC7D',
'7	c #82A87B',
'8	c #86A97C',
'9	c #759C6D',
'0	c #537C49',
'a	c #445840',
'b	c #80A776',
'c	c #749868',
'd	c #4B7040',
'e	c #90B387',
'f	c #749A6B',
'g	c #3B5E31',
'h	c #5D8554',
'i	c #37592F',
'j	c #3F6534',
'                        ',
'                        ',
'                        ',
'                        ',
'                        ',
'      ..                ',
'      .+..              ',
'      .k#$..            ',
'      .k%&#*..          ',
'      .k=-;>-,..        ',
'      .k;;;>>l#)!.      ',
'      ~k;;;>{]^]/(..    ',
'      ._:<:<[}|123..    ',
'      .4567|890a..      ',
'      .46b[c0d..        ',
'      .ebf0g..          ',
'      .<hi..            ',
'      .j..              ',
'      ..                ',
'                        ',
'                        ',
'                        ',
'                        ',
'                        ');

@gl_logo_stop = ('24 24 166 2',
'  	c None',
'. 	c #010000',
'+ 	c #080102',
'@ 	c #0E0203',
'# 	c #110305',
'$ 	c #140505',
'% 	c #150405',
'& 	c #130204',
'* 	c #020000',
'= 	c #030000',
'- 	c #B1A4A4',
'; 	c #CEBBBC',
'> 	c #DDCCCC',
', 	c #DDCCCD',
'" 	c #CBB6B7',
') 	c #B89A9B',
'! 	c #7D5E61',
'~ 	c #210708',
'{ 	c #270A0B',
'] 	c #A19999',
'^ 	c #DED1D1',
'/ 	c #F3E6E6',
'( 	c #EFE0E1',
'_ 	c #EBDCDD',
': 	c #EADCDC',
'< 	c #E4D7D7',
'[ 	c #E6D2D3',
'} 	c #E1C5C6',
'| 	c #AC7D7D',
'1 	c #654040',
'2 	c #2E0C0D',
'3 	c #050001',
'4 	c #DED1D2',
'5 	c #F4EBEB',
'6 	c #F1E6E6',
'7 	c #EBDFDF',
'8 	c #E4DBDA',
'9 	c #E5DBDB',
'0 	c #E2D3D3',
'a 	c #DDC3C4',
'b 	c #DBB3B6',
'c 	c #A06E6E',
'd 	c #310D0D',
'e 	c #A39596',
'f 	c #F5ECEC',
'g 	c #EEE4E4',
'h 	c #120808',
'i 	c #E4DADA',
'j 	c #E5DEDD',
'k 	c #0E0505',
'l 	c #CBB3B4',
'm 	c #D8B9BB',
'n 	c #B88B8C',
'o 	c #633E3F',
'p 	c #250A0A',
'q 	c #BFB2B3',
'r 	c #EADEDE',
's 	c #190E0E',
't 	c #0F0606',
'u 	c #130A0A',
'v 	c #E6DCDC',
'w 	c #0C0404',
'x 	c #0F0505',
'y 	c #130606',
'z 	c #C3A9A9',
'A 	c #CBA5A6',
'B 	c #A57577',
'C 	c #2C0B0D',
'D 	c #0D0303',
'E 	c #D1C3C4',
'F 	c #EDE1E0',
'G 	c #120909',
'H 	c #090303',
'I 	c #0B0303',
'J 	c #0D0404',
'K 	c #B9A7A7',
'L 	c #DEC6C7',
'M 	c #CCABAD',
'N 	c #B68B8F',
'O 	c #290A0C',
'P 	c #CCB9B9',
'Q 	c #ECE1E1',
'R 	c #E5DDDD',
'S 	c #DFD1D0',
'T 	c #DFCDCC',
'U 	c #CDB1B1',
'V 	c #CBA7A9',
'W 	c #B28487',
'X 	c #2B0A0C',
'Y 	c #1B0607',
'Z 	c #C9AFB0',
'` 	c #ECDFDF',
' .	c #E6DEDF',
'..	c #0F0405',
'+.	c #120506',
'@.	c #D0B4B6',
'#.	c #CBAAAB',
'$.	c #C09699',
'%.	c #A17273',
'&.	c #2A0B0C',
'*.	c #1A0507',
'=.	c #AD8C8D',
'-.	c #D6C0C0',
';.	c #E1D0D1',
'>.	c #0F0504',
',.	c #100405',
'".	c #DECFCF',
').	c #120505',
'!.	c #180707',
'~.	c #24090A',
'{.	c #C69B9E',
'].	c #B38083',
'^.	c #905E5F',
'/.	c #170405',
'(.	c #957273',
'_.	c #C6A3A5',
':.	c #DAB9BA',
'<.	c #DCC4C4',
'[.	c #130505',
'}.	c #DCC6C7',
'|.	c #E0C9CA',
'1.	c #CFB3B4',
'2.	c #22080A',
'3.	c #BA8D8F',
'4.	c #BE8C8D',
'5.	c #A16C6E',
'6.	c #774748',
'7.	c #220809',
'8.	c #1D0607',
'9.	c #B88D8F',
'0.	c #C79FA0',
'a.	c #D6B2B4',
'b.	c #D8BEBF',
'c.	c #CDACAF',
'd.	c #D9BABC',
'e.	c #CBA5A7',
'f.	c #C6999A',
'g.	c #BF8B8C',
'h.	c #9F6A6B',
'i.	c #804F50',
'j.	c #1E0708',
'k.	c #A17477',
'l.	c #C29698',
'm.	c #C69E9F',
'n.	c #C69B9C',
'o.	c #C59898',
'p.	c #B27C7D',
'q.	c #AB7475',
'r.	c #8C5A5B',
's.	c #734849',
't.	c #210707',
'u.	c #250909',
'v.	c #9E7070',
'w.	c #B98A8B',
'x.	c #B88888',
'y.	c #B37D7F',
'z.	c #9F6767',
'A.	c #824E4F',
'B.	c #703F40',
'C.	c #27090A',
'D.	c #1B0507',
'E.	c #1E0707',
'F.	c #230909',
'G.	c #280B0B',
'H.	c #2C0B0C',
'I.	c #2F0C0C',
'                                                ',
'                                                ',
'                                                ',
'                                                ',
'                . + @ # $ % &                   ',
'            * = - ; > , " ) ! ~ {               ',
'          = ] ^ / ( _ : < [ } | 1 2             ',
'          3 4 5 6 7 8 8 9 0 a b c d             ',
'        3 e f g 7 h 8 i j k l m n o p           ',
'        + q 6 r s t u v w x y z A B C           ',
'        D E F r 8 G H I J x K L M N O           ',
'        $ P Q 8 R R I J J S T U V W X           ',
'        Y Z `  . .J ....k +.@.#.$.%.&.          ',
'        *.=.-.;...>.,.".).!.~.{.].^.O           ',
'        /.(._.:.<.[.}.|.1.2.3.4.5.6.7.          ',
'          8.9.0.a.b.c.d.e.f.g.h.i.O             ',
'          j.k.l.m.n.f.o.4.p.q.r.s.8.            ',
'            t.u.v.w.x.y.z.A.B.C.D.              ',
'                E.F.G.H.I.I.C.                  ',
'                                                ',
'                                                ',
'                                                ',
'                                                ',
'                                                ');

@gl_logo_save = (
'24 24 64 1',
' 	c None',
'.	c #000000',
'+	c #779FA8',
'@	c #495A5E',
'#	c #BFD1D5',
'$	c #A8C1C5',
'%	c #E4ECED',
'&	c #FFFFFF',
'*	c #EEF3F4',
'=	c #E0E9EB',
'-	c #87AAB2',
';	c #AEC4C9',
'>	c #F5F8F9',
',	c #8BADB5',
'"	c #3E4D50',
')	c #94B2B9',
'!	c #CFDCDF',
'~	c #E4ECEE',
'{	c #788A8D',
']	c #EBF1F2',
'^	c #E8EFF0',
'/	c #F2F6F7',
'(	c #607A7F',
'_	c #F0F4F5',
':	c #536E75',
'<	c #A0BCC1',
'[	c #465E63',
'}	c #4B575A',
'|	c #557278',
'1	c #A4ABAD',
'2	c #EAEAEA',
'3	c #E4E4E4',
'4	c #606364',
'5	c #C6CACC',
'6	c #F3F3F3',
'7	c #F1F1F1',
'8	c #E7E7E7',
'9	c #E1E1E1',
'0	c #A9B2B4',
'a	c #486166',
'b	c #34464A',
'c	c #729096',
'd	c #BCC2C3',
'e	c #F6F6F6',
'f	c #57696D',
'g	c #CFD8DA',
'h	c #DEDEDE',
'i	c #D8D8D8',
'j	c #8C9394',
'k	c #F2F2F2',
'l	c #3A474A',
'm	c #7EA4AC',
'n	c #D5DADA',
'o	c #E0E0E0',
'p	c #B4B4B4',
'q	c #657376',
'r	c #D0D5D6',
's	c #E9E9E9',
't	c #A7B0B2',
'u	c #D2D4D5',
'v	c #899293',
'w	c #484848',
'x	c #DDDDDD',
'y	c #8F9A9B',
'                        ',
'                        ',
'                        ',
'              ..        ',
'            ..+@.       ',
'          ..#$%+.       ',
'        ..#$#&*+@.      ',
'      ..#$#&&&&=+.      ',
'    ..-;#&&&&&&>,".     ',
'   .);!&&&&&&&&&~+.     ',
'   .{)]&&&&&&&&&^+@.    ',
'    .$=&&&&&&&/=+++.    ',
'    .(-]&&&&_=++::+@.   ',
'     .<=&&_=++[}|+:+.   ',
'     .(-^=++[1234+:+@.  ',
'      .)++:567890a+[b.  ',
'      .c-+defg3hij+"..  ',
'       .)+:klmnopq..    ',
'       .|++rstuvw.      ',
'        .a+:xy..        ',
'         .....          ',
'                        ',
'                        ',
'                        ');

@gl_logo_load = (
'24 24 62 1',
' 	c None',
'.	c #000000',
'+	c #629DA8',
'@	c #2C3D42',
'#	c #A8C7CB',
'$	c #E9EEEF',
'%	c #C5D8DC',
'&	c #F0F2F3',
'*	c #F9F9F9',
'=	c #E5ECED',
'-	c #7AABB6',
';	c #B1CAD0',
'>	c #F4F6F6',
',	c #80AFB9',
'"	c #212F32',
')	c #8DB6BE',
'!	c #D5E1E4',
'~	c #E9EEF0',
'{	c #647F82',
']	c #EDF2F2',
'^	c #EBF0F1',
'/	c #F2F4F5',
'(	c #45676E',
'_	c #F1F3F4',
':	c #36575F',
'<	c #9EC2C7',
'[	c #294249',
'}	c #2E3B3D',
'|	c #385C64',
'1	c #A4ADAF',
'2	c #EDEDED',
'3	c #E9E9E9',
'4	c #45494A',
'5	c #CDD1D3',
'6	c #F2F2F2',
'7	c #EAEAEA',
'8	c #E6E6E6',
'9	c #AAB6B8',
'0	c #2B464D',
'a	c #18292D',
'b	c #5C8791',
'c	c #C2C8C9',
'd	c #F4F4F4',
'e	c #3B5055',
'f	c #D5DFE0',
'g	c #E3E3E3',
'h	c #DFDFDF',
'i	c #828C8D',
'j	c #1E2A2D',
'k	c #6DA4AE',
'l	c #DCE0E0',
'm	c #E5E5E5',
'n	c #B8B8B8',
'o	c #4B5C61',
'p	c #D6DCDD',
'q	c #ECECEC',
'r	c #A7B4B6',
's	c #D9DBDC',
't	c #7D8A8C',
'u	c #2B2B2B',
'v	c #E2E2E2',
'w	c #859597',
'                        ',
'      .                 ',
'     ..                 ',
'    ......              ',
'   .........  ..        ',
'    ..........+@.       ',
'     ..   ...#$+.       ',
'      . ..%...&+@.      ',
'      ..%#%*..*=+.      ',
'    ..-;%***..*>,".     ',
'   .);!*****.***~+.     ',
'   .{)]****.****^+@.    ',
'    .#=*******/=+++.    ',
'    .(-]****_=++::+@.   ',
'     .<=**_=++[}|+:+.   ',
'     .(-^=++[1234+:+@.  ',
'      .)++:5667890+[a.  ',
'      .b-+cdef3ghi+"..  ',
'       .)+:6jklmno..    ',
'       .|++pqrstu.      ',
'        .0+:vw..        ',
'         .....          ',
'                        ',
'                        ');

@gl_logo_reset = (
'24 24 11 1',
' 	c None',
'.	c #000000',
'+	c #566B43',
'@	c #4C603C',
'#	c #526741',
'$	c #5A7046',
'%	c #445636',
'&	c #37452B',
'*	c #425334',
'=	c #475937',
'-	c #5C7449',
'                        ',
'                        ',
'                        ',
'                        ',
'           .            ',
'          ..            ',
'         .+@...         ',
'        .#$##@%..       ',
'         .+#...%%.      ',
'       .  ..   .&.      ',
'      .    .    .&.     ',
'     ..          ..     ',
'     ..          ..     ',
'     .*.    .    .      ',
'      .*.   ..  .       ',
'      .%@...#=.         ',
'       ..##-#@#.        ',
'         ...@%.         ',
'            ..          ',
'            .           ',
'                        ',
'                        ',
'                        ',
'                        ');

@gl_logo_close = (
'24 24 2 1',
' 	c None',
'.	c #000000',
'                        ',
'                        ',
'                        ',
'                        ',
'                        ',
'                        ',
'       .    ..          ',
'       ..  ....         ',
'        .. ...          ',
'        .....           ',
'         ...            ',
'         ....           ',
'        ......          ',
'        .. ....         ',
'       ..   ....        ',
'       .     ..         ',
'                        ',
'                        ',
'                        ',
'                        ',
'                        ',
'                        ',
'                        ',
'                        ');

@gl_logo_channel = (
'18 13 3 1',
' 	c None',
'.	c #000000',
'+	c #00FF00',
' ..  .     .  ..  ',
'..  ..  .  ..  .  ',
'.  ..  ...  .. .. ',
'.  .  ..+..  .  ..',
'.  .   ...   .  ..',
'.. ..   .   ..  ..',
'..  ..  .  ..  .. ',
' ..  .  .  .   .  ',
' ..     .     ..  ',
'  .     .     .   ',
'      .....       ',
'    .........     ',
'  .............   ');

@gl_logo_detail = (
'96 96 17 1',
' 	c None',
'.	c #9A9A9A',
'+	c #3A3A3A',
'@	c #121212',
'#	c #373636',
'$	c #1E1E1E',
'%	c #272727',
'&	c #6A6A66',
'*	c #8C8A88',
'=	c #5E4E4A',
'-	c #7A7672',
';	c #4B4A4A',
'>	c #5A5A5A',
',	c #CEC2AA',
'a	c #ACA8A7',
')	c #DEDACA',
'!	c #434242',
'                          @@@@                                              @@@@                ',
'                          @@@@                                              @@@@                ',
'                          @@@@                                              @@@@                ',
'                          @@@@                                              @@@@                ',
'                          @@@@                                              @@@@                ',
'                          @@@@                                              @@@@                ',
'                          @@@@                                              @@@@                ',
'                          @@@@                                              @@@@                ',
'                          @@@@                                              @@@@                ',
'                          @@@@                                              @@@@                ',
'                          @@@@                                              @@@@                ',
'                          @@@@                                              @@@@                ',
'                          @@@@                                              @@@@                ',
'                          @@@@                                              @@@@                ',
'                          @@@@                                              @@@@                ',
'                          @@@@                                              @@@@                ',
'                          @@@@                                              @@@@                ',
'                          @@@@                                              @@@@                ',
'                          @@@@                                              @@@@                ',
'                          @@@@                                              @@@@                ',
'          **&&==++++++    @@@@                                              @@@@                ',
'          *-&&==######    @@@@                                              @@@@                ',
'        --******--;;++++++@@@@                                              @@@@                ',
'        ---***.*--;;######@@@@                                              @@@@                ',
'    &&>>**........**--;;++++@@                                              @@@@                ',
'    &&>>*..........*--;;####@@                                              @@@@                ',
'    >>&&..........*.,,aa==;;;;                                              @@@@                ',
'    >>&&..........**,,aa==;;;;                                              @@@@                ',
'  &&&&aa............aa,,..====                                              @@@@                ',
'  &&>&aa............a.,,..====                                              @@@@                ',
'  >>**............aaaaaa,,**>>==                                            @@@@@@              ',
'  >=.*............aaaa,a,,-*>>==                                            @@@@@@              ',
'  &&............++@@@@@@,,aa&&>>>>@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@++..    ',
'  &&............##@@@@@@,,.a&&>>>>@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@##..    ',
'**&&.......*..++@@@@@@@@a,,,-*&&>>@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@++..  ',
'*-&&......**..##@@@@@@@@aa,,*-&&>>@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@##..  ',
'**&&........++$$$$@@@@@@@@aa,a**----$@$$@$$@$$@$$@$$@$$@$$@$$@$$@$$@--$$@@>&##@@@@@$@@@$@@$$++..',
'*-&&........##$$$@@@@@@@@@,a,a*-----$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$--%%@@&&##@@@@$@@@$$@@$$##..',
'**=>.....a%%$$$$$$@$@$$$$$..aa..****$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$%%$$$@%%$@$@$$$$$$$$@@$$$$%%',
'**>=......%%$@$$$$$$$@$$$$..aa..-***$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$%%$$$$%%$$$$$$$$$$@$@@$$$$%%',
'-->>aa....$$%%###+%%+###%%%%-*aaaa..%$%$%$%$%$$$$%$@$$@$$@$$@$@@@$@@@@@@@@@@@@@@@@@@@@@@@@@@@@$$',
'-->>aa....$$%%####%%++##%%%%*-aaaa..%%%%%%%%%%$$%%$$$$$$$$$$$@@@$@@@@@@@@@@@@@@@@@@@@@@@@@@@@@$$',
'  >>aa..**$$#++++#+##++#%%%%--*-a,a,%%%%%%%%%%%%%%$$$$$$$$@@$$@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@$$',
'  >=aa..*.$$+####++++##+%%%%--**,aaa%%%%%%%%%%%%%$$$$$$$$$@@$$@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@$$',
'  &&,,aa**$$++++####++##++%%===;,,,,,,%%%%%%%%$$$$$$@$$@$$$$@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@$',
'  &>,,aa**$$#+++++++##++##%%====,,,,,,%%%%%%%%$$$$$$$$$$$$$@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@$$',
'  ----..**$$#+#+++++++%%%%%%==+#,,,,,,%%%%%%%%$$%$$$$$$$$$$$@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@$$',
'  ----..*-$$++##+#++##%%%%%%==##,,,,,,%%%%%%%$$$%%$$$$$@$$$@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@$$',
'  ))--..**$$##+#+#++%%#+%%%%%%+#aaaa%%%%%%%%$$$$$$$$$@$$$$@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@$',
'  ))--..-*$$+#+#+#++%%+#%%%%%%++,aaa%%%%%%%%$$$$$@$$$$$$$$@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@$$',
'  ))&&----$$%%#+##%%%%%%%%%%%%##aaaa%%%%$$$$$$$$$$$$$$@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@$$',
'  ))&&----$$%%#+++%%%%%%%%%%%%+#aaaa%%%$$$$$@$$$$@$$$$@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@$$',
'    =>;;--#+%%%%%%%%%%%%%%%%%%==aa****%%$$$%$$$$$$$$$$@$@$@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@##',
'    >>;!--+#%%%%%%%%%%%%%%%%%%==,a-***%%$$%%$$$$$$$@$$$$$@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#+',
'    &&##=>&&#+%%$$$$$$$$$$$$$$***.--&&))$$$$$@%%$$$$$$$$$$@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@$##&&',
'    &&++>>&&+#%%$$$$$$$$$$$$$$.***--&&))$$$$$$%$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$##&&',
'    &&;;#+>>&&%%$$$$@$$$$$$$$$******&&>>--;;$$$$$$$$@$$@$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$%%&&  ',
'    &&;;++=>&&%$$$$$$$$$$$$$$$-*-*.*&&>>--;;$$$$@$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$%%&&  ',
'      ;;++;;&&&&&&&&>>>>&&**.a**----aa**>>%%$%%@                                                ',
'      ;;#+;!&&>&&&&&>>>>&&-*aa.*---&aa**>>%%%#%$                                                ',
'        ##+#>>&&>&&&=>&&&&&&..**--&&****;;%%#$%$$@                                              ',
'        ++##>=&&&&&&>>>&&&&&..**--&&-*-*;;%%#$%$$$$                                             ',
'          %%+#>=&&&&&&&&&&&&****&&&&>>>>#+%%+%#%$$$$@                                           ',
'          %%+#>>&>&&&&&>&&>&*-*-&&&&>>>>++%%+$#%%%$$$@                                          ',
'            +#;;>>&&-*--&&&&***---====    +++%#%##%$$$@                                         ',
'            #+;;>=&&**--&&&&-***--====    ++#######%%$$@                                        ',
'              %%++;;--******--=>              ###%###%$$@                                       ',
'              %%##;;--*****--->>              ##+#####%%$@                                      ',
'                  ;!>>****                      +####+##%$$@                                    ',
'                  ;;>>-*-*                        ++#+##%%%$$@                                  ',
'                                                   ++++!+##%%$                                  ',
'                                                    +!!+!+++%$$@                                ',
'                                                     +!+!!!+#%%$$@                              ',
'                                                      +!+!+!###%$$$                             ',
'                                                       !!!!!++##%%$$@                           ',
'                                                      ;!!!!!!!!+##%$$@                          ',
'                                                         !!!!!!!++#%%$$                         ',
'                                                          ;!!!;!!!+#%%$$@                       ',
'                                                            ;!!;!!!+##$$$@                      ',
'                                                            ;;;!!;!!+##%$$$@                    ',
'                                                              ;;;;;;!++##$%$@@                  ',
'                                                                ;!;!;!!+##%%$$@                 ',
'                                                                 ;;;;!;!++##%%$$@@              ',
'                                                                  ;;;;;!;!+##%%$$$              ',
'                                                                    ;;;;;;!!++#%%%$$            ',
'                                                                     ;;;;;;!!+###%%%            ',
'                                                                      ;;;;;;;!!!++#+%%          ',
'                                                                        =;;;;;;;;!!!%%          ',
'                                                                          =;;;;!;;!;##          ',
'                                                                           ;;;;;=;;!#%          ',
'                                                                              !!!!!!            ',
'                                                                              !!!+!+            ',
'                                                                                                ',
'                                                                                                ',
'                                                                                                ',
'                                                                                                ');

@gl_logo_accesspoint = (
'16 16 129 2',
'  	c None',
'. 	c #020202',
'+ 	c #1AFE02',
'@ 	c #868696',
'# 	c #565656',
'$ 	c #313753',
'% 	c #121226',
'& 	c #FEFEFE',
'* 	c #272E49',
'= 	c #D6E6EE',
'- 	c #202641',
'; 	c #6A7A92',
'> 	c #A6AFBD',
', 	c #48505E',
'" 	c #222226',
') 	c #626A83',
'! 	c #9EA2B2',
'~ 	c #4A4A4E',
'{ 	c #0A0A22',
'] 	c #121A32',
'^ 	c #6A5A6E',
'/ 	c #463A5A',
'( 	c #CCCAD6',
'_ 	c #8E8E96',
': 	c #06061A',
'< 	c #5A6272',
'[ 	c #2E263A',
'} 	c #3E4252',
'| 	c #3A363A',
'1 	c #312E47',
'2 	c #1E1A2A',
'3 	c #373955',
'4 	c #070416',
'5 	c #A29EB4',
'6 	c #4E566C',
'7 	c #5E5A66',
'8 	c #737273',
'9 	c #26262A',
'0 	c #12122D',
'a 	c #727682',
'b 	c #4D5173',
'c 	c #767E96',
'd 	c #423C60',
'e 	c #2A2232',
'f 	c #0E0C0C',
'g 	c #22162A',
'h 	c #434760',
'i 	c #969CAA',
'j 	c #29293C',
'k 	c #524A60',
'l 	c #16162F',
'm 	c #BAB6BE',
'n 	c #393E5D',
'o 	c #9096B8',
'p 	c #2F2E4F',
'q 	c #050311',
'r 	c #22222E',
's 	c #1E1E3A',
't 	c #524E5A',
'u 	c #828292',
'v 	c #6E668E',
'w 	c #4C476E',
'x 	c #6E7086',
'y 	c #5E5A6E',
'z 	c #9593A3',
'A 	c #1A1E37',
'B 	c #282644',
'C 	c #65626A',
'D 	c #62667E',
'E 	c #4E5A76',
'F 	c #272A47',
'G 	c #363154',
'H 	c #B2B2B6',
'I 	c #AAAAAA',
'J 	c #2A324E',
'K 	c #1A1631',
'L 	c #04030A',
'M 	c #201E33',
'N 	c #1A223A',
'O 	c #1E1626',
'P 	c #E6EAF6',
'Q 	c #1A1A22',
'R 	c #3E375A',
'S 	c #16122A',
'T 	c #272242',
'U 	c #191A33',
'V 	c #A6A8BA',
'W 	c #21223F',
'X 	c #222A44',
'Y 	c #0F0D1D',
'Z 	c #A6B2CE',
'` 	c #7C7882',
' .	c #7E809A',
'..	c #494259',
'+.	c #2F2A49',
'@.	c #525E72',
'#.	c #615E7F',
'$.	c #3C3A4E',
'%.	c #261E3E',
'&.	c #787890',
'*.	c #535177',
'=.	c #8389A5',
'-.	c #231A33',
';.	c #394261',
'>.	c #363249',
',.	c #100E2E',
'".	c #3A3A62',
').	c #161230',
'!.	c #8A90A6',
'~.	c #303253',
'{.	c #0E0A22',
'].	c #555679',
'^.	c #534F67',
'/.	c #565872',
'(.	c #4A4E69',
'_.	c #6E626E',
':.	c #7E7E86',
'<.	c #423E68',
'[.	c #464769',
'}.	c #171323',
'|.	c #221E3C',
'1.	c #666A8E',
'2.	c #1E1A34',
'3.	c #4A4266',
'4.	c #2E2645',
'5.	c #110E25',
'6.	c #545A78',
'7.	c #3E3E5E',
'8.	c #8282A6',
'+ + + +           + + +         ',
'+ :.+ +           + 5.+         ',
'+ 8 + +           + . +         ',
'+ 8 + +         + + | +         ',
'+ ~ + + + + + + + + . + +       ',
'+ " + + + + + + + $.W = + +     ',
'& o A . K S K +.3.* J A @.+     ',
'+ ! ~.5.} 2 M D x D 6 X * + +   ',
'+ Z J X }.5.Y T *.#.<.~.B !.+   ',
'+ @ * * s K % 2.h ].b R +.- + + ',
'+ >.v X N K 0 A U F F 2.2 F + + ',
'+ 8 =.s K U ).] s A U R , ) > + ',
'+ + i |.).).0 l A ~.1 }.2 [ j + ',
'+ + t 3 h T q . . . . . . . + + ',
'  + f : 4 . . j + + + + + + +   ',
'  + + + + + + + + + + + +       ');


@gl_logo_accesspoint_wep = (
'16 16 137 2',
'  	c None',
'. 	c #FF0000',
'+ 	c #75717D',
'@ 	c #FF4E4E',
'# 	c #B3161C',
'$ 	c #5C585E',
'% 	c #990000',
'& 	c #555555',
'* 	c #A32224',
'= 	c #7F7F83',
'- 	c #EB3A40',
'; 	c #040407',
'> 	c #66666C',
', 	c #BA3136',
'" 	c #9E1E2E',
') 	c #44455D',
'! 	c #925868',
'~ 	c #D3151B',
'{ 	c #FF6161',
'] 	c #B3B5C6',
'^ 	c #454557',
'/ 	c #141222',
'( 	c #2D2644',
'_ 	c #1F1A36',
': 	c #1D1834',
'< 	c #282243',
'[ 	c #3B3859',
'} 	c #303453',
'| 	c #2A2F4B',
'1 	c #242B47',
'2 	c #6F3448',
'3 	c #E7282D',
'4 	c #AAADC3',
'5 	c #2D3553',
'6 	c #171630',
'7 	c #201E38',
'8 	c #1D1A2D',
'9 	c #151224',
'0 	c #3D3A51',
'a 	c #4F5266',
'b 	c #555C72',
'c 	c #4F5771',
'd 	c #262E49',
'e 	c #30324E',
'f 	c #DC1E23',
'g 	c #8A8CA7',
'h 	c #3D4662',
'i 	c #222942',
'j 	c #191631',
'k 	c #1B162C',
'l 	c #19162B',
'm 	c #24203B',
'n 	c #3F3A5F',
'o 	c #514F75',
'p 	c #46466A',
'q 	c #3A3D5A',
'r 	c #282B47',
's 	c #844658',
't 	c #727087',
'u 	c #5A6078',
'v 	c #252D47',
'w 	c #1A1E38',
'x 	c #201C38',
'y 	c #141228',
'z 	c #1C1834',
'A 	c #3A3A5C',
'B 	c #505377',
'C 	c #4C4B72',
'D 	c #464164',
'E 	c #2C2946',
'F 	c #393A59',
'G 	c #8D4A58',
'H 	c #7C7F99',
'I 	c #242946',
'J 	c #1E233C',
'K 	c #1B1A35',
'L 	c #14122A',
'M 	c #1B1B35',
'N 	c #242643',
'O 	c #2D304F',
'P 	c #292844',
'Q 	c #2E2C4B',
'R 	c #1A1831',
'S 	c #282644',
'T 	c #AC2D3E',
'U 	c #B4333C',
'V 	c #717291',
'W 	c #282643',
'X 	c #1C1B36',
'Y 	c #1A1A35',
'Z 	c #16142B',
'` 	c #15182F',
' .	c #1D203A',
'..	c #1D1E36',
'+.	c #1B1C35',
'@.	c #33324E',
'#.	c #373850',
'$.	c #41455C',
'%.	c #7D8893',
'&.	c #79788B',
'*.	c #353450',
'=.	c #1A1733',
'-.	c #171431',
';.	c #141431',
'>.	c #12122E',
',.	c #161A34',
'".	c #22233C',
').	c #282642',
'!.	c #201E34',
'~.	c #332D46',
'{.	c #424357',
'].	c #403D57',
'^.	c #A21F30',
'/.	c #615C6A',
'(.	c #393950',
'_.	c #2D2C48',
':.	c #242644',
'<.	c #1E2038',
'[.	c #1E1E2C',
'}.	c #0C0C18',
'|.	c #010103',
'1.	c #000000',
'2.	c #010002',
'3.	c #09060E',
'4.	c #6D2630',
'5.	c #8C0C0E',
'6.	c #060411',
'7.	c #09061D',
'8.	c #02010B',
'9.	c #000002',
'0.	c #0A0A0E',
'a.	c #800000',
'b.	c #C00000',
'c.	c #C80909',
'd.	c #800002',
'e.	c #800001',
'f.	c #BF0001',
'. . . .           . . .         ',
'. + @ .           . # .         ',
'. $ @ .           . % .         ',
'. & @ .           . * . .       ',
'. = - . . . . . . . ; . .       ',
'. > , . . . . . . " ) ! ~ .     ',
'{ ] ^ / ( _ : < [ } | 1 2 .     ',
'3 4 5 6 7 8 9 0 a b c d e f .   ',
'. g h i j k l m n o p q r s .   ',
'. t u v w x y z A B C D E F . . ',
'. G H I J K L M N O P Q R S T . ',
'. U V W X Y Z `  ...+.@.#.$.%.. ',
'. . &.*.=.-.;.>.,.".).!.~.{.].^.',
'. . /.(._.:.<.[.}.|.1.1.2.3.4.. ',
'  . 5.6.7.8.9.0.a.a.a.b.. . .   ',
'  . c.d.e.f.. . . . . . . .     ');

@gl_logo_adhoc = (
'16 16 129 2',
'  	c None',
'. 	c #020202',
'+ 	c #1A1A1A',
'@ 	c #7A8282',
'# 	c #AAAEB1',
'$ 	c #E2E6EA',
'% 	c #424242',
'& 	c #D2D6DA',
'* 	c #525252',
'= 	c #5A5A5A',
'- 	c #8E9296',
'; 	c #B6BABC',
'> 	c #666667',
', 	c #FEFEFE',
'" 	c #CACECE',
') 	c #6A6A6A',
'! 	c #8E9AA6',
'~ 	c #66727C',
'{ 	c #FAFAFA',
'] 	c #2A2A2A',
'^ 	c #BABEC2',
'/ 	c #9A9EA2',
'( 	c #868686',
'_ 	c #6E767E',
': 	c #D2DADE',
'< 	c #F2F2F2',
'[ 	c #2E2E2E',
'} 	c #C6CAC6',
'| 	c #A2A6A2',
'1 	c #6E7A84',
'2 	c #AAB6BE',
'3 	c #EEEEEE',
'4 	c #D6DEDE',
'5 	c #C2C6C6',
'6 	c #7A7A7A',
'7 	c #8A8A8A',
'8 	c #7E8284',
'9 	c #363636',
'0 	c #626262',
'a 	c #CECECF',
'b 	c #727E86',
'c 	c #E2EAEE',
'd 	c #A6A6A6',
'e 	c #B2B2B2',
'f 	c #727272',
'g 	c #DEDEDF',
'h 	c #CED2D3',
'i 	c #929292',
'j 	c #828A96',
'k 	c #4A4A4A',
'l 	c #BEC2C2',
'm 	c #A6AAAB',
'n 	c #DEE2E5',
'o 	c #AAB2C2',
'p 	c #969A97',
'q 	c #B2B6B6',
'r 	c #929696',
's 	c #9EA2A4',
't 	c #565656',
'u 	c #C2C2C2',
'v 	c #767E86',
'w 	c #EAEAEA',
'x 	c #AEB2B0',
'y 	c #3A3A3B',
'z 	c #929AA6',
'A 	c #76828A',
'B 	c #D2D2D2',
'C 	c #D6DADE',
'D 	c #767A80',
'E 	c #FAF6F6',
'F 	c #7A8690',
'G 	c #767676',
'H 	c #7A7E7E',
'I 	c #8A8E91',
'J 	c #BABABA',
'K 	c #C6C6C6',
'L 	c #E2E2E2',
'M 	c #6E6E6F',
'N 	c #9EA6B2',
'O 	c #E6EAEE',
'P 	c #E6E6E6',
'Q 	c #828282',
'R 	c #D6D6D6',
'S 	c #8E8E8F',
'T 	c #767E8A',
'U 	c #CACACE',
'V 	c #AEAEAE',
'W 	c #AAAAAB',
'X 	c #464646',
'Y 	c #C6C6CB',
'Z 	c #9A9A9A',
'` 	c #7A828A',
' .	c #DADADA',
'..	c #F6F6F6',
'+.	c #A2A2A2',
'@.	c #DAE2E6',
'#.	c #727A82',
'$.	c #7E868A',
'%.	c #BEC2C7',
'&.	c #DADAE2',
'*.	c #DEDEE6',
'=.	c #C2C2C6',
'-.	c #D6D6DE',
';.	c #A2A6AA',
'>.	c #E6E6EE',
',.	c #E6EAF2',
'".	c #C6CACD',
').	c #B2B2B6',
'!.	c #7A7E86',
'~.	c #B6B6B6',
'{.	c #969697',
'].	c #BEBABE',
'^.	c #D2D2D6',
'/.	c #1E1E1E',
'(.	c #7A828E',
'_.	c #BEBEBE',
':.	c #9E9E9E',
'<.	c #DADEE1',
'[.	c #7E828A',
'}.	c #AEB2B6',
'|.	c #7E7E80',
'1.	c #E2E6EE',
'2.	c #CACED2',
'3.	c #727A86',
'4.	c #626266',
'5.	c #BABABE',
'6.	c #C2C6CA',
'7.	c #76767A',
'8.	c #9A9A9E',
'  . . ` . . . .                 ',
'. . ~ A D K u . . .             ',
'. F A T D J g d . . .           ',
'o 3.T T %.u P K ~.Y . .         ',
'A 3.T #./ , P K d e e . . .     ',
'. (.(.a 3 , L K d ( M ).U . .   ',
'. . 8 G , , g u d ( > k :.).. . ',
'  . ^.B , { g u +.Q > k ] 0  .. ',
'  . . ~.U { g _.+.Q 0 k ] # *.. ',
'    . . h I R _.+.Q > X [ @.$ . ',
'      . . ;.S h :.|.0 % | c # . ',
'        . . D ^." |.0 X & c . . ',
'          . . . & 8.|.{.,.%..   ',
'            . . . ;.# & ,.. .   ',
'                . . . - &..     ',
'                    . . .       ');


@gl_logo_adhoc_wep = (
'16 16 129 2',
'  	c None',
'. 	c #FE0202',
'+ 	c #1A1A1A',
'@ 	c #7A8282',
'# 	c #AAAEB1',
'$ 	c #E2E6EA',
'% 	c #424242',
'& 	c #D2D6DA',
'* 	c #525252',
'= 	c #5A5A5A',
'- 	c #8E9296',
'; 	c #B6BABC',
'> 	c #666667',
', 	c #FEFEFE',
'" 	c #CACECE',
') 	c #6A6A6A',
'! 	c #8E9AA6',
'~ 	c #66727C',
'{ 	c #FAFAFA',
'] 	c #2A2A2A',
'^ 	c #BABEC2',
'/ 	c #9A9EA2',
'( 	c #868686',
'_ 	c #6E767E',
': 	c #D2DADE',
'< 	c #F2F2F2',
'[ 	c #2E2E2E',
'} 	c #C6CAC6',
'| 	c #A2A6A2',
'1 	c #6E7A84',
'2 	c #AAB6BE',
'3 	c #EEEEEE',
'4 	c #D6DEDE',
'5 	c #C2C6C6',
'6 	c #7A7A7A',
'7 	c #8A8A8A',
'8 	c #7E8284',
'9 	c #363636',
'0 	c #626262',
'a 	c #CECECF',
'b 	c #727E86',
'c 	c #E2EAEE',
'd 	c #A6A6A6',
'e 	c #B2B2B2',
'f 	c #727272',
'g 	c #DEDEDF',
'h 	c #CED2D3',
'i 	c #929292',
'j 	c #828A96',
'k 	c #4A4A4A',
'l 	c #BEC2C2',
'm 	c #A6AAAB',
'n 	c #DEE2E5',
'o 	c #AAB2C2',
'p 	c #969A97',
'q 	c #B2B6B6',
'r 	c #929696',
's 	c #9EA2A4',
't 	c #565656',
'u 	c #C2C2C2',
'v 	c #767E86',
'w 	c #EAEAEA',
'x 	c #AEB2B0',
'y 	c #3A3A3B',
'z 	c #929AA6',
'A 	c #76828A',
'B 	c #D2D2D2',
'C 	c #D6DADE',
'D 	c #767A80',
'E 	c #FAF6F6',
'F 	c #7A8690',
'G 	c #767676',
'H 	c #7A7E7E',
'I 	c #8A8E91',
'J 	c #BABABA',
'K 	c #C6C6C6',
'L 	c #E2E2E2',
'M 	c #6E6E6F',
'N 	c #9EA6B2',
'O 	c #E6EAEE',
'P 	c #E6E6E6',
'Q 	c #828282',
'R 	c #D6D6D6',
'S 	c #8E8E8F',
'T 	c #767E8A',
'U 	c #CACACE',
'V 	c #AEAEAE',
'W 	c #AAAAAB',
'X 	c #464646',
'Y 	c #C6C6CB',
'Z 	c #9A9A9A',
'` 	c #7A828A',
' .	c #DADADA',
'..	c #F6F6F6',
'+.	c #A2A2A2',
'@.	c #DAE2E6',
'#.	c #727A82',
'$.	c #7E868A',
'%.	c #BEC2C7',
'&.	c #DADAE2',
'*.	c #DEDEE6',
'=.	c #C2C2C6',
'-.	c #D6D6DE',
';.	c #A2A6AA',
'>.	c #E6E6EE',
',.	c #E6EAF2',
'".	c #C6CACD',
').	c #B2B2B6',
'!.	c #7A7E86',
'~.	c #B6B6B6',
'{.	c #969697',
'].	c #BEBABE',
'^.	c #D2D2D6',
'/.	c #1E1E1E',
'(.	c #7A828E',
'_.	c #BEBEBE',
':.	c #9E9E9E',
'<.	c #DADEE1',
'[.	c #7E828A',
'}.	c #AEB2B6',
'|.	c #7E7E80',
'1.	c #E2E6EE',
'2.	c #CACED2',
'3.	c #727A86',
'4.	c #626266',
'5.	c #BABABE',
'6.	c #C2C6CA',
'7.	c #76767A',
'8.	c #9A9A9E',
'  . . ` . . . .                 ',
'. . ~ A D K u . . .             ',
'. F A T D J g d . . .           ',
'o 3.T T %.u P K ~.Y . .         ',
'A 3.T #./ , P K d e e . . .     ',
'. (.(.a 3 , L K d ( M ).U . .   ',
'. . 8 G , , g u d ( > k :.).. . ',
'  . ^.B , { g u +.Q > k ] 0  .. ',
'  . . ~.U { g _.+.Q 0 k ] # *.. ',
'    . . h I R _.+.Q > X [ @.$ . ',
'      . . ;.S h :.|.0 % | c # . ',
'        . . D ^." |.0 X & c . . ',
'          . . . & 8.|.{.,.%..   ',
'            . . . ;.# & ,.. .   ',
'                . . . - &..     ',
'                    . . .       ');

@gl_logo_network_broadcasting = (
'16 16 2 1',
' 	c None',
'.	c #00FF04',
'    .......     ',
'   ..........   ',
'  ..       ...  ',
' ..   ....   .  ',
' .   ......  .. ',
'..  ..   ...  . ',
'.  ..      .. . ',
'.  .  ...  .. ..',
'.  .  . ..  . ..',
'.  .  . ..  . . ',
'.. .. . .. .  . ',
'..  ...  ...  . ',
' .. ...  ... .  ',
'  .....  .....  ',
'   ....  ....   ',
'    ...  ..     ');

@gl_logo_network_nonbroadcasting = (
'16 16 2 1',
' 	c None',
'.	c #FF0000',
'    .......     ',
'   ..........   ',
'  ..       ...  ',
' ..   ....   .  ',
' .   ......  .. ',
'..  ..   ...  . ',
'.  ..      .. . ',
'.  .  ...  .. ..',
'.  .  . ..  . ..',
'.  .  . ..  . . ',
'.. .. . .. .  . ',
'..  ...  ...  . ',
' .. ...  ... .  ',
'  .....  .....  ',
'   ....  ....   ',
'    ...  ..     ');

@gl_logo_encrypted = 
( '16 16 17 1',
' 	c None',
'.	c #322516',
'+	c #BF6F0E',
'b	c #D59220',
'#	c #C3CBCE',
'a	c #FDEF4F',
'%	c #601907',
'&	c #ACB1B1',
'*	c #F7D944',
'=	c #603406',
'-	c #984802',
';	c #ACA894',
'>	c #828686',
',	c #ECB114',
'd	c #DCE2E2',
')	c #7B4104',
'!	c #444A4A',
'    #dd>        ',
'  ddd>&d#       ',
' #d&!  >d#      ',
' dd!    ##.     ',
' dd.    ;&.     ',
' d#.    &&.     ',
' ##)    ;>%     ',
',a*aa,bb-)=.    ',
',aaa**,+--)%    ',
',aa**,b+)===    ',
',aa*,b+-)===    ',
',a*,b+-)=.==    ',
',a*b++)==.==    ',
'ba,b+--===%%    ',
' )-))=%%%%%     ',
'                ');


@gl_nowep = (
'16 16 17 1',
' 	c None',
'.	c #120202',
'+	c #625E62',
'@	c #E2920A',
'#	c #B2B6B6',
'$	c #FCE950',
'%	c #954C03',
'&	c #A2A9A9',
'*	c #CA7602',
'=	c #621606',
'-	c #EEB716',
';	c #424646',
'>	c #AEA29A',
',	c #4A2E02',
'a	c #D9DDDD',
')	c #8B8A8A',
'!	c #6B3605',
'    aaaaaa      ',
'    aa&&)aa     ',
'   aa>+  )&#    ',
'   a&;    #a+   ',
'   &)     aa+   ',
'          a&;   ',
'         >)+    ',
'-$$$$--@%!!,    ',
'-$$$$--**!!!    ',
'-$$$$-@*%!!!    ',
'-$$$--*%%!!!    ',
'-$$-@*%!,,,!    ',
'-$-@*%%!!,,!    ',
'@$-@*%%!,,!!    ',
' %%%!!=====.    ',
'                ');

@gl_wireless_card_icon = (
'16 16 17 1',
' 	c None',
'.	c #040404',
'+	c #1C1B1B',
'@	c #5C5757',
'#	c #067E0A',
'$	c #A8A1A4',
'%	c #AAB2BA',
'&	c #C9C5CC',
'*	c #6E6666',
'=	c #CFD1D8',
'-	c #726A6A',
';	c #D6D8E1',
'>	c #12100F',
',	c #4A2A12',
'a	c #928B8F',
')	c #BBBABF',
'!	c #D9E0E8',
'                ',
'                ',
'           %;)  ',
'         $);;&  ',
'       a);!!!;& ',
'     $&;!!&);;= ',
' >>>a=!!=))=%!; ',
'>...@&!=)%$;;;=$',
'>#...$;$a)!;&%@ ',
' ,>..@=!!!&$*   ',
' >...>%;=$@     ',
' +....@)*,      ',
'  >..+>@        ',
'  ++>           ',
'                ',
'                ');




@gl_accesspoint_icon = (
'16 16 17 1',
' 	c None',
'.	c #020202',
'+	c #4AAA2E',
'@	c #312A2A',
'#	c #090808',
'$	c #CE6636',
'%	c #1C1A1A',
'&	c #2E5622',
'*	c #2C2322',
'=	c #0F0F0E',
'-	c #393939',
';	c #262626',
'>	c #181616',
',	c #261F1F',
'a	c #201E1E',
')	c #161210',
'!	c #352F2F',
'                ',
'                ',
'            %   ',
'  .         .   ',
'  .         .   ',
'  .         .   ',
'  .         .   ',
'  .         .   ',
' ;========)===; ',
'-aaaa%%%%$,%+&)!',
'@!@@@*,%>)==#..=',
'@!@@*,%%>)=##..#',
'-*%%%a%%%>%>%>%-',
'                ',
'                ',
'                ');






####################################
### The logo in xpm format    #####
### Dont change anything      ####
#################################

@gl_logo = ( "250 175 565 2",
'  	c None',
'. 	c #FFFFFF',
'+ 	c #FBFAF5',
'@ 	c #F4F2E7',
'# 	c #EDEAD8',
'$ 	c #E7E2C9',
'% 	c #DFD8B7',
'& 	c #D6CDA3',
'* 	c #CEC493',
'= 	c #C7BC83',
'- 	c #C0B373',
'; 	c #B9AA63',
'> 	c #FEFEFD',
', 	c #B3A356',
'` 	c #FDFDFB',
') 	c #FFFEFE',
'! 	c #AD9D49',
'~ 	c #FCFBF8',
'{ 	c #A8973F',
'] 	c #A59237',
'^ 	c #F9F8F2',
'/ 	c #FCFCF9',
'( 	c #A18E2F',
'_ 	c #F8F7EF',
': 	c #FBFBF7',
'< 	c #9D8926',
'[ 	c #F6F4EA',
'} 	c #9A851E',
'| 	c #F3F0E4',
'1 	c #FAF9F3',
'2 	c #98831A',
'3 	c #EEEBDA',
'4 	c #F9F8F1',
'5 	c #968117',
'6 	c #EAE6D0',
'7 	c #FEFDFC',
'8 	c #FDFCFA',
'9 	c #F8F7F0',
'0 	c #F8F6EE',
'a 	c #957F14',
'b 	c #E6E1C7',
'c 	c #F6F4EB',
'd 	c #F1EEDF',
'e 	c #937D10',
'f 	c #E3DDC1',
'g 	c #E8E3CC',
'h 	c #F5F3EA',
'i 	c #F1EFE1',
'j 	c #927B0C',
'k 	c #E0D9BA',
'l 	c #E5E0C5',
'm 	c #E1DABC',
'n 	c #F2EFE2',
'o 	c #907A09',
'p 	c #DDD6B3',
'q 	c #D7CEA5',
'r 	c #EFEBDB',
's 	c #8F7907',
't 	c #D9D1AA',
'u 	c #D0C797',
'v 	c #EBE7D3',
'w 	c #8F7806',
'x 	c #D4CCA0',
'y 	c #DAD2AC',
'z 	c #CCC18D',
'A 	c #CFC595',
'B 	c #E2DCBE',
'C 	c #E7E2CA',
'D 	c #FBFAF6',
'E 	c #D3CA9C',
'F 	c #EBE7D2',
'G 	c #E6E0C6',
'H 	c #CBC18C',
'I 	c #CCC28F',
'J 	c #F2F0E3',
'K 	c #D5CCA1',
'L 	c #E3DEC1',
'M 	c #C7BB82',
'N 	c #BAAC67',
'O 	c #E6E1C8',
'P 	c #F0ECDD',
'Q 	c #BEB06E',
'R 	c #E1DBBD',
'S 	c #C2B678',
'T 	c #B3A355',
'U 	c #E8E3CB',
'V 	c #AC9A45',
'W 	c #DFD9B9',
'X 	c #BDB06D',
'Y 	c #AE9D4A',
'Z 	c #FAF9F4',
'` 	c #DAD3AD',
' .	c #DDD6B4',
'..	c #B7A960',
'+.	c #BBAD69',
'@.	c #F0EDDE',
'#.	c #B1A152',
'$.	c #E9E5CE',
'%.	c #DBD3AE',
'&.	c #D1C899',
'*.	c #E5DFC4',
'=.	c #D2C89A',
'-.	c #D8D0A8',
';.	c #AF9F4D',
'>.	c #BDAF6C',
',.	c #D9D1AB',
'`.	c #F4F2E8',
').	c #E4DFC3',
'!.	c #AC9B46',
'~.	c #A7953B',
'{.	c #D8D0A9',
'].	c #DCD5B2',
'^.	c #A18E2E',
'/.	c #A99841',
'(.	c #968016',
'_.	c #EEEAD9',
':.	c #937C0E',
'<.	c #CDC391',
'[.	c #A6943A',
'}.	c #EAE6D1',
'|.	c #957F13',
'1.	c #C8BD85',
'2.	c #F5F3E9',
'3.	c #917A0A',
'4.	c #CABF8A',
'5.	c #A39032',
'6.	c #D7CFA7',
'7.	c #9E8A27',
'8.	c #DFD8B8',
'9.	c #9A851D',
'0.	c #C8BC84',
'a.	c #9F8B29',
'b.	c #C1B475',
'c.	c #AE9E4B',
'd.	c #F7F5EC',
'e.	c #ECE8D4',
'f.	c #A8963D',
'g.	c #B7A85E',
'h.	c #C5B97D',
'i.	c #9B8721',
'j.	c #A99740',
'k.	c #C6BB81',
'l.	c #9F8C2A',
'm.	c #99841B',
'n.	c #CDC390',
'o.	c #C2B576',
'p.	c #E2DDC0',
'q.	c #E9E5CF',
'r.	c #9C8823',
's.	c #C5BA7F',
't.	c #F3F1E5',
'u.	c #968015',
'v.	c #917B0B',
'w.	c #A7953C',
'x.	c #E0DABB',
'y.	c #978218',
'z.	c #E4DEC2',
'A.	c #D6CEA4',
'B.	c #BAAC66',
'C.	c #937D0F',
'D.	c #DCD5B1',
'E.	c #EDE9D7',
'F.	c #D0C696',
'G.	c #ECE8D5',
'H.	c #B0A050',
'I.	c #B8A961',
'J.	c #C9BE87',
'K.	c #DED7B6',
'L.	c #B2A253',
'M.	c #B5A65B',
'N.	c #B2A254',
'O.	c #947E11',
'P.	c #A39033',
'Q.	c #C3B679',
'R.	c #BAAB65',
'S.	c #DED7B5',
'T.	c #9D8824',
'U.	c #9E8B28',
'V.	c #A08D2C',
'W.	c #907908',
'X.	c #F7F5ED',
'Y.	c #BCAE6A',
'Z.	c #9D8925',
'`.	c #B7A85F',
' +	c #927C0D',
'.+	c #A59338',
'++	c #B9AB64',
'@+	c #A08C2B',
'#+	c #CEC492',
'$+	c #C4B87C',
'%+	c #AC9B47',
'&+	c #C9BE88',
'*+	c #C2B577',
'=+	c #AB9A44',
'-+	c #C0B372',
';+	c #DBD4B0',
'>+	c #A49134',
',+	c #F1EEE0',
'`+	c #C6BA80',
')+	c #D4CB9F',
'!+	c #D4CB9E',
'~+	c #E9E4CD',
'{+	c #947E12',
']+	c #BEB16E',
'^+	c #99841C',
'/+	c #CCC28E',
'(+	c #EDE9D6',
'_+	c #B3A457',
':+	c #9B8620',
'<+	c #C4B87B',
'[+	c #AD9C48',
'}+	c #F4F1E6',
'|+	c #BBAD68',
'1+	c #A69439',
'2+	c #B1A151',
'3+	c #DBD4AF',
'4+	c #C9BD86',
'5+	c #C1B474',
'6+	c #A49135',
'7+	c #D2C99B',
'8+	c #CBC08B',
'9+	c #BCAF6B',
'0+	c #B09F4E',
'a+	c #9A861F',
'b+	c #B0A04F',
'c+	c #AF9E4C',
'd+	c #A28F31',
'e+	c #A8963E',
'f+	c #C5B97E',
'g+	c #AA9943',
'h+	c #D5CDA2',
'i+	c #BEB16F',
'j+	c #A28F30',
'k+	c #B4A458',
'l+	c #B5A65A',
'm+	c #D7CFA6',
'n+	c #BFB270',
'o+	c #A18D2D',
'p+	c #D1C798',
'q+	c #AB9944',
'r+	c #978219',
's+	c #C3B77A',
't+	c #BFB271',
'u+	c #AA9842',
'v+	c #B8AA62',
'w+	c #98831B',
'x+	c #CFC594',
'y+	c #A59236',
'z+	c #D0C697',
'A+	c #B4A559',
'B+	c #EFECDC',
'C+	c #CABF89',
'D+	c #D3CA9D',
'E+	c #9C8722',
'F+	c #B6A75C',
'G+	c #E2DCBF',
'H+	c #F7F7F7',
'I+	c #E4E4E4',
'J+	c #C8C8C8',
'K+	c #AFAFAF',
'L+	c #9F9F9F',
'M+	c #8F8F8F',
'N+	c #7F7F7F',
'O+	c #757575',
'P+	c #6E6E6E',
'Q+	c #6B6B6B',
'R+	c #6D6D6D',
'S+	c #717171',
'T+	c #797979',
'U+	c #878787',
'V+	c #989898',
'W+	c #A7A7A7',
'X+	c #BBBBBB',
'Y+	c #DADADA',
'Z+	c #F0F0F0',
'`+	c #FEFEFE',
' @	c #B6A75D',
'.@	c #E3E3E3',
'+@	c #B3B3B3',
'@@	c #808080',
'#@	c #575757',
'$@	c #2D2D2D',
'%@	c #0E0E0E',
'&@	c #060606',
'*@	c #010101',
'=@	c #000000',
'-@	c #040404',
';@	c #0A0A0A',
'>@	c #1F1F1F',
',@	c #494949',
'`@	c #A5A5A5',
')@	c #D5D5D5',
'!@	c #FDFDFD',
'~@	c #E6E6E6',
'{@	c #A3A3A3',
']@	c #616161',
'^@	c #272727',
'/@	c #020202',
'(@	c #1C1C1C',
'_@	c #545454',
':@	c #999999',
'<@	c #E0E0E0',
'[@	c #D7D7D7',
'}@	c #828282',
'|@	c #353535',
'1@	c #2F2F2F',
'2@	c #818181',
'3@	c #D9D9D9',
'4@	c #E5E5E5',
'5@	c #8D8D8D',
'6@	c #323232',
'7@	c #292929',
'8@	c #666666',
'9@	c #444444',
'0@	c #232323',
'a@	c #0B0B0B',
'b@	c #383838',
'c@	c #EDEDED',
'd@	c #FBFBFB',
'e@	c #BEBEBE',
'f@	c #565656',
'g@	c #080808',
'h@	c #242424',
'i@	c #BCBCBC',
'j@	c #F3F3F3',
'k@	c #CCCCCC',
'l@	c #6A6A6A',
'm@	c #333333',
'n@	c #090909',
'o@	c #101010',
'p@	c #6C6C6C',
'q@	c #F6F6F6',
'r@	c #161616',
's@	c #050505',
't@	c #868686',
'u@	c #E8E8E8',
'v@	c #646464',
'w@	c #1D1D1D',
'x@	c #555555',
'y@	c #F4F4F4',
'z@	c #949494',
'A@	c #1E1E1E',
'B@	c #B9B9B9',
'C@	c #5A5A5A',
'D@	c #F8F8F8',
'E@	c #C1C1C1',
'F@	c #1A1A1A',
'G@	c #515151',
'H@	c #CECECE',
'I@	c #9D9D9D',
'J@	c #B2B2B2',
'K@	c #F5F5F5',
'L@	c #FCFCFC',
'M@	c #686868',
'N@	c #F1F1F1',
'O@	c #A6A6A6',
'P@	c #3F3F3F',
'Q@	c #070707',
'R@	c #626262',
'S@	c #DFDFDF',
'T@	c #B1B1B1',
'U@	c #2C2C2C',
'V@	c #191919',
'W@	c #7C7C7C',
'X@	c #8C8C8C',
'Y@	c #050000',
'Z@	c #460101',
'`@	c #860303',
' #	c #A40606',
'.#	c #CD0303',
'+#	c #AC0303',
'@#	c #850202',
'##	c #520101',
'$#	c #969696',
'%#	c #CBCBCB',
'&#	c #838383',
'*#	c #D0D0D0',
'=#	c #464646',
'-#	c #212121',
';#	c #959595',
'>#	c #040000',
',#	c #5C0606',
'`#	c #C10C0C',
')#	c #B80303',
'!#	c #570101',
'~#	c #0D0D0D',
'{#	c #D2D2D2',
']#	c #606060',
'^#	c #262626',
'/#	c #707070',
'(#	c #202020',
'_#	c #130101',
':#	c #A81F1F',
'<#	c #960202',
'[#	c #140000',
'}#	c #3E3E3E',
'|#	c #D3D3D3',
'1#	c #535353',
'2#	c #E2E2E2',
'3#	c #121212',
'4#	c #A2A2A2',
'5#	c #190707',
'6#	c #C61B1B',
'7#	c #AE0303',
'8#	c #ACACAC',
'9#	c #0F0F0F',
'0#	c #727272',
'a#	c #2B2B2B',
'b#	c #090707',
'c#	c #C53C3C',
'd#	c #9A9A9A',
'e#	c #3A3A3A',
'f#	c #474747',
'g#	c #A85C5C',
'h#	c #C6C6C6',
'i#	c #E9E9E9',
'j#	c #7B7B7B',
'k#	c #BABABA',
'l#	c #2A2A2A',
'm#	c #A8A8A8',
'n#	c #423E3E',
'o#	c #D21C1C',
'p#	c #120000',
'q#	c #030303',
'r#	c #EEEEEE',
's#	c #C27E7E',
't#	c #484848',
'u#	c #CDCDCD',
'v#	c #6F6F6F',
'w#	c #0C0C0C',
'x#	c #FAFAFA',
'y#	c #DF6868',
'z#	c #920202',
'A#	c #CACACA',
'B#	c #D83A3A',
'C#	c #B90303',
'D#	c #C0C0C0',
'E#	c #181818',
'F#	c #313131',
'G#	c #858585',
'H#	c #D1D1D1',
'I#	c #9B9B9B',
'J#	c #A1A1A1',
'K#	c #5F5F5F',
'L#	c #171717',
'M#	c #8A8A8A',
'N#	c #929292',
'O#	c #3D3D3D',
'P#	c #DDDDDD',
'Q#	c #B4B4B4',
'R#	c #9C9C9C',
'S#	c #131313',
'T#	c #EAEAEA',
'U#	c #E16A6A',
'V#	c #4E4E4E',
'W#	c #4D4D4D',
'X#	c #EEA9A9',
'Y#	c #5C5C5C',
'Z#	c #303030',
'`#	c #151515',
' $	c #A0A0A0',
'.$	c #111111',
'+$	c #E0DBDB',
'@$	c #D21D1D',
'#$	c #C40303',
'$$	c #1B1B1B',
'%$	c #7E7E7E',
'&$	c #4A4A4A',
'*$	c #EA9494',
'=$	c #630101',
'-$	c #343434',
';$	c #676767',
'>$	c #EFEFEF',
',$	c #CECACA',
'`$	c #DB4747',
')$	c #970404',
'!$	c #A4A4A4',
'~$	c #979797',
'{$	c #282828',
']$	c #E6D2D2',
'^$	c #D52A2A',
'/$	c #B30808',
'($	c #E1E1E1',
'_$	c #E3D1D1',
':$	c #DD5454',
'<$	c #AD0D0D',
'[$	c #F9F9F9',
'}$	c #B8B7B7',
'|$	c #ECA0A0',
'1$	c #CA1515',
'2$	c #681212',
'3$	c #4F4F4F',
'4$	c #BBB7B7',
'5$	c #EAA5A5',
'6$	c #DE5B5B',
'7$	c #D52C2C',
'8$	c #D11B1B',
'9$	c #C63636',
'0$	c #7B2B2B',
'a$	c #070202',
'b$	c #888888',
'c$	c #525252',
'd$	c #B6B6B6',
'e$	c #ECECEC',
'f$	c #3B3B3B',
'g$	c #424242',
'h$	c #8B8B8B',
'i$	c #E7E7E7',
'j$	c #ADADAD',
'k$	c #373737',
'l$	c #919191',
'm$	c #777777',
'n$	c #5D5D5D',
'o$	c #3C3C3C',
'p$	c #141414',
'q$	c #7A7A7A',
'r$	c #737373',
's$	c #2E2E2E',
't$	c #EBEBEB',
'u$	c #B7B7B7',
'v$	c #5E5E5E',
'w$	c #585858',
'x$	c #BDBDBD',
'y$	c #9E9E9E',
'z$	c #DEDEDE',
'A$	c #C5C5C5',
'B$	c #F2F2F2',
'C$	c #C2C2C2',
'D$	c #B8B8B8',
'E$	c #4C4C4C',
'F$	c #C3C3C3',
'G$	c #595959',
'H$	c #DCDCDC',
'I$	c #5B5B5B',
'J$	c #C7C7C7',
'K$	c #CFCFCF',
'L$	c #656565',
'M$	c #252525',
'N$	c #B5B5B5',
'O$	c #D4D4D4',
'P$	c #393939',
'Q$	c #636363',
'R$	c #7D7D7D',
'S$	c #8E8E8E',
'T$	c #747474',
'U$	c #848484',
'V$	c #222222',
'W$	c #BFBFBF',
'X$	c #DBDBDB',
'Y$	c #404040',
'Z$	c #939393',
'`$	c #4B4B4B',
' %	c #C9C9C9',
'.%	c #D8D8D8',
'+%	c #AAAAAA',
'@%	c #787878',
'#%	c #767676',
'$%	c #B0B0B0',
'%%	c #A9A9A9',
'&%	c #C4C4C4',
'*%	c #AEAEAE',
'=%	c #505050',
'-%	c #D6D6D6',
';%	c #898989',
'>%	c #696969',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . + . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . @ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . # . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . $ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . % . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . & . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . * . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . = . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . - . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ; > . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . , ` . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ) ! ~ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . > { + . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ` ] ^ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . / ( _ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . : < [ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . + } | . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 1 2 3 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 4 5 6 . . . . . . . . . . . . . . 7 8 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 9 . . . . . . . . . . . . . . . 0 a b . . . . . . . . . . . . . . c : . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . d / . . . . . . . . . . . . . . c e f . . . . . . . . . . . . . . g ) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . h i . . . . . . . . . . . . . . @ j k . . . . . . . . . . . . . . l . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . > m . . . . . . . . . . . . . . n o p . . . . . . . . . . . . . . p . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . q . . . . . . . . . . . . . . r s t . . . . . . . . . . . . . 7 q . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . u . . . . . . . . . . . . . . v w x . . . . . . . . . . . . . @ y . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . z / . . . . . . . . . . . . . g w A . . . . . . . . . . . . . B C . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . : D . . . . . . . . . . . . E F . . . . . . . . . . . . . G w H . . . . . . . . . . . . . I J . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ) r . . . . . . . . . . . . f K . . . . . . . . . . . . . L w M . . . . . . . . . . . . . N / . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . O ) . . . . . . . . . . . P Q . . . . . . . . . . . . . R w S . . . . . . . . . . . . . T . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . U @ . . . . . . . . . . . : V . . . . . . . . . . . . . W w X . . . . . . . . . . . . ^ Y . . . . . . . . . . . . ` 7 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . Z ` . . . . . . . . . . . . ] D . . . . . . . . . . . .  .w ... . . . . . . . . . . . $ +.. . . . . . . . . . . . @.) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . I > . . . . . . . . . . . #.$.. . . . . . . . . . . . %.w , . . . . . . . . . . . . &.z . . . . . . . . . . . . *.. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . E @.. . . . . . . . . . . Q =.. . . . . . . . . . . . -.w ;.. . . . . . . . . . . . >.,.. . . . . . . . . . . `.).. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 3 * . . . . . . . . . . . A N . . . . . . . . . . . . x w !.. . . . . . . . . . . . ~.G . . . . . . . . . . . {.[ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 7 ..7 . . . . . . . . . . ].^.. . . . . . . . . . . . u w /.. . . . . . . . . . . ~ (.@ . . . . . . . . . . ) = . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . > ) . . . . . . . . . . . X _.. . . . . . . . . . v :._ . . . . . . . . . . . <.w [.. . . . . . . . . . . }.|.> . . . . . . . . . . @ 1.. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ` 2.. . . . . . . . . . . ` M . . . . . . . . . . Z 3.L . . . . . . . . . . . 4.w 5.) . . . . . . . . . . 6.7.. . . . . . . . . . . &.8.. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 6 > . . . . . . . . . . 2.] 7 . . . . . . . . . ) 9.<.. . . . . . . . . . . 0.w a.` . . . . . . . . . . b.Y . . . . . . . . . . ) c.d.. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . @ e.. . . . . . . . . . . f.$.. . . . . . . . . . { g.. . . . . . . . . . . h.w i.~ . . . . . . . . . . Y +.. . . . . . . . . . i j.. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . -.) . . . . . . . . . . k.b.. . . . . . . . . . ; l.) . . . . . . . . . . b.w m.+ . . . . . . . . . ` m.= . . . . . . . . . . n.o.. . . . . . . . . . . . ) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . p.q.. . . . . . . . . . *.r.` . . . . . . . . . s.j t.. . . . . . . . . . Q w u.^ . . . . . . . . . n v.q . . . . . . . . . ) w.x.. . . . . . . . . . . > 2.. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 8 0.) . . . . . . . . . D y.z.. . . . . . . . . A.w k . . . . . . . . . . B.w C.0 . . . . . . . . . D.w l . . . . . . . . . r C.d.. . . . . . . . . . . E.1 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . F.G.. . . . . . . . . . H.>.. . . . . . . . . U w 1.. . . . . . . . . . I.w o 2.. . . . . . . . . M w d . . . . . . . . . J.~.. . . . . . . . . . . > K.. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . @ Q ) . . . . . . . . . &.9.: . . . . . . . . `.s L.. . . . . . . . . . M.w s n . . . . . . . . . N.O.: . . . . . . . . ) P.Q.. . . . . . . . . . . l v . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ` . . . . . . . . . . . . R.r . . . . . . . . . 3 s S.. . . . . . . . / 5 T.7 . . . . . . . . . , w w r . . . . . . . . ) U.V.> . . . . . . . . G.W. .. . . . . . . . . . 7 M ) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 9 X.. . . . . . . . . . . ).Y.. . . . . . . . . ) Z.`.. . . . . . . . ) ] j d . . . . . . . . . #.w w G.. . . . . . . . `.C.Y . . . . . . . . . h. +4 . . . . . . . . . . p.{.. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . O 7 . . . . . . . . . . 7 .+d . . . . . . . . . +.5 ^ . . . . . . . . L.w S.. . . . . . . . . ;.w w $.. . . . . . . . L w ++. . . . . . . . 7 @+~.. . . . . . . . . . > g.1 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . X.R . . . . . . . . . . . #+Q . . . . . . . . . y w -.. . . . . . . . b.w $+. . . . . . . . . %+w w G . . . . . . . . #+w &+. . . . . . . . C W.*+. . . . . . . . . . x.o.. . . . . . . . . . 7 ) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . D.J . . . . . . . . . . 0 m.t.. . . . . . . . 2.v.#.. . . . . . . . &.w ! . . . . . . . . . /.w w m . . . . . . . . g.w & . . . . . . . . *+w % . . . . . . . . . ) =+e.. . . . . . . . . . 3 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . / 1.> . . . . . . . . . . ++-+. . . . . . . . ) { |.h . . . . . . . K.w 9.D . . . . . . . . [.w w ;+. . . . . . . ) >+w f . . . . . . . 8 T.j d.. . . . . . . . . W %+. . . . . . . . . . e.,+. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . W q . . . . . . . . . . G |.@ . . . . . . . . `+w )+. . . . . . . 3 w 3.r . . . . . . . ) 5.w w A.. . . . . . . X.|.s i . . . . . . . z.s ] ) . . . . . . . . ) f.{.. . . . . . . . . : !+. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . B.| . . . . . . . . . > >+Q.. . . . . . . . L w V . . . . . . . Z a w 6.. . . . . . . > @+w w &.. . . . . . . ~+s {++ . . . . . . . ]+w S . . . . . . . . . S.^+: . . . . . . . . . /+t.. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . (+_+) . . . . . . . . . &.(.`.. . . . . . . + 5 :.,+. . . . . . ` l.w S . . . . . . . 8 Z.w w <.. . . . . . . E w Z.` . . . . . . Z :+w S.. . . . . . . . 7 .+<+. . . . . . . . . ~+0.. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 8 . . . . . . . . . . . . . - K . . . . . . . . . 0 u.`+. . . . . . . . N.w * . . . . . . . [+w { ) . . . . . . ~ :+w w 4.. . . . . . . -+w V . . . . . . . W s  +X.. . . . . . . . ].3.r . . . . . . . . : !.X.. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . }+^ . . . . . . . . . . . . c l.n . . . . . . . . . N 2 h . . . . . . . F.w { ) . . . . . . X w 2 1 . . . . . . + m.w w 0.. . . . . . . /.w |+. . . . . . . R.w 1+> . . . . . . . ` 1+%+. . . . . . . . . `+H . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ) p.+ . . . . . . . . . . . . * 2+7 . . . . . . . . g W.0.. . . . . . . # W.j E.. . . . . . 4.w s q.. . . . . . 1 y.w w $+. . . . . . D 9.w 1.. . . . . . ^ 9.w - . . . . . . . . y s 3+. . . . . . . . $ U.Z . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ~ K ` . . . . . . . . . . . : ( !+. . . . . . . . 7 w.9.X.. . . . . . 8 l.w 4+. . . . . . y w w K . . . . . . 9 a w w 5+. . . . . . (+o w )+. . . . . . S.w w K.. . . . . . . 8 ] :+: . . . . . . . + 6+&.. . . . . . . . . . . . . . > . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . t.#+) . . . . . . . . . . . ;+2 ,+. . . . . . . . 7+w 8+. . . . . . . N w >+` . . . . . 6 w w 9+. . . . . . X.C.w w Y.. . . . . . ` w w *.. . . . . . M.w :.[ . . . . . . . {.s $+. . . . . . . . $+^.~ . . . . . . . . . . . . . t.0 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . f A . . . . . . . . . . . 7 Y 0+7 . . . . . . . 0 2 :+9 . . . . . . %.w o 6 . . . . . `.v.w f.) . . . . . h v.w w `.. . . . . . <+w s P . . . . . _ y.w [.> . . . . . . / P.j 3 . . . . . . . O  +-.. . . . . . . . . . . . . ,+L . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 8+{.. . . . . . . . . . . g  +)+. . . . . . . . Q w #+. . . . . . @ e w Q.. . . . . : a+w |.X.. . . . . t.W.w w T . . . . . . b+w {+9 . . . . . ,.w w 5+. . . . . . . -.s 0+) . . . . . . 1 P.] 8 . . . . . . . . . . . . `.z > . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . > , B . . . . . . . . . . ) |+y.d . . . . . . . $.o i.^ . . . . . > ~.w a./ . . . . . w.w w $ . . . . . ,+s w w c+. . . . . ~ T.w a.` . . . . . N.w w ;+. . . . . . ~ d+w ;+. . . . . . . <+s 8.. . . . . . . . . . . . 0 ..^ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . c ] ~+. . . . . . . . . . | 5 ;.` . . . . . . > e+w F.. . . . . . f+w w l . . . . . _+w w * . . . . . r w w w g+. . . . . }+j w g+. . . . . h |.w O.h . . . . . . & w T.D . . . . . . l  +=+7 . . . . . . . . . . . 1 c+F . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . l @+@.. . . . . . . . . . 1.w =.. . . . . . . h+w U.D . . . . . L w w i+. . . . . f+w w ++. . . . . E.w w w ] ) . . . . W w w g.. . . . . h+w w .+> . . . . . : ^.w k.. . . . . . 1 5.o ).. . . . . . . . . . . : ;.u . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . d.> . . . . . . . . . . . . . * ( 2.. . . . . . . . . ^ a.5 d . . . . . . 9 m.w 7+. . . . . 4 2 w a+D . . . . & w w j+7 . . . . F w w w j+> . . . . J.w w = . . . . ) ;.w w b.. . . . . . !+w :.P . . . . . ) *+w L.) . . . . . . . . . . / k+M.) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . D B / . . . . . . . . . . . . 7 l+g+^ . . . . . . . . . m+s c.` . . . . . . n+w a.~ . . . . . #.w w W . . . . f w w e d.. . . . $.w w w a.` . . . . M.w w A.. . . . 2.C.w w p . . . . . D @+w b+) . . . . . *.j j ~+. . . . . . . . . . ` +.a.X.. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . + u d.. . . . . . . . . . . . X.^., ~ . . . . . . . . 8 /.w 7+. . . . . . v v.w & . . . . . F.w w ++. . . . ,+3.w w ).. . . . $ w w w T.8 . . . 7 o+w w p.. . . . p+w w C.t.. . . . . !+w s D.. . . . . ^ d+w ..) . . . . . . . . . 7 *+C.G . . . . . . . . . . . > _ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . + S E.. . . . . . . . . . . . U {+Y.7 . . . . . . . . ).3.a @.. . . . . ) q+w V.8 . . . . e.3.w r+Z . . . 1 2 w w I . . . . z.w w w a+/ . . . d.e w W.r . . . ) q+w w 6+> . . . . + 7.w 7.: . . . . . o.w e _.. . . . . . . . . ) M W.H . . . . . . . . . . . 8 S./ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . Z R.% . . . . . . . . . . . . E o = ) . . . . . . . ) M.w [+7 . . . . . q w w {.. . . . 8 < w w y . . . > o+w w , . . . . m w w w 2 : . . . G w w (.9 . . . J v.w w - . . . . . &.w w = . . . . . ).v.w ]+. . . . . . . . . ) n.o H.8 . . . . . . . . . . 9 4+9 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 1 2+#+> . . . . . . . . . . > ; W.&.. . . . . . . . @.{+w p+. . . . . 1 m.w >+7 . . . . Y.w w , . . . . b+w w l.7 . . . p w w w {+Z . . . &.w w T.8 . . . <.w w w ].. . . . + T.w C.P . . . . Z o+w a J . . . . . . . . . x v.r.}+. . . . . . . . . . J l+}+. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . Z c.|+D . . . . . . . . . . ^ 5.v.p . . . . . . . . s+w a P . . . . . *+w w ` . . . . ,.w w e 9 . . . t+w w W.2.. . . ,.w w w v._ . . . +.w w /.. . . . ~.w w e @ . . . . F.w w L.. . . . . - w w <+. . . . . . . . . %.j v.x.. . . . . . . . . . q.[.E.. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ^ Y u+`.. . . . . . . . . . e.a O.l . . . . . . . 4 } w %+7 . . . . E.o w .+7 . . . @ :.w w A.. . . /+w w w W . . . h+w w w s @ . . ) f.w w v+. . . P s w w >+> . . . + i.w s % . . . . z.3.w w+[ . . . . . . . . W C.w s.. . . . . . . . . . K.a+z.. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ^ %+Z.~+. . . . . . . . . . q s 2 (+. . . . . . . E w s F.. . . . . V w s ].. . . . [.w w Y . . . K.w w w 4+. . . =.w w w w @.. . 1 |.w w h.. . . 4.w w w t+. . . . #+w w 7./ . . . 4 V.w w 4.. . . . . . . . l {+w =+/ . . . . . . . . ) &.O.y . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . Z c . . . . . . . . . . . . . . . ^ V |.` ) . . . . . . . . . X w 7.J . . . . . . 8 P.w u._.. . . . y w w f.7 . . . h.w w  +}+. . # W.w w H.. . . x+w w w w e.. . G.w w w =.. . ) y+w w w D.. . . 1 a+w w 1.. . . . n+w w :+Z . . . . . . . 6 5 w ^+i . . . . . . . . 8 *+3.x+. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . @.;+~ . . . . . . . . . . . . . . 4 V o = 7 . . . . . . . . D .+w ] X.. . . . . . R W.w %+8 . . . / ^+w W.W . . . B s w w z+. . c {+w w ^+> . . /+w w w w C . . h+w w w B . . F W.w w C.@ . . . I w w :.| . . . B v.w w =.. . . . . . . # } w o D.. . . . . . . . 1 A+s o.> . . . . . . . . . . . . . . ` ,+) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . d.4+L ) . . . . . . . . . . . . . _ g+w M.4 . . . . . . . . B+y.w ! Z . . . . . > 2+w s x+. . . . s+w w u+7 . . D y.w w u+) . ` Z.w w s i . . C+w w w w f . . *+w w s (+. . `+w w w y+) . . _ } w w T . . . _ V.w w l.: . . . . . . d 7.w w -+. . . . . . . . }+e+w g.8 . . . . . . . . . . . . . . # ,.D . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ` z X @ . . . . . . . . . . . . . 9 j.w [.d . . . . . . . . y o w `./ . . . . . (+C.w u._.. . . 3 3.w W.B . . . H.w w v.r . . =+w w w %.. . 1.w w w w K.. . V w w {+c . 7 ^.w w w n+. . . H w w w 8.. . ) t+w w w {.. . . . . . @ j+w w 1+D . . . . . . . e.a.w !.1 . . . . . . . . . . . . . D #+E > . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . m 6+&.8 . . . . . . . . . . . . 9 j.w a+L . . . . . . . ) o.w s b.> . . . . . t+w w =+/ . . ) c+w w ! > . . #+w w w 4.. . I.w w w s+. . `+w w w w ` . 7 9.w w Z.` . g o w w w ` . . d.9.w w a.7 . . m v.w w ] ` . . . . . c 1+w w (.r . . . . . . . x.r+w >+d.. . . . . . . . . . . . . b ! % . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ,+u+j.C . . . . . . . . . . . . X.{ w e D+) . . . . . . D g+w W.8+) . . . . 2.^+w s #+. . . 3+w w o L . . G.W.w w y+> . 4+w w w ! . . s+w w w w q . d s w w g+. . o.w w w  +}+. . J.w w w 4.. . 0 @+w w s  .. . . . . 4 V w w W.m+. . . . . . ) !+C.w i.d . . . . . . . . . . . . _ 5+P.F . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . D n+:.i+0 . . . . . . . . . . . X.w.w o b./ . . . . . . ,+^+w 3.q . . . . . * w w |._.. . D E+w w ;.> . > Z.w w 3.v . -.w w w y.` . b.w w w w !+. 3+w w w M.. 8 7.w w w d+) . d.^+w w :.}+. ) X w w w V 7 . . . . D ;.w w w |+) . . . . . ` f+o w (.$.. . . . . . . . . . . ) % U.V h . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ) m+{+:+6.) . . . . . . . . . . d.~.w w ;.X.. . . . . . S.v.w :.x.. . . . + o+w w g+` . . `+w w 3.O . . B.w w w f+. *.w w w s B+. ]+w w w w p+. M w w w $+. l W.w w w t+. . 0.w w w _+. . B 3.w w W.L . . . . 8 l+w w w j+4 . . . . . + ..s w j k . . . . . . . . . . . 2.g.3.+.: . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . F V.s [+E.. . . . . . . . . . d.[.w w ( # . . . . . . f+w w a ~+. . . . ].W.w w <.. . @.j w w #.) . t w w w o+8 t.:.w w w A.. N w w w w n.. N.w w w D+. X w w w w %.. c 2 w w w R . _ < w w w 2+> . . . 7 Y.w w w {+6 . . . . . [ q+w w W.& . . . . . . . . . . ) h+m.v.n.> . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ) . . . . . . . . . . . . . . . . . . . 9 T w  +s.^ . . . . . . . . . c 1+w w 5 W . . . . . 8 ! w w a+@.. . . > !.w w C._.. ) b+w w 3.$.. [ 3.w w W.$ / 9.w w w t+. g.w w w w 4+. T.w w w 8.+ i.w w w v.}+. `+w w w V.` . 9+w w w j $.. . . ) o.w w w s =.. . . . . # V.w w s 1.. . . . . . . . . . B+! w (. .. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . X.U 0 . . . . . . . . . . . . . . . . . . > H j w 7.p > . . . . . . . . [ 1+w w v.n.> . . . . }+:+w w @+2.. . . ~+j w w u+` . K.w w w l+) . ] w w w 5+. 6+w w w f.. k+w w w w s+d.W.w w W.(+x.s w w w d+. `.5 w w w H . k s w w w `.. . . ) M w w w w F+> . . . . L w+w w w Q > . . . . . . . . / H O.w a.v . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . > B u F ) . . . . . . . . . . . . . . . . . m a+w W.N.P . . . . . . . . h ] w w s |++ . . . . G+ +w w { 4 . . . N w w w /+. : U.w w 3.F . Q.w w w r.D k+w w w u.: 2+w w w w ]+p.w w w {+X.|+w w w w Q . h.w w w O.@ _ Z.w w w e # . . . <.s w w w @+c . . . . q e w w w N.~ . . . . . . . . C [.w w q+`.. . . . . . . . . . . . . . . . . ) _.v ` . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . : E N D.D . . . . . . . . . . . . . . . . ,+g+w w u.8+D . . . . . . . 2.y+w w w =+t.. . . . &+w w w L.D . . n u.w w {+(+. = w w w `.. L w w w s B s+w w w W.$.Y w o e e Y.=.a e j i.0 :+w w w w 3+2.5 w w w F+) +.w w w w >.. . . K 3.w w w C.l . . . 7 J.o w w w f.9 . . . . . . . 9 Q.:.w s R.D . . . . . . . . . . . . . . . . : p 0.O . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . _ = 1+4.`.. . . . . . . . . . . . . . . + n+o w w d+G+) . . . . . . 2.>+w w w < ~+. . . 7 2+w w w |+7 . . J.w w w j./ @.C.w w j E.Z u.w w w |+u j i.j.; v B x.# 2.h 4 : 9 h n n ~ v G+-.4.]+c <.C.w w s B 8.o w w w u.i . . y  +w w w s /+. . . : N w w w w @+@ . . . . . . ) 8.@+w w v.8+> . . . . . . . . . . . . . . . @ 4.j.E 8 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . J >.^+R.C > . . . . . . . . . . . . . ) A.u.w w 3.I.| . . . . . . `.P.w w w u.t ) . . h Z.w w s `+> . 1 Z.w w s 8+. , w w w ++. b+r+q+n+& X.n / . . . . . . . . . . . . . . . . . . . . . 7 @ f z t+8 ].c.:.w w $+. . K.O.w w w w H.` . . c Y w w w w } E.. . . . . . `.v+3.w w 5 ;+) . . . . . . . . . . . . . 7 G v+w+>.`.. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . F N.v.u+{.+ . . . . . . . . . . . . . 6 o+w w w 2 u / . . . . . @ d+w w w 3.= ` . . G :.w w W.u . . 6.w w w {+v 8.s w 3.q+8 @ ^ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ) ,+1.j.[ . *.u.w w w w E+@ . . r P.w w w w {+).. . . . . > q 9.w w w 7.$.. . . . . . . . . . . . . 1 K f.o e+b ) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ) f w.s E+1.| . . . . . . . . . . . . 0 T w w w w w.$ . . . . . | j+w w w s M.^ . . #+w w w j 3+. > w.w w w /.4 V h.# > . . . . . . . . . . . . H+I+J+K+L+M+N+O+P+Q+R+S+T+U+V+W+X+Y+Z+`+. . . . . . . . > . 0 5.w w w w 3.R . . b :+w w w w v.3+. . . . . @.0+s w w w /.t.. . . . . . . . . . . . B+$+9.w m.&./ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ` t @+w e  @).) . . . . . . . . . . 7 8+v.w w w j X c . . . . J j+w w w w ] ,+. 7 l+w w w {+L . ).W.w w Z.F 7 . . . . . . . . . . .@+@@@#@$@%@&@*@=@=@=@=@=@=@=@=@=@=@=@=@=@=@-@;@>@,@S+`@)@!@. . . . . . + D...m.w M . . ,.|.w w w w w z+. . . . / n.a w w w s ; Z . . . . . . . . . . ` 8.#. +w 3.>.2.. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . + <.w+w s [.h+D . . . . . . . . . . m ^+w w w w a+& > . . . J V.w w w w a+l . X.o+w w w 2 (+) F+Z.6.~ . . . . . . . . ~@{@]@^@-@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@/@(@_@:@<@. . . . . . D G 8 ) I v.w w w w w Q.) . . . q.f.w w w w o &+7 . . . . . . . . . 0 * ^.s w w [.O . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 0 Q.O.w w w+s+i . . . . . . . . . | j.w w w w w u+G.. . . J o+w w w w :.!+) ~+O.w w w E+| h ^ . . . . . . `+[@}@|@/@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@*@1@2@3@`+. . . . . _ ! s w w w w I.> . . 1 s+j w w w w {+;+. . . . . . . . ) }.|+O.w w w r+7+7 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ) 7 . . . . . . . . . . . . . . . . . . . . . . . . . . ,+v+v.w w j , B ` . . . . . . . : n+o w w w w  +Q.9 . . ,+o+w w w w W.5+~ 7+W.w 3.A+n . . . . . . 4@5@6@*@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@7@2@T+8@9@0@a@/@=@=@=@=@=@=@=@=@=@/@b@V+c@. . . . > m Y 3.w ! D . ) x.@+w w w w w Z.$.. . . . . . . + {.u+s w w w j Y.h . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ) 2.6 R E.~ . . . . . . . . . . . . . . . . . . . . . . . . ~+Y W.w w w >+=.0 . . . . . . ) A.a w w w w w < %.> . ,+a.w w w w w 0+[ ++~.p.. . . . . d@e@f@g@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@h@i@. . . j@k@L+l@m@n@=@=@=@=@=@=@=@=@o@p@[@`+. . . . $ i+X.. [ B.W.w w w w w e+t.. . . . . ) ,+M i.w w w w s f.b . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 8 G z o.&.v + . . . . . . . . . . . . . . . . . . . . . > % 6+s w w w 2 5+_.) . . . . . 6 ^.w w w w w s #.r . d U.w w w w w %+Z ` . . . . q@{@6@*@=@=@=@=@=@=@*@r@s@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@s@t@!@. . . . . . u@K+v@w@*@=@=@=@=@=@=@&@x@k@`+. . . . . ).} w w w w w s g.1 . . . . 8 L l+C.w w w w w m.&./ . . . . . . . . . . . . . . . . . . . . . . . . . . . . / ) . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ~ L n+w.#.I b Z . . . . . . . . . . . . . . . . . . . / x 7.w w w w j 0+K./ . . . . d.A+w w w w w w a 1.Z P U.w w 3.++@ . . . . y@z@h@=@=@=@=@=@=@=@A@R+B@C@*@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@Q+d@. . . . . . . . D@E@l@F@=@=@=@=@=@=@s@G@H@. . . . ~ u 9.w w w v.4+` . . . X.u 6+s w w w w w v.>.2.. . . . . . . . . . . . . . . . . . . . . . . . . > t.% h+B | ) . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . + R Y.a+^+c.C+)._ . . . . . . . . . . . . . . . . . 9 &+r+w w w w s ( #+[ . . . ` 8+j w w w w w w d+k 3 Z.6+R ) . . . H+I@0@=@=@=@=@=@=@;@G@J@K@L@M@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@S+!@. . . . . . . . . . N@O@P@-@=@=@=@=@=@Q@R@S@. . . . [ 5+e a {.) . ) v t+w+w w w w w w w w.l . . . . . . . . . . . . . . . . . . . . . . ) c l <. @! b.L ~ . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . + x.; m.s (.g+f+G+X.. . . . . . . . . . . . . . . @ t+C.w w w w w 5 9+}.) . . B 9.w w w w w w o >.t.+ . . . !@T@U@=@=@=@=@=@=@V@W@S@. . . X@*@=@=@=@=@=@=@=@=@=@Y@Z@`@ #.#.#.#+#@###Y@=@=@=@=@=@=@=@/@$#. . . . . . . . . . . . !@%#C@Q@=@=@=@=@=@o@&#j@. . . . (+$.. ~ D.%+v.w w w w w w w m.&./ . . . . . . . . . . . . . . . . . . . D 6 K B.] {+^+++m D . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ^ S.v+5 w w |.w.Q.S.c . . . . . . . . . . . . . # A+W.w w w w w v.%+%./ . i /.w w w w W.F+n . . . . *#=#/@=@=@=@=@=@-#;#Z+. . . . %#g@=@=@=@=@=@=@=@=@>#,#`#.#.#.#.#.#.#.#.#.#)#!#>#=@=@=@=@=@=@~#{#. . . . . . . . . . . . . . [@]#&@=@=@=@=@=@^#+@`+. . . . Z !.s w w w w w w w 3.Y.`.. . . . . . . . . . . . . . . . ` d {.S /.2 W.w a g.p ^ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 4 %.M.a w w w C.1+-+3+}+. . . . . . . . . . ) *.g+w w w w w w s U.8+`.D t+W.w r.3+> . . . c@/#g@=@=@=@=@=@(#V+K@. . . . . L@m@=@=@=@=@=@=@=@=@_#:#.#.#.#.#.#.#.#.#.#.#.#.#.#<#[#=@=@=@=@=@=@}#d@. . . . . . . . . . . . . . `+|#1#/@=@=@=@=@/@_@2#. . . . 2.T w w w w w w w.l ) . . . . . . . . . . . . . 2.8.0.L.a+v.w w w e L.-._ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 4 t N.e w w w w v.V.Q -.t.) . . . . . . . 7 ;+o+w w w w w w w O.R.g & - _ . . . `+O@F@=@=@=@=@=@3#5@K@. . . . . . . 4#=@=@=@=@=@=@=@=@5#6#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#7#[#=@=@=@=@=@*@8#. . . . . . . . . . . . . . . . `+E@m@=@=@=@=@=@9#$#L@. . . 7 F.C.w w r+=.8 . . . . . . . . . . Z b A g.7.v.w w w w w j [+!+X.. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 9 m+#.C.w w w w w W.a.; x 3 > . . . . . / u a+w w w w w w w r.# . . . . [@9@=@=@=@=@=@Q@0#c@. . . . . . . . d@a#=@=@=@=@=@=@=@b#c#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#<#>#=@=@=@=@=@m@d@. . . . . . . . . . . . . . . . . L@d#r@=@=@=@=@=@e#*#. . . . }.1+Y.[ . . . . . . . 8 6 )++..+ +w w w w w w w 3.=+p+`.. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . c x ;.e w w w w w w s Z.g.p+(+/ . . . _ s.a w w w 3.B.c . . . K@}@;@=@=@=@=@*@f#|#. . . . . . . . . . i@*@=@=@=@=@=@=@*@g#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#!#=@=@=@=@=@/@h#. . . . . . . . . . . . . . . . . . . i#]@-@=@=@=@=@g@j#j@. . . > . . . . 8 ,+,.s+q+y.w w w w w w w w w 3.[./+d . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . 8 i g *.$ ,+1 8 ) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 2.=.!.:.w w w w w w w w } A+A q.D . n N j a.x.. . . !@k#l#=@=@=@=@=@>@m#!@. . . . . . . . . . . 8@=@=@=@=@=@=@=@n#o#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#)#p#=@=@=@=@=@S+. . . . . . . . . . . . . . . . . . . . . i@7@=@=@=@=@=@^#J@!@. . . .  ., i.s w w w w w w w w w w o d+0.(+. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ) / _ B+[ > . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . : _.` z Q #.M.-+&+K L @.0 D ) . . . . . . . . . . . . . . . . . . . . . . . . . . | u g+ +w w w w w w w w w ^+0+4.C G.^ . . . Y+x@q#=@=@=@=@Q@S+r#. . . . . . . . . . . . `+(#=@=@=@=@=@=@*@s#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.###=@=@=@=@=@a#L@. . . . . . . . . . . . . . . . . . . . . K@W@n@=@=@=@=@/@t#u#`+. . ~ 8+|.w w w w w w w w W.a.f+6 > . . . . . . . . . . . . . . . . . . . . . . . . . ~ 0 3 W A s.t+0.h+G h ) . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 8 n % 8+k+^.{+O.9.y+b+R.M !+8.$.`.Z 7 . . . . . . . . . . . . . . . . . . . ) @.* j. +w w w w w w w w j 1.> . . S@v#w#=@=@=@=@=@=@w@m#x#. . . . . . . . . . . . S@s@=@=@=@=@=@=@$@y#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#z#=@=@=@=@=@n@u@. . . . . . . . . . . . . . . . . . . . . . . *#P@*@=@=@=@=@s@x@h#L@. . 3 #.W.w w w s < - G 8 . . . . . . . . . . . . . . . . . . . . ~ d.v W =.Q.l+/.E+m..++.h+G.~ . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . > h G <.B.>+(.s w w w  +2 U.g+I.s.x+3+U J 0 7 . . . . . . . . . . . . . ) @.H [.v.w w w w U.L . . A#C@a@=@=@=@=@=@=@=@=@=@*@}#u#. . . . . . . . . . . J@=@=@=@=@=@=@=@0#B#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#C#=@=@=@=@=@=@D#. . . . . . . . . . . . . . . . . . . . . . . . x#d#E#=@=@=@=@=@q#F#G#H#. > 3+U.} Y.f : . . . . . . . . . . . . . . . 8 [ _.W u s.M.1+:+{+s w W.} ;.M B [ ) . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . > 9 g h+i+=+2 s w w w w w w w j a T.{ L.i+H 6.m # X.7 . . . . . . . > # 4.1+3.I.X.. . `+(@=@=@=@=@=@=@=@=@=@=@=@=@=@n@T+y@. . . . . . . . . I#=@=@=@=@=@=@=@m#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#=@=@=@=@=@=@J#. . . . . . . . . . . . . . . . . . . . . . . . . . i#v#n@=@=@=@=@=@=@K#. . . ^ Z . . . . . . . . . . > d.v S.=.S _+{ :+O.W.w w w w w  +6+|+h+e.D . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . Z # {.$+c.r.o w w w w w w w w w w w o {+:+P.c+Q = E W e.t.: . 7 3 ` . . . `+L#=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@F#A#. . . . . . . . 5@=@=@=@=@=@=@=@e@.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#=@=@=@=@=@=@z@. . . . . . . . . . . . . . . . . . . . . . . . . . . . )@6@=@=@=@=@=@0#. . . . . . . > h E.8.z+$+F+[.r.{+W.w w w w w w w w w 9.Y M x.`.7 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . / n D.4+N.l.o w w w w w w w w w w w w w w w W. +(.^.Y 0./ . . . `+L#=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@n@t@d@. . . . . . M#=@=@=@=@=@=@=@E@.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#=@=@=@=@=@=@N#. . . . . . . . . . . . . . . . . . . . . . . . . . . 2#C@-@=@=@=@=@=@v#. . . . J +.{ a+:.o w w w w w w w w w w w w 3.d+v+7+}.: . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 7 c z.#+; ^. +w w w w w w w w w w w w w w w w Y X.. . `+]#;@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@O#P#. . . . . z@=@=@=@=@=@=@=@Q#B#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#C#=@=@=@=@=@=@d#. . . . . . . . . . . . . . . . . . . . . . . . . !@R#S#=@=@=@=@=@/@1@m#. . ) x 5 w w w w w w w w w w w w w a !.M 8.h > . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ) + O D+Y.{ {+s w w w w w w w w w w w @+G.. . . T#2@3#=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@9#I#!@. . . W+=@=@=@=@=@=@=@M#U#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#z#=@=@=@=@=@=@J@. . . . . . . . . . . . . . . . . . . . . . . . ~@V#=@=@=@=@=@a@/#3@`+. . n b+s w w w w w w w w w o V.I.7+q.8 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . / _.A.b.V m.o w w w w w w w (.p . . . . T#8@s@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@W#.@. . u#/@=@=@=@=@=@=@,@X#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.###=@=@=@=@=@/@Y+. . . . . . . . . . . . . . . . . . . . . . `+Q#E#=@=@=@=@q#Y#I+. . . 7 h+5 w w w w w w s (.g+s+ .[ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . > P  .k.0+Z.j w w w 3.4.> . . . . h#Z#=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@`# $L@H+.$=@=@=@=@=@=@n@+$@$.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.##$p#=@=@=@=@=@$$H+. . . . . . . . . . . . . . . . . . . . . K@S+/@=@=@=@=@h@X+. . . . n 2+w w w w j a.M.&.g ~ . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . > | R H `.( |...^ . . . . q@%$n@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@*@&$3@,@=@=@=@=@=@=@=@S+*$.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#=$=@=@=@=@=@=@x@. . . . . . . . . . . . . . . . . . . . . {#-$=@=@=@=@-@;$>$. . . 7 x 2 s r+u+s+;+n > . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . X.z.U . . . . . . A#F#=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@~#6@=@=@=@=@=@=@=@;@,$`$.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#)$>#=@=@=@=@=@=@!$. . . . . . . . . . . . . . . . . . . L@~$%@=@=@=@=@E#8#`+. . . }+b.l+x+G 1 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ) > 8 : + ^ _ X.c h `.@ | i @.r 8 . . . . K@j#Q@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@{$]$^$.#.#.#.#.#.#.#.#.#.#.#.#.#.#.#/$[#=@=@=@=@=@=@L#>$. . . . . . . . . . . . . . . . . . .@W#*@=@=@=@=@=#($. . . . . 4 ` . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . ) > > 8 : 1 9 X.[ @ | ,+r E.6 U l f m 8.S.D.%.t m+h+D+p+#+H J.M h.*+- Q |+I.F+k+L.b+c+[+V u+e+1+>+( a.T.a+^+2 5 u.|.{+e C. +j 3.o W.;.J . . . . . h#1@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@-$_$:$.#.#.#.#.#.#.#.#.#.#.#.#.#<$[#=@=@=@=@=@=@=@j#. . . . . . . . . . . . . . . . . !@{@E#=@=@=@=@Q@U+[$. . . . . d.n.q+q+[+c+H.T M.I.|+i+b.<+k.J./+F.E h+6.y ;+ .8.R z.O 6 E.P n }+h X.4 + / 7 > ) . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . + @ # $ % A.x+= -+B.l+2+%+w.d+l.< E+} m.r+(.a {+e :. +v.o s s w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w :+ .) . . . . j@W@g@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@(#}$|$@$.#.#.#.#.#.#.#.#.#1$2$>#=@=@=@=@=@=@=@L#i#. . . . . . . . . . . . . . . . P#3$/@=@=@=@=@^@h#. . . . . B+b.2 w w w w w w w w w w w w w w w w w w w w w w w w w w w s W.3.j :.e {+a 5 w+} E+7.@+( >+] w.u+[+b+_+`.+.S C+F.x ;+)._.4 . . . . . . . . ',
'. . . . . . . . . . . . . . . . . ) 7 8 ~ D 1 X.J # $.b G+K.{.E #+J.Q.>.`.T 0+!.e+5.7.} u.j W.w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w 3.b.: . . . . . H@b@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@q#&$4$5$6$7$.#.#.#8$9$0$a$=@=@=@=@=@=@=@=@*@I#. . . . . . . . . . . . . . . H+b$9#=@=@=@=@/@;$N@. . . ) b k+:.w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w w s j y.r.5.j.c., ++b.&+z+m+% ).~+3 h ^ : 8 7 ) . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . > 7 8 ~ Z X.}+@.E.g p.D.A.=.* 8+M o.Y.`.L.%+w.P.@+T.w+O.o w w w w w w w w w w w w w w w w w w w w w w w w w 1+# . . . . . x#;#S#=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@*@`#f#Q+0#l@=#S#*@=@=@=@=@=@=@=@=@=@=@c$L@. . . . . . . . . . . . . !@8#^@=@=@=@=@=@>@d$`+. . / ,.j.W.w w w w w w w w w w w w w w w w w w w w s C.^+U.5.e+b+g.Q f+8+F.K p l G.,+h 1 ~ ` > . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ) ) > > ` Z h d e.b m ].t h+p+z s.t+B.g._+0+q+y+@+:+(.j o W.s s u.& ) . . . . . ~@R@q#=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@a#e$. . . . . . . . . . . . `+X+f$*@=@=@=@=@q#8@r#. . 9 <.U.w w w w s s W.v.5 Z.>+V L. @+.Q.H E 6.].p.}.,+0 8 > > ) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ) 8 1 d.}+P F *.9 . . . . . . . %#g$*@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@h@2#. . . . . . . . . . . H+K+b@*@=@=@=@=@=@Q@!$. . . ~+k.0.* D+-.% $ 3 }+_ / ) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . `+Q#|@*@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@6@I+. . . . . . . x#T#i@h$V#`#=@=@=@=@=@=@=@~#T@. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . N@4@4@D@. . . . . i$4@i#. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . x#j$k$/@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@r@l${@{@R#N#t@m$n$o$(#&@=@=@=@=@=@=@=@=@=@=@p$D#. . . . . . . . . . . . . . . . . . . . . . . . . . . . K@4@4@y@. . . . . . i#4@i$`+. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . q$/@/@B@. . . . !@3#/@l#. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . L@X+t#&@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@A@*#. . . . . . . . . . . . . . . . . . . . . . . . . . . . . R#/@/@V+. . . . . L@^#/@F@H+. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . T+=@=@B@. . . . !@.$=@{$. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . `+)@r$(@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@*@r@q#=@=@s$S@. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . R#=@=@~$. . . . . L@h@=@E#H+. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . T+=@=@B@. . . . !@.$=@{$. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . y@j$x@o@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@%@x@Q+A@=@=@g$t$. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . u$=#=#+@. . . . . L@h@=@E#H+. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . T+=@=@B@. . . . !@.$=@{$. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . >$8#]@(#*@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@p$1#J#)@Y#q#=@=@v$K@. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . L@h@=@E#H+. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . E@w$w$+@. . . x$w$w$e@. . . y$w$#@z$. . . . . . `+A$2@]#w$w$w$#@u#. . . . T+=@=@B@. . . . !@.$=@{$. . . . . . . y@!$v#C@w$w$w$p@L@. . . d@l@w$w$w$w$w$Y#m$u$!@. . . . . . . . . . B$C$W+`@D$~@. . . . . . . . . . . . . . . . . [$)@I#]@s$&@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@*@L#E$&#F$y@L@d#r@=@=@q#2@d@. . . . . t$G$w$w$w$Y#0#T@!@. . . . . . . {#b$R@w$w$w$w$k#. . . . e@w$w$X+. . . q@G$#@w#=@g@f@w$#@H$. . . . . K@m#S+I$w$w$w$M@`+. . . . P+w$w$w$C@l@I@j@. . . . . . . . . . . . ',
'. . . . . . . . . .  $=@=@h$. . . R#=@=@R#. . . p@=@=@k@. . . . . j@w$q#=@=@=@=@=@=@Q#. . . . T+=@=@B@. . . . !@.$=@{$. . . . . . J$(#=@=@=@=@=@=@>@x#. . . [$(@=@=@=@=@=@=@=@*@_@[$. . . . . . . J+c$~#*@=@=@=@Q@-$:@q@. . . . . . . . . . . . . . . . . . !@>$K$4#G#L$,@6@M$$$3#~#~#%@p$w@^@k$G@S+M+N$<@D@. . . H@O#*@=@=@w#4#`+. . . . . . <@/@=@=@=@=@=@*@Y#!@. . . . d@v#s@=@=@=@=@=@=@$#. . . . R#=@=@~$. . . N@/@=@=@=@=@=@=@=@A#. . . . k@M$=@=@=@=@=@=@F@`+. . . . 0@=@=@=@=@=@=@F#e$. . . . . . . . . . . ',
'. . . . . . . . . .  $=@=@h$. . . R#=@=@R#. . . p@=@=@k@. . . . `+v$=@=@V@C@Q+R+R+p@O$. . . . T+=@=@B@. . . . !@.$=@{$. . . . . 2#S#=@*@P$Q$p@R+R+%$L@. . . [$(@=@%@p@R+p@#@n@=@=@R#. . . . . `+R$-@=@=@=@=@=@=@=@=@=@{$%#. . . . . . . . . . . . . . . . . . . . . . . . `+!@!@L@d@d@d@L@!@`+`+. . . . . . . e$Q+s@=@=@=@$$h#. . . . . . . . <@/@=@w@C@t#-@=@/@h#. . . . 2@=@=@o@x@l@R+R+R+C$. . . . R#=@=@~$. . . H+R+p@9#=@;@l@R+p@<@. . . i#$$=@=@|@R@p@R+R+j#`+. . . . 0@=@g@C@c$.$=@=@5@. . . . . . . . . . . ',
'. . . . . . . . . .  $=@=@h$. . . R#=@=@R#. . . p@=@=@k@. . . . H@-@=@|@B$. . . . . . . . . . T+=@=@B@. . . . !@.$=@{$. . . . . p@=@=@S$. . . . . . . . . . [$(@=@(#L@. . . K+=@=@_@. . . . . %$=@=@=@=@=@=@V@T$m#i@!$]@p$i@. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . [$z@p$=@=@=@=@b@I+. . . . . . . . . <@/@=@G@. . M#=@=@L+. . . ~@w#=@A@4@. . . . . . . . . . R#=@=@~$. . . . . L@h@=@E#H+. . . . . . T$=@=@U$`+. . . . . . . . . . 0@=@r@. . h#/@=@Y#. . . . . . . . . . . ',
'. . . . . . . . . .  $=@=@h$. . . R#=@=@R#. . . p@=@=@k@. . . . T+=@=@{@L@L@L@L@L@L@`+. . . . T+=@=@B@. . . . !@.$=@{$. . . . q@V@=@p$K@L@L@L@L@L@L@. . . . [$(@=@(#L@. . . B$q#=@-$. . . . |#&@=@=@=@=@s@T+j@. . . . . {#|@P#. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . L@+@$@=@=@=@=@/@v@q@. . . . . . . . . . <@/@=@G@. . F$=@=@l$. . . I@=@=@&#L@L@L@L@L@L@`+. . . . R#=@=@~$. . . . . L@h@=@E#H+. . . . . x#V$=@3#c@L@L@L@L@L@L@. . . . . 0@=@r@. . >$~#=@3$. . . . . . . . . . . ',
'. . . . . . . . . .  $=@=@h$. . . R#=@=@R#. . . p@=@=@k@. . . . g$=@=@>@^#^#^#^#^#^#W$. . . . T+=@=@B@. . . . !@.$=@{$. . . . X$-@=@g@^#^#^#^#^#^#Y$x#. . . [$(@=@(#L@. . . x#Q@=@$@. . . . p@=@=@=@=@/@Z$. . . . . . . . H@v@. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . `+J$9@*@=@=@=@=@;@V+`+. . . . . . . . . . . <@/@=@G@. . {#m@m@O@. . . M@=@=@V@^#^#^#^#^#^#`@. . . . R#=@=@~$. . . . . L@h@=@E#H+. . . . . 4@q#=@s@^#^#^#^#^#^#o$`+. . . . 0@=@r@. . j@P@m@/#. . . . . . . . . . . ',
'. . . . . . . . . .  $=@=@h$. . . R#=@=@R#. . . p@=@=@k@. . . . m@=@=@=@=@=@=@=@=@=@Q#. . . . T+=@=@B@. . . . !@.$=@{$. . . . A#=@=@=@=@=@=@=@=@=@>@x#. . . [$(@=@(#L@. . . x#Q@=@$@. . . . 1@=@=@=@=@`$!@. . . . . . . . . v@z$. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . {#_@q#=@=@=@=@=@^# %. . . . . . . . . . . . . <@/@=@G@. . . . . . . . . G@=@=@=@=@=@=@=@=@=@$#. . . . R#=@=@~$. . . . . L@h@=@E#H+. . . . . {#=@=@=@=@=@=@=@=@=@F@`+. . . . 0@=@r@. . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . J#=@=@h$. . . R#=@=@R#. . . p@=@=@k@. . . . f$=@=@N+J#J#J#J#J#J#.@. . . . T+=@=@B@. . . . !@.$=@{$. . . . O$/@=@>@4#J#J#J#J#J#j$!@. . . [$(@=@(#L@. . . x#Q@=@$@. . . !@r@=@=@=@=@K+. . . . . . . . . . K+Q#. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . )@v$g@=@=@=@=@=@*@f@t$. . . . . . . . . . . . . . <@/@=@G@. . . . . . . . . n$=@=@L$J#J#J#J#J#J#.%. . . . R#=@=@~$. . . . . L@h@=@E#H+. . . . . P#*@=@`# $J#J#J#J#J#+%. . . . . 0@=@r@. . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . m#=@=@U$. . . R#=@=@R#. . . p@=@=@k@. . . . Q+=@=@~$. . . . . . . . . . . T+=@=@B@. . . . !@.$=@{$. . . . Z+3#=@%@B$. . . . . . . . . . [$(@=@(#L@. . . x#Q@=@$@. . . `+A@=@=@=@q#[@. . . . . . . . . . `+`+. . . . . . . . . . . . . . . . . . . . . . . . . . . . O$v$g@=@=@=@=@=@=@~#$#L@. . . . . . . . . . . . . . . <@/@=@G@. . . . . . . . . l$=@=@@%. . . . . . . . . . . R#=@=@~$. . . . . L@M$=@r@q@. . . . . D@F@=@%@u@. . . . . . . . . . . 0@=@r@. . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . u#=@=@m@u@. . R#=@=@R#. . . p@=@=@k@. . . . J$-@=@w@ %L@. . . . . . . . . T+=@=@B@. . . . !@.$=@{$. . . . . L$=@=@n$e$. . . . . . . . . [$(@=@(#L@. . . x#Q@=@$@. . . . g$=@=@=@/@{#. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . `+%#x@g@=@=@=@=@=@=@=@m@{#. . . . . . . . . . . . . . . . . <@/@=@G@. . . . . . . . . <@a@=@%@d$x#. . . . . . . . . R#=@=@~$. . . . . `+F#=@Q@ %. . . . . . R+=@=@x@u@`+. . . . . . . . . 0@=@r@. . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . x#Z#=@=@w#^@l#F@=@=@F@l#l#l#3#=@=@k@. . . . `+8@=@=@-@F@7@l#l#l#D#. . . . T+=@=@B@. . . . !@.$=@{$. . . . . 2#$$=@=@a@0@l#l#l#9@d@. . . [$(@=@(#L@. . . x#Q@=@$@. . . . q$=@=@=@=@`@. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . d@d$=#-@=@=@=@=@=@=@=@&@T+K@. . . . . . . . . . . . . . . . . . <@/@=@G@. . . . . . . . . . b$*@=@q#r@7@l#l#l#W+. . . . R#=@=@~$. . . . . . M@=@=@g@^#7@{#. . . u@V$=@=@;@V$l#l#l#P@`+. . . . 0@=@r@. . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . [@Z#=@=@=@=@=@=@=@=@=@=@=@=@=@=@k@. . . . . D@#%;@=@=@=@=@=@=@Q#. . . . T+=@=@B@. . . . !@.$=@{$. . . . . . .%f$=@=@=@=@=@=@>@x#. . . [$(@=@(#L@. . . x#Q@=@$@. . . . z$~#=@=@=@,@`+. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . N@:@U@*@=@=@=@=@=@=@=@=@l#h#. . . . . . . . . . . . . . . . . . . . <@/@=@G@. . . . . . . . . . `+5@o@=@=@=@=@=@=@$#. . . . R#=@=@~$. . . . . . <@{$=@=@=@=@A#. . . . X$Y$*@=@=@=@=@=@F@`+. . . . 0@=@r@. . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . d@*#J@W+O@O@O@O@O@O@O@O@O@O@O@c@. . . . . . . e$D#+%O@O@O@O@4@. . . . *#O@O@i$. . . . `+8#O@Q#. . . . . . . !@.%Q#W+O@O@O@T@!@. . . !@$%O@J@`+. . . !@%%O@d$. . . . . 5@=@=@=@-@i@. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . H#Q+3#=@=@=@=@=@=@=@=@=@&@W@q@. . . . . . . . . . . . . . . . . . . . . y@W+O@C$. . . . . . . . . . . . N@&%8#O@O@O@O@Y+. . . . H$O@O@X$. . . . . . . q@F$+%O@O@e$. . . . . !@Y+d$m#O@O@O@K+. . . . . J@O@*%. . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . !@t#=@=@=@M$T#. . . . . . . . . . . . . . . . . . . . . . . . . . u@$#b@*@=@=@=@=@=@=@=@=@=@*@P@H#. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . u@V$=@=@=@b@u@. . . . . . . . . . . . . . . . . . . . . `+c@`@=%;@=@=@=@=@=@=@=@=@=@=@=@(@y$L@. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . -%r@=@=@=@-#D$!@. . . . . . . . . . . . . . . . x#Y+N#t#a@=@=@=@=@=@=@=@=@=@=@=@=@w#@%r#. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . %#F@=@=@=@/@9@m#e$`+. . . . . . . . L@r#k@~$n$^#/@=@=@=@=@=@=@=@=@=@=@=@=@=@g@R@z$. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . )@{$=@=@=@=@=@w#k$L$W@;%M+M#%$P+3$7@~#*@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@g@n$O$. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . T#G@*@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@o@>%3@. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . d@L+F@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@*@U@X@u@. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . T#j#3#=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@=@E#8@E@x#. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . Z+V+e#-@=@=@=@=@=@=@=@=@=@=@=@=@=@=@-@s$O+W$H+. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . `+4@%%S+t#V$o@Q@-@&@%@(@b@K#U$B@i#!@. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ',
'. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . ');
}

# EOF #

sub when_packets_pending
{
		#-- Read from the pcap subprocess pipe...thankx to mjm for the select waypoint. --#
	    my $line = 0;
	    #-- This got damn bitch did fucked me 4 days long!!!!! --#
	    #-- i had $line = <PIPE_READ>; before....!!! this splits up the packets --#
	    #-- because 0a did mean \n and this buffered readin did interpret it!!! --#
	    #-- sysread now dont --#
		sysread (PIPE_READ,$line,65535);

		#-- prints out the packet in hex --#
		if ($gl_debugon==1){print "\npending packet: " . unpack('H*',$line) ." \n";}
		
		#-- Resets the packet position --#
		$gl_packet_pos = 0;
		if ($line)
		{
			chomp $line;
			$gl_sniffnumtotalpackets++;
			$gl_statusbar->push($gl_statusbar_context, "Total amount of sniffed packets: $gl_sniffnumtotalpackets   accesspoints: $gl_ap_count clients: $gl_client_count");	

			#-- Starts the packet decoding funtion --#
			read80211b_func ($line);				

		}
return(TRUE);
}
#----------- Menu functions ----------------#
# this file contains callback from the menu # 
#-------------------------------------------#

sub toggle_toolbar	# Hide/Show the toolbar in scanner window
{
	my $test = shift(@_);
 	if ($$test->visible() == 0)
 	{
 		$$test->show();
 	}
 	else
 	{
 		$$test->hide();
 	}
}


sub toggle_accoustic_beacon	# activates the accoustic beacon stuff
{
	if ($gl_accoustic_beacon == 0)
 	{
 		$gl_accoustic_beacon = 1;
 	}
 	else
 	{
 		$gl_accoustic_beacon = 0;
 	}
}

sub toggle_accoustic_events
{
	if ($gl_do_soundevents == 0)
 	{
 		$gl_do_soundevents = 1;
 	}
 	else
 	{
 		$gl_do_soundevents = 0;
 	}
}


sub start_scan
{
	if ($gl_is_sniffing == TRUE)
	{
		writetologwin ('Allready scanning');
		#We dont do all the stuff twiche :-)
		#So we do actualy nothing :-)
		return(TRUE);
	}
	
	set_monitormode;
	if (check_monitor_mode != TRUE)
	{
		show_dialog "Wellenreiter","\nCould not set card into RFMON mode, cannot continue\n",TRUE;
	}
	writetologwin ('Card set into RFMON mode');
	
	# Check for gpsd listening port (Assume that gpsd is running there)
	if (detect_gpsd == TRUE)
	{
		#-- Initialize the gps when existing --#
		get_gpsdata;
		writetologwin ('Listening for gps data');
	}
	else
	{
		writetologwin ('No gpsd detected, so not listening for gps data');
	}

	# Open a handle to libpcap
	my $err;
	if ($gl_sniff_dev->{dev_type} == TYPE_CISCO2) 
	{
		$gl_pcap_descrip = Net::Pcap::open_live('wifi0',65535,1,10,\$err);
	}
	else
	{
		$gl_pcap_descrip = Net::Pcap::open_live($gl_sniff_dev->{dev_name},65535,1,10,\$err);
	}

	#-- Open the dumpfile --#
	my $tmpdate=`date +%H_%M_%S-%d_%m_%Y`;
	chomp ($tmpdate);
	my $savename=$gl_savedir ."/Wellenreiter-" . $tmpdate . ".dump"; 
	writetologwin ("Packets will also be logged into $savename for further analysis");

    $gl_cap_save_descrip = Net::Pcap::dump_open($gl_pcap_descrip,$savename);
	
	if($gl_cap_save_descrip && $gl_pcap_descrip)
	{
		$gl_is_sniffing = 1;
	}
	else
	{
		show_dialog "-=[ Wellenreiter ]=-", "\n Could not connect to libpcap, cannot continue \n", TRUE;
	}
	
	#-- Open the savefile --#
	my $tmpdate2=`date +%H_%M_%S-%d_%m_%Y`;
	chomp ($tmpdate2);
	$gl_savefilename=$gl_savedir ."/Wellenreiter-" . $tmpdate2 . ".save"; 
	writetologwin ("Automaticly saving discovered objects to $gl_savefilename");

	#-- Add a handler that checks the pipe for pending packets coming from the client --#
	$gl_idlefunction = Gtk::Gdk->input_add(PIPE_READ->fileno(),'read',\&when_packets_pending,undef);

	

	$gl_sniffnumtotalpackets = 0;
	$gl_statusbar->push($gl_statusbar_context, "Waiting for packages... - Total amount of sniffed packets: $gl_sniffnumtotalpackets   accesspoints: $gl_ap_count clients: $gl_client_count");	

	#-- Add a timeout handler to switch the channels
    # Switch Cisco cards also to prevent undetected overlapping networks
    $gl_sniffchannel = 1;
    
    $gl_channelswitch = Gtk->timeout_add(450,\&switchchannel);
	writetologwin ('Starting to switch the channels');

    #-- Defining that the signals form the child doesn't care the parent process.
    $SIG{CHLD} = "IGNORE";
    #-- Forking of the client to capture the packets and send it to the parent --#
    unless ($gl_child = fork())
    {
	#-- This block and subfunctions are started in the child process --#
        die "Cannot fork the childprocess correctly: $!" unless defined $gl_child;
	#-- Close the read end of the pipe, becaus pipes cannot be bidirectional --#
	close (PIPE_READ);
	#-- Close the writing part of the pipe, used only from the parent to send you a stop. --#
	close (PIPE_WRITE2);
	#-- Close on the second pipe the write end because we only want the exit read --#
		
	#-- Getting into the endless loop for getting the packets. --# 
	while (1)
	{ 
		#-- When the process receives a "stop\n" over the pipe it will terminate
		if (<PIPE_READ2> eq "stop\n")
		{
			#-- Exit the forked client process --#
			#system($commandstopsniff); 
			_exit(0);
		}
		my $packet = Net::Pcap::next($gl_pcap_descrip, \%hdr);
		my $unpacket = unpack('H*',$packet);				
		my $save_packet = Net::Pcap::dump($gl_cap_save_descrip, \%hdr, $packet);

		if ($packet)
		{
			if ($unpacket =~ /[A-Fa-f0-9]/)
			{
				#-- Write the packet to the parent process --#
				syswrite (PIPE_WRITE,($packet),length($packet));
			}
		}
	}
} #-- End of the child functions


}

sub stop_scan
{
	if ($gl_is_sniffing == 0)
	{
		#We dont do all the stuff twiche :-)
		#So we do actualy nothing :-)
		return(TRUE);	
	}

	writetologwin ('Stopscanning initiated');

	#-- Remove timeout handler to stop switch the channels
	Gtk->timeout_remove($gl_channelswitch);
	writetologwin ('Stop switching channels');

	$gl_is_sniffing = 0;
	#-- Send the command to stop the sniffer --#
	print PIPE_WRITE2 "stop\n";

	if (detect_gpsd == TRUE)
	{
		#-- Stop the gpsd stuff --#
		close_gpsd;
	}
	
	#Close pcap handles
	Net::Pcap::dump_close($gl_cap_save_descrip);
	Net::Pcap::close($gl_pcap_descrip);

	# Don't listen for any new packets
	Gtk::Gdk->input_remove($gl_idlefunction);

	undef($gl_pcap_descrip);
	undef($gl_cap_save_descrip);

	remove_monitormode;

	if (check_monitor_mode == FALSE)
	{
		writetologwin ('Card is set now to normal mode again');
	}
	else
	{
		writetologwin ('Card could not return to  normal mode again');
	}

	$gl_statusbar->push($gl_statusbar_context, "Waiting for user interaction - Total amount of sniffed packets: $gl_sniffnumtotalpackets   accesspoints: $gl_ap_count clients: $gl_client_count");

}

sub auto_save
{
    if ($gl_savefilename)
    {	
	open(AUTOSAVEFILE, ">$gl_savefilename") || die "Cannot open the autosavefile $gl_savefilename: $!\n";
    	if (@gl_accesspoints) # When there are objects in the array
			{
				foreach my $save_object (@gl_accesspoints)
					{
						for my $key_save_object (sort keys(%$save_object))
							{ 
								print AUTOSAVEFILE "$key_save_object: $save_object->{$key_save_object}\n";
							}
						print AUTOSAVEFILE "\n";
					}
			}
	close (AUTOSAVEFILE);
    }
}

sub save_file
{
	  my $file_save_dialog = new Gtk::FileSelection( 'Save file:');
	  my $savefile;
	  $file_save_dialog->show_fileop_buttons();
	  $file_save_dialog->set_transient_for ($mainwindow);
	  $file_save_dialog->show();
	  $file_save_dialog->signal_connect("delete_event",sub{$file_save_dialog->destroy();});	
	  $file_save_dialog->cancel_button->signal_connect("clicked",sub{$file_save_dialog->destroy();});
 	  $file_save_dialog->ok_button->signal_connect("clicked",
 	  sub {
  		$savefile=$file_save_dialog->get_filename();
  		open(SAVEFILE, ">$savefile") || die "Cannot open the savefile $savefile: $!\n";
   	 	if (@gl_accesspoints) # When there are objects in the array
		{
			foreach my $save_object (@gl_accesspoints)
			{
				for my $key_save_object (sort keys(%$save_object))
				{ 
					print SAVEFILE "$key_save_object: $save_object->{$key_save_object}\n";
				}
					print SAVEFILE "\n";
			}
		}
		close (SAVEFILE);
		#-- Removes the temporary file because not needed anymore --#
		$file_save_dialog->destroy();});
}


sub load_file
{
	  # Switch of sound events
	  my $tmpvalue = $gl_do_soundevents;
	  $gl_do_soundevents = 0;

	  my $loadfilename;
	  my @tmpallobjects;
	  #my $netnode;
	  #my (%tmphash,$tmphash);
	  my $file_load_dialog = new Gtk::FileSelection( 'Load file:');
	  $file_load_dialog->set_transient_for ($mainwindow);
	  $file_load_dialog->hide_fileop_buttons();
	  $file_load_dialog->show();
	  $file_load_dialog->signal_connect("delete_event",sub{$file_load_dialog->destroy();});
	  $file_load_dialog->cancel_button->signal_connect("clicked",sub{$file_load_dialog->destroy();});
	  $/ = "";
	  $file_load_dialog->ok_button->signal_connect("clicked",
	  sub {
	  		
 	 		$loadfilename=$file_load_dialog->get_filename();
			# Stop the scanner
			stop_scan;
	   	   	# Reset the content of the scanner
			reset;

			# Open the file to load
	  		open(LOADFILE, "<$loadfilename") || die "Cannot open the file $loadfilename: $!\n";
			while (<LOADFILE>)
			{
		 	 	my @felder = split /^([^:]+):\s*/m;
		 	 	shift @felder; # for the blank line
		 	 	push (@tmpallobjects, {map /(.*)/,@felder});
		  	}
			close (LOADFILE); 
     	   		foreach my $tmphashref (@tmpallobjects)
			{
				$gl_tmphashref = $tmphashref;
				# Add it to the clist
				add_accesspoint TRUE;
			}				
                	
			$gl_do_soundevents = $tmpvalue;
			$file_load_dialog->destroy();});	
}

sub export_as_csv
{
  my $file_save_dialog = new Gtk::FileSelection( 'Export csv file:');
  my $savefilename;
  $file_save_dialog->show_fileop_buttons();
  $file_save_dialog->set_transient_for ($mainwindow);
  $file_save_dialog->show();
  $file_save_dialog->signal_connect("delete_event",sub{$file_save_dialog->destroy();});
  $file_save_dialog->cancel_button->signal_connect("clicked",sub{$file_save_dialog->destroy();});
  $file_save_dialog->ok_button->signal_connect("clicked",
  sub {
  		$savefilename=$file_save_dialog->get_filename();
  		my ($save_object, %save_object, $key_save_object);
  		open(SAVEFILE, ">$savefilename") || die "Cannot open the savefile $savefilename: $!\n";
   	 	if (@gl_accesspoints) # When there are objects in the array
		{
			foreach my $save_object (@gl_accesspoints)
			{
				for my $key_save_object (sort keys(%$save_object))
				{ 
					print SAVEFILE "$save_object->{$key_save_object},";
				}
				print SAVEFILE "\n";
			}
		}
		close (SAVEFILE);
		$file_save_dialog->destroy();});
}

sub export_as_mappoint
{
  my $file_save_dialog = new Gtk::FileSelection( 'Export mappoint file:');
  my $savefilename;
  $file_save_dialog->show_fileop_buttons();
  $file_save_dialog->set_transient_for ($mainwindow);
  $file_save_dialog->show();
  $file_save_dialog->signal_connect("delete_event",sub{$file_save_dialog->destroy();});
  $file_save_dialog->cancel_button->signal_connect("clicked",sub{$file_save_dialog->destroy();});
  $file_save_dialog->ok_button->signal_connect("clicked",
  sub {
  		$savefilename=$file_save_dialog->get_filename();
  		open(SAVEFILE, ">$savefilename") || die "Cannot open the savefile $savefilename: $!\n";
		  print SAVEFILE "Lat\tLong\tMac\tEssid\tEnc\n";
		  
   	 	if (@gl_accesspoints) # When there are objects in the array
		{
			foreach my $save_object (@gl_accesspoints)
			{
				my ($tmplat,$tmplong,$tmpmac, $tmpessid, $tmpwep)=0;
				for my $key_save_object (sort keys(%$save_object))
				{ 
					if ($key_save_object eq 'lat') {$tmplat = $save_object->{$key_save_object}};
					if ($key_save_object eq 'long') {$tmplong = $save_object->{$key_save_object}};
					if ($key_save_object eq 'sendmac') {$tmpmac = $save_object->{$key_save_object}};
					if ($key_save_object eq 'essid') {$tmpessid = $save_object->{$key_save_object}};
					if ($key_save_object eq 'WEP') {$tmpwep = $save_object->{$key_save_object}};
				}
				if ($tmpmac && $tmpessid && $tmplat != 0 && $tmplong != 0)
				{
					if ($tmplat > 0) {$tmplat = "+" . $tmplat};
					if ($tmplong > 0) {$tmplong = "+" . $tmplong};
					if ($tmpwep == 0) {$tmpwep = "Cleartext"};
					if ($tmpwep == 1) {$tmpwep = "Encrypted"};
					print SAVEFILE "$tmplat\t$tmplong\t$tmpmac\t$tmpessid\t$tmpwep\n";
				}
			}
		}

		close (SAVEFILE);
		$file_save_dialog->destroy();});
}
#--- Beacon frame decoding ---#
sub decode_beacons
{
	my $packet = $_[0];
	my $retval = 1;
	
	
			if (length($packet) < 37 || $gl_tmphashref->{flag_from_ds} == 1 || 
			    $gl_tmphashref->{flag_to_ds} == 1 || $gl_tmphashref->{duration} ne '0000' || $gl_tmphashref->{destmac} ne 'ffffffffffff')
			{ #at least 37 bytes are needed for a beacon frame, otherwise drop it
			  #got this values from kismet, another great wireless scanner
			  # Beacons are only in the Distribution System so packets from or to DS flag set could
			  # Not be a valid beacon also if destination address is something other than fffffffff
			  $gl_tmphashref = undef;
			  return(0);
			}

		# its a beaconframe so do beep if accoustic beacon indicator is on
		if ($gl_accoustic_beacon == 1)
		{
			print "\a";
		}

			#-- Switch the led if it is a beacon frame --#
    		$gl_tmphashref->{type_text} = 'Beacon frame';

		    #-- Get the timestamp
			
		    $gl_tmphashref->{timestamp} = reverse(decode_bytes($packet,'H*',8));
			
            #-- Get the beacon interval
            $gl_tmphashref->{beaconinterval} = reverse(decode_bytes($packet,'h*',2));

			#-- Get the capability flags
			my @capability_flags = split(//,decode_bytes($packet,'b16',2));

			# Its a real accesspoint network
			$gl_tmphashref->{ISAP} = @capability_flags[$CP_FLAG_IS_ASCCESSPOINT];
			$gl_tmphashref->{ISAH} = @capability_flags[$CP_FLAG_IS_ADHOC];
    			$gl_tmphashref->{cap_flag_IS_POLLABLE} = @capability_flags[$CP_FLAG_CF_POLLABLE];
        		$gl_tmphashref->{cap_flag_POLLREQUEST} = @capability_flags[$CP_FLAG_CF_POLLREQ];
			$gl_tmphashref->{WEP} = @capability_flags[$CP_FLAG_WEP_REQUIRED];
        		$gl_tmphashref->{cap_flag_SHORT_PREAMBLE} = @capability_flags[$CP_FLAG_SHORT_PREAMBLE];
        		$gl_tmphashref->{cap_flag_PBCC} = @capability_flags[$CP_FLAG_PBCC];
        		$gl_tmphashref->{cap_flag_CHANNEL_AGILITY} = @capability_flags[$CP_FLAG_CHANNEL_AGILITY];

			if ($gl_tmphashref->{ISAP} == 1 && $gl_tmphashref->{ISAH} == 1)
			{
			  # This is not possible to be an AP and an adhoc at once.
  			  $gl_tmphashref = undef;
			    return(0);
			}

			while ($gl_packet_pos < length($packet))
			{
				#-- Get the tagtype and the taglength 
				my $tmptagtype = decode_bytes($packet,'C*',1);
				my $tmptaglen = decode_bytes($packet,'C*',1);
				if ($tmptagtype == $TAG_TYPE_SSID)
				{
					if ($tmptaglen > 34)
					{ #at max 34 length on essid possible, otherwise its noise
 	 				  $gl_tmphashref = undef;
					    return(0);
					}

        			$gl_tmphashref->{essid} = decode_bytes($packet,'A*',$tmptaglen);
					$gl_tmphashref->{essid_len} = $tmptaglen;

					if ($gl_tmphashref->{essid_len} > 0 && $gl_tmphashref->{essid} !~ /[a-zA-Z0-9]/)
					{
						$gl_tmphashref->{essid} = "Non-broadcasting";
					}
				}
				elsif ($tmptagtype == $TAG_TYPE_DS_PARAM_CHANNEL)
				{
        			$gl_tmphashref->{Channel} = decode_bytes($packet,'C*',$tmptaglen);
				}
				else
				{
					# unhandled type
					#Jump over the amount of bytes
					$gl_packet_pos = $gl_packet_pos + $tmptaglen; 
				}
				$gl_tmphashref->{isaccesspoint} = 1;
	


			} #-- Until end of packet --#
			
			if ($gl_tmphashref->{Channel} > 15 || length($gl_tmphashref->{essid}) < 1)
			{ #This is a shitty packet
 	 				  $gl_tmphashref = undef;
					    return(0);
			}

#-- Do the double check --#
#-- first seen beacons are stored in an array and only after a second occurence its will --#
#-- be taken into decoding --#
	# Check if there is allready an enry for it in the clist
	my $tmpkeyname = $gl_tmphashref->{essid} . "-" . $gl_tmphashref->{sendmac} . "-" .$gl_tmphashref->{Channel};
	if (exists$gl_clist_objects{$tmpkeyname})
	{
		# dort drinnen ist die tmprowpos;
		my $tmpnumrow = $gl_clist_objects{$tmpkeyname};
		my $tmptext = $gl_clist->get_text($tmpnumrow, 7);
		if ($tmptext eq "+")
		{
			$gl_clist->set_text($tmpnumrow, 7,"*");
		}
		else
		{
			$gl_clist->set_text($tmpnumrow, 7,"+");
		}

	}
	else
	{
		#-- Reset the checkflag --#
		my $has_been_seen_before = 0;
		foreach my $first_check (@gl_beacon_check1)
		{
			if ($first_check->{essid} eq $gl_tmphashref->{essid} && 
			$first_check->{Channel} == $gl_tmphashref->{Channel} && 
			$first_check->{sendmac} eq $gl_tmphashref->{sendmac}) 
			{
				$has_been_seen_before = 1;
			}
		} # End for each $first_check
		
		if ($has_been_seen_before == 0)
		{
			push (@gl_beacon_check1,$gl_tmphashref);	
		}
		elsif ($has_been_seen_before == 1)
		{
			#-- Check if it is allready on the list --#
			my $isallreadyinarray = 0;
			my $essidallreadyexists = 0;
			#When it is the first accesspoint we do no checking
			if (@gl_accesspoints == 0)
			{
				add_accesspoint;		

			}

			foreach my $apref (@gl_accesspoints)
			{
				if ($apref->{essid} eq $gl_tmphashref->{essid} && $apref->{Channel} == $gl_tmphashref->{Channel} && $apref->{sendmac} eq $gl_tmphashref->{sendmac})
				{
					$isallreadyinarray = 1;
				}
			}# Foreach $apref
			if ($isallreadyinarray == 0)
			{
				add_accesspoint;	
			}
 	
		} # end has_been_seen_before
	} # End if it allready exists in the listview
  #Cleanup
  $gl_tmphashref = undef;
  return ($retval);

} #-- end of sub decode_beacon --#

#This decodes an amount of bytes of a packet in the given unpack type
#example: $test = decode_bytes ($packet,'n',1);

sub decode_bytes 
{
	my $encpacket = $_[0];
	my $type = $_[1];
	my $len = $_[2];
	my $retval;
	$retval = unpack($type,substr ($encpacket,$gl_packet_pos,$len));
	$gl_packet_pos = $gl_packet_pos + $len;
	return ($retval);
}
sub read80211b_func
{
	Gtk->main_iteration while (Gtk->events_pending );
	my($packet) = @_;
	$gl_tmphashref = undef;

	#$gl_tmphashref->{frame_type} = undef;

	$gl_packet_pos = 0;

	my $date=`date`;
	chomp ($date);
	$gl_tmphashref ={'time' => $date};


	#### Get-gpsinfo if available ###
	$gl_tmphashref->{lat} = $gl_lat;	
	$gl_tmphashref->{long} = $gl_long;
	$gl_tmphashref->{speed} = $gl_speed;

	#-- Debug print --#
	if ($gl_debugon == 1) {print "packet is now: ". unpack ('H*',$packet) . "\n"};

	#-- Get 802.11b standard header infos --#
	#-- Cut of the framecontrol from the packet
	my $FC = substr($packet,$gl_packet_pos,1);
	$gl_packet_pos = $gl_packet_pos + 1;

	#--Get packet type (Management / Data / Control)
	my $FC_Type = substr(unpack('b8',$FC),0,4);

	#-- Cut the framecontrol flags
	my @FC_FLAGS = split (//,unpack ('b8',substr($packet,$gl_packet_pos,1)));
	$gl_packet_pos = $gl_packet_pos + 1;
	
	if (length($packet) < 24)
	{ # at least 24 bytes are needed for a 80211b frame, otherwise drop it
	  $gl_tmphashref = undef;
	  return(0);
	}
	

	#-- When the packet is a MGTFRAME
	if ($FC_Type == $TYP_MGTFRAME)
	{
		
		#-- This is correct for every Management frame --#
		$gl_tmphashref->{frame_type} = 'management frame';
    		$gl_tmphashref->{flag_from_ds} = @FC_FLAGS[$FC_FLAG_FROM_DS];
    		$gl_tmphashref->{flag_to_ds} = @FC_FLAGS[$FC_FLAG_TO_DS];
    		$gl_tmphashref->{flag_fragments} = @FC_FLAGS[$FC_FLAG_FRAGMENTS];
    		$gl_tmphashref->{flag_retrans} = @FC_FLAGS[$FC_FLAG_RETRANS];
    		$gl_tmphashref->{flag_pwrmgt} = @FC_FLAGS[$FC_FLAG_PWR_MGT];
    		$gl_tmphashref->{flag_more_data} = @FC_FLAGS[$FC_FLAG_MORE_DATA];
    		$gl_tmphashref->{flag_wep} = @FC_FLAGS[$FC_FLAG_WEP];
    		$gl_tmphashref->{flag_order} = @FC_FLAGS[$FC_FLAG_STRIC_ORDER];
    		$gl_tmphashref->{duration} = unpack ('H4',substr($packet,$gl_packet_pos,2));
		$gl_packet_pos = $gl_packet_pos + 2;
    		$gl_tmphashref->{destmac} = unpack ('H12',substr($packet,$gl_packet_pos,6));
		$gl_packet_pos = $gl_packet_pos + 6;
		$gl_tmphashref->{sendmac} =  unpack ('H12',substr($packet,$gl_packet_pos,6));
		$gl_packet_pos = $gl_packet_pos + 6;
    		$gl_tmphashref->{bssmac} =  unpack ('H12',substr($packet,$gl_packet_pos,6));
		$gl_packet_pos = $gl_packet_pos + 6;
		#getting and calculating the sequence number
    		my $SequenceCrl = unpack ('B16',substr($packet,$gl_packet_pos,2));
		$gl_packet_pos = $gl_packet_pos + 2;
    		my $Seq_ctrl_fragment_number_in_dec = unpack('N',pack('B32','0' x 28 .substr($SequenceCrl,0,4)));
    		my $Seq_ctrl_seq_number_in_dec = unpack('N',pack('B32','0' x 20 .substr($SequenceCrl,4,15)));
		$gl_tmphashref->{sequence_ctl} = (($Seq_ctrl_seq_number_in_dec * 16) +$Seq_ctrl_fragment_number_in_dec);
    		##### btw... i hate unpack/pack :-) ### 

    		#-- Checks if it is a beacon frame --#
    		if (unpack('b8', $FC ^ $FC_Beacon) == 0)
	        {
			if ($gl_Traffic_Window)
			{
				if ($gl_Traffic_clist->rows() == 10000)
				{
					$gl_Traffic_clist->remove(($gl_Traffic_clist->rows()-1));
				}
				$gl_Traffic_clist->prepend($gl_tmphashref->{sendmac},$gl_tmphashref->{bssmac},$gl_tmphashref->{destmac},"Beacon Frame");
				if ($gl_Traffic_style == 0)
				{
					$gl_Traffic_clist->set_background (0,Gtk::Gdk::Color->parse_color('lightgray'));
					$gl_Traffic_style++;
				}
				else
				{	
					$gl_Traffic_clist->set_background (0,Gtk::Gdk::Color->parse_color('white'));
					$gl_Traffic_style=0;
				}
			}
			decode_beacons ($packet);
		} 

	    	#-- Checks if it is a Probe Response --#
		elsif (unpack('b8', $FC ^ $FC_Probe_Resp) == 0)
		{
			if ($gl_Traffic_Window)
			{
				if ($gl_Traffic_clist->rows() == 10000)
				{
					$gl_Traffic_clist->remove(($gl_Traffic_clist->rows()-1));
				}
				$gl_Traffic_clist->prepend($gl_tmphashref->{sendmac},$gl_tmphashref->{bssmac},$gl_tmphashref->{destmac},"Probe Response Frame");
				if ($gl_Traffic_style == 0)
				{
					$gl_Traffic_clist->set_background (0,Gtk::Gdk::Color->parse_color('lightgray'));
					$gl_Traffic_style++;
				}
				else
				{	
					$gl_Traffic_clist->set_background (0,Gtk::Gdk::Color->parse_color('white'));
					$gl_Traffic_style=0;
				}

			}
			decode_probe_response ($packet);
		}
		else 
		{
		# No other mgt frames are handled and should be skipped 
		# Adding an entry to the active traffic if it is working and updated
		# Adding an entry to the active traffic if it is working and updated
		if ($gl_Traffic_Window)
		{
			if ($gl_Traffic_clist->rows() == 10000)
			{
				$gl_Traffic_clist->remove(($gl_Traffic_clist->rows()-1));
			}
			$gl_Traffic_clist->prepend($gl_tmphashref->{sendmac},$gl_tmphashref->{bssmac},$gl_tmphashref->{destmac},"Management Frame");
				if ($gl_Traffic_style == 0)
				{
					$gl_Traffic_clist->set_background (0,Gtk::Gdk::Color->parse_color('lightgray'));
					$gl_Traffic_style++;
				}
				else
				{	
					$gl_Traffic_clist->set_background (0,Gtk::Gdk::Color->parse_color('white'));
					$gl_Traffic_style=0;
				}

		}

		$gl_tmphashref = undef;
		return(0);		
		}


	} #-- end of is it a mgtframe 
	elsif ($FC_Type == $TYP_DATAFRAME) #-- If it is a data frame
	{
		#-- This is correct for every Datat frame --#
		$gl_tmphashref->{type_text} = 'Data frame';
		$gl_tmphashref->{frame_type} = 'data frame';
    		$gl_tmphashref->{flag_from_ds} = @FC_FLAGS[$FC_FLAG_FROM_DS];
    		$gl_tmphashref->{flag_to_ds} = @FC_FLAGS[$FC_FLAG_TO_DS];
    		$gl_tmphashref->{flag_fragments} = @FC_FLAGS[$FC_FLAG_FRAGMENTS];
    		$gl_tmphashref->{flag_retrans} = @FC_FLAGS[$FC_FLAG_RETRANS];
    		$gl_tmphashref->{flag_pwrmgt} = @FC_FLAGS[$FC_FLAG_PWR_MGT];
    		$gl_tmphashref->{flag_more_data} = @FC_FLAGS[$FC_FLAG_MORE_DATA];
    		$gl_tmphashref->{flag_wep} = @FC_FLAGS[$FC_FLAG_WEP];
		if ($gl_tmphashref->{flag_wep})
		{
			#-- Dont decode WEP encrypted data --#
		    #-- Skip it --#
			$gl_tmphashref = undef;
		    return(0);
		}

    		$gl_tmphashref->{flag_order} = @FC_FLAGS[$FC_FLAG_STRIC_ORDER];
    		$gl_tmphashref->{duration} = unpack ('H4',substr($packet,$gl_packet_pos,2));
		 $gl_packet_pos = $gl_packet_pos + 2;
		
		if ($gl_tmphashref->{flag_from_ds} eq '1' && $gl_tmphashref->{flag_to_ds} eq '0')
		{
   	 		$gl_tmphashref->{bssmac} =  unpack ('H12',substr($packet,$gl_packet_pos,6));
			$gl_packet_pos = $gl_packet_pos + 6;
			$gl_tmphashref->{sendmac} =  unpack ('H12',substr($packet,$gl_packet_pos,6));
			$gl_packet_pos = $gl_packet_pos + 6;
 	   		$gl_tmphashref->{destmac} = unpack ('H12',substr($packet,$gl_packet_pos,6));
			$gl_packet_pos = $gl_packet_pos + 6;
		}
		elsif ($gl_tmphashref->{flag_to_ds} eq '1' && $gl_tmphashref->{flag_from_ds} eq '0')
		{
  	  		$gl_tmphashref->{destmac} = unpack ('H12',substr($packet,$gl_packet_pos,6));
			$gl_packet_pos = $gl_packet_pos + 6;
  		  	$gl_tmphashref->{bssmac} =  unpack ('H12',substr($packet,$gl_packet_pos,6));
			$gl_packet_pos = $gl_packet_pos + 6;
			$gl_tmphashref->{sendmac} =  unpack ('H12',substr($packet,$gl_packet_pos,6));
			$gl_packet_pos = $gl_packet_pos + 6;
		}
		elsif ($gl_tmphashref->{flag_to_ds} eq '0' && $gl_tmphashref->{flag_from_ds} eq '0')
		{
  		  	$gl_tmphashref->{destmac} = unpack ('H12',substr($packet,$gl_packet_pos,6));
			$gl_packet_pos = $gl_packet_pos + 6;
			$gl_tmphashref->{sendmac} =  unpack ('H12',substr($packet,$gl_packet_pos,6));
			$gl_packet_pos = $gl_packet_pos + 6;
	  	  	$gl_tmphashref->{bssmac} =  unpack ('H12',substr($packet,$gl_packet_pos,6));
			$gl_packet_pos = $gl_packet_pos + 6;
		}
		##- Why did they change the order of src and bssid addr. in data frames?

		# Adding an entry to the active traffic if it is working and updated
		if ($gl_Traffic_Window)
		{
			if ($gl_Traffic_clist->rows() == 10000)
			{
				$gl_Traffic_clist->remove(($gl_Traffic_clist->rows()-1));
			}

			$gl_Traffic_clist->prepend($gl_tmphashref->{sendmac},$gl_tmphashref->{bssmac},$gl_tmphashref->{destmac},"Dataframe");

			if ($gl_Traffic_style == 0)
			{
				$gl_Traffic_clist->set_background (0,Gtk::Gdk::Color->parse_color('lightgray'));
				$gl_Traffic_style++;
			}
			else
			{	
				$gl_Traffic_clist->set_background (0,Gtk::Gdk::Color->parse_color('white'));
				$gl_Traffic_style=0;
			}

		}

		#-- getting and calculating the sequence number
    	my $SequenceCrl = unpack ('B16',substr($packet,$gl_packet_pos,2));
	$gl_packet_pos = $gl_packet_pos + 2;
    	my $Seq_ctrl_fragment_number_in_dec = unpack('N',pack('B32','0' x 28 .substr($SequenceCrl,0,4)));
    	my $Seq_ctrl_seq_number_in_dec = unpack('N',pack('B32','0' x 20 .substr($SequenceCrl,4,15)));
		$gl_tmphashref->{sequence_ctl} = (($Seq_ctrl_seq_number_in_dec * 16) +$Seq_ctrl_fragment_number_in_dec);

		##-- llc decoding --#		
		my $llc_not_used = decode_bytes($packet,'H*',3);
		my $llc_organisation_code = decode_bytes($packet,'H*',3);

		if ($llc_organisation_code ne $LLC_ORG_ECAPS_ETHERNET)
		{
			$gl_tmphashref = undef;
			return(0); #-- non ethernet does not interrest at the moment --#
		}

		##-- This is the ethernet type --#
		
		my $llc_type = decode_bytes($packet,'H*',2);
		
		if ($llc_type eq $LLC_TYPE_ARP)
	    	{
			$gl_tmphashref->{type_text} = 'Data - Arp frame';
	    		decode_arp ($packet);
		}
		elsif ($llc_type eq $LLC_TYPE_IP )
		{
			$gl_tmphashref->{type_text} = 'Data - Ip frame';

			#-- decode the ip header --#
			#			$gl_tmphashref->{sequence_ctl}
			# unpack IP header
			$gl_tmphashref->{HipVersionipHdrLen} = decode_bytes($packet,'H*',1);
			$gl_tmphashref->{HipTOS} = decode_bytes($packet,'H*',1);
			$gl_tmphashref->{DipTotalLen} = decode_bytes($packet,'n',2);
			$gl_tmphashref->{DipIdent} = decode_bytes($packet,'n',2);
			$gl_tmphashref->{HipFlagsFrags} = decode_bytes($packet,'H*',2);
			$gl_tmphashref->{DipTTL} = decode_bytes($packet,'C',1);
			$gl_tmphashref->{DipProto} = decode_bytes($packet,'C',1);
			$gl_tmphashref->{HipHdrCksum} = decode_bytes($packet,'H*',2);
			$gl_tmphashref->{HipSrcAddr} = decode_bytes($packet,'H*',4);
			$gl_tmphashref->{HipDestAddr} = decode_bytes($packet,'H*',4);			
			$gl_tmphashref->{Hip_Src_Addr} = hex_to_IP ($gl_tmphashref->{HipSrcAddr});
			$gl_tmphashref->{Hip_Dst_Addr} = hex_to_IP ($gl_tmphashref->{HipDestAddr});
			$gl_tmphashref->{DipHdrLen} = hex($gl_tmphashref->{HipVersionipHdrLen}) & 0x0f; # in 32-bit words
			$gl_tmphashref->{DipVersion} = (hex($gl_tmphashref->{HipVersionipHdrLen}) & 0xf0)>>4;

			if ($gl_tmphashref->{DipProto} == $IP_PROTO_UDP)
			{
				$gl_tmphashref->{type_text} = 'Data - Udp frame';

				#-- Udp decoding --#
				$gl_tmphashref->{UdpSrcPort} = decode_bytes($packet,'n',2);
				$gl_tmphashref->{UdpDstPort} = decode_bytes($packet,'n',2);
				$gl_tmphashref->{UdpLen} = decode_bytes($packet,'n',2);
				$gl_tmphashref->{UdoCksum} = decode_bytes($packet,'H*',2);
				unless (($gl_tmphashref->{UdpSrcPort} == $portBOOTPS) || ($gl_tmphashref->{UdpSrcPort} == $portBOOTPC) ||
				($gl_tmphashref->{UdpDstPort} == $portBOOTPS) || ($gl_tmphashref->{UdpDstPort} == $portBOOTPC)) 
				{
					#-- I only want dhcp for now
					$gl_tmphashref = undef;
					return (0);
				}
				$gl_tmphashref->{type_text} = 'Data - Dhcp frame';
				decode_dhcp ($packet);
			}
		}
		else
		{
	 		$gl_tmphashref = undef;
		 	return (0); # it is not an arp or dhcp type packet
		}

	}
	else 
	{
		#Nothing except mgtframes and data are handled, others should be skipped 
		$gl_tmphashref = undef;
		return(0);		
	}


	
} #-- end of read80211b_func


sub add_accesspoint
{
	my ($do_coloring) = @_;
	my $tmpstyle = $mainwindow->get_style()->bg('normal');
	push (@gl_accesspoints,$gl_tmphashref);
	my $tmpmanuf = get_manuf $gl_tmphashref->{sendmac};

	#Add it to the clist
	my $tmprowpos;
	if ($gl_tmphashref->{detssid})
	{
		$tmprowpos = $gl_clist->append (undef,$gl_tmphashref->{Channel},$gl_tmphashref->{detssid},$gl_tmphashref->{sendmac},
                	                           undef,$tmpmanuf,undef);
	}
	else
	{
		$tmprowpos = $gl_clist->append (undef,$gl_tmphashref->{Channel},$gl_tmphashref->{essid},$gl_tmphashref->{sendmac},
                	                           undef,$tmpmanuf,undef);
	}

	#Add it also to a hash for faster locate macaddress in row
	my $tmpnamekey = $gl_tmphashref->{essid} . "-" . $gl_tmphashref->{sendmac} . "-" .$gl_tmphashref->{Channel};
	$gl_clist_objects{$tmpnamekey} = $tmprowpos; 

	#-- Add the pixmaps for the clist entries --#
	if ($gl_tmphashref->{essid} eq "Non-broadcasting")
	{
		my ($tmppixmap1,$tmpmask1) = Gtk::Gdk::Pixmap->create_from_xpm_d ($mainwindow->window,$tmpstyle,@gl_logo_network_nonbroadcasting);
		$gl_clist->set_pixmap($tmprowpos,0,$tmppixmap1,$tmpmask1);
		if ($gl_do_soundevents == 1)
		{
			if ($gl_tmphashref->{WEP} == 0)
			{
				system("$gl_conf{new_nb_ap_clear} &");
			}
			else
			{
				system("$gl_conf{new_nb_ap_wep} &");
			}
		}
	}
	else
	{
		($tmppixmap1,$tmpmask1) = Gtk::Gdk::Pixmap->create_from_xpm_d ($mainwindow->window,$tmpstyle,@gl_logo_network_broadcasting);
		$gl_clist->set_pixmap($tmprowpos,0,$tmppixmap1,$tmpmask1);
		if ($gl_do_soundevents == 1)
		{
			if ($gl_tmphashref->{WEP} == 0)
			{
				system("$gl_conf{new_b_ap_clear} &");
			}
			else
			{
				system("$gl_conf{new_b_ap_wep} &");
			}
		}
	}
	if ($gl_tmphashref->{WEP} == 0)
	{
		my ($tmppixmap1,$tmpmask1) = Gtk::Gdk::Pixmap->create_from_xpm_d ($mainwindow->window,$tmpstyle,@gl_nowep);
		$gl_clist->set_pixtext($tmprowpos,4,"Off",2,$tmppixmap1,$tmpmask1);
	}
	else
	{
		my ($tmppixmap1,$tmpmask1) = Gtk::Gdk::Pixmap->create_from_xpm_d ($mainwindow->window,$tmpstyle,@gl_logo_encrypted);
		$gl_clist->set_pixtext($tmprowpos,4,"On",2,$tmppixmap1,$tmpmask1);
	}
	
	if ($gl_tmphashref->{ISAP})
	{
		my ($tmppixmap1,$tmpmask1) = Gtk::Gdk::Pixmap->create_from_xpm_d ($mainwindow->window,$tmpstyle,@gl_accesspoint_icon);
		$gl_clist->set_pixtext($tmprowpos,6,"ESS",2,$tmppixmap1,$tmpmask1);
		#Add it to the treeview	
		$gl_tree->insert_node(@gl_channeltrees[$gl_tmphashref->{Channel}],undef,["$gl_tmphashref->{sendmac}"],2,$tmppixmap1,$tmpmask1,$tmppixmap1,$tmpmask1,FALSE,FALSE);
		if ($do_coloring != TRUE)
    		{
			$gl_tree->node_set_cell_style(@gl_channeltrees[$gl_tmphashref->{Channel}],0,$gl_redstyle);
		}
		if ($gl_tmphashref->{WEP} == 1)
		{
			writetologwin ("Found new encrypted accesspoint $gl_tmphashref->{sendmac} on Channel $gl_tmphashref->{Channel}");
		}
		else
		{
			writetologwin ("Found new cleartext accesspoint $gl_tmphashref->{sendmac} on Channel $gl_tmphashref->{Channel}");
		}

	}
	if ($gl_tmphashref->{ISAH})
	{
		my ($tmppixmap1,$tmpmask1) = Gtk::Gdk::Pixmap->create_from_xpm_d ($mainwindow->window,$tmpstyle,@gl_wireless_card_icon);
		$gl_clist->set_pixtext($tmprowpos,6,"IBSS",2,$tmppixmap1,$tmpmask1);
		#Add it to the treeview	
		$gl_tree->insert_node(@gl_channeltrees[$gl_tmphashref->{Channel}],undef,["$gl_tmphashref->{sendmac}"],2,$tmppixmap1,$tmpmask1,$tmppixmap1,$tmpmask1,FALSE,TRUE);
		if ($do_coloring != TRUE)
    		{
			$gl_tree->node_set_cell_style(@gl_channeltrees[$gl_tmphashref->{Channel}],0,$gl_redstyle);
		}
		if ($gl_tmphashref->{WEP} == 1)
		{
			writetologwin ("Found new encrypted AD-HOC station $gl_tmphashref->{sendmac} on Channel $gl_tmphashref->{Channel}");
		}
		else
		{
			writetologwin ("Found new cleartext AD-HOC station $gl_tmphashref->{sendmac} on Channel $gl_tmphashref->{Channel}");
		}
	}

	$gl_ap_count ++;	
	auto_save;

}




sub build_detail_window
{
	if (!$gl_detail_ap_windows)
	{
		$gl_detail_ap_windows = new Gtk::Window( 'toplevel' );
		$gl_detail_ap_windows->set_transient_for ($mainwindow);
		$gl_detail_ap_windows->realize();
		#$teststyle = $mainwindow->get_style()->bg('normal');	#-- Get the background --#
		my $tmprefreshtimer;
		$gl_detail_ap_windows->title("-=[ Detail view of $gl_detail_ap_name ]=-");
		$gl_detail_ap_windows->set_usize( (($gl_screenwidth * 50)/ 100), (($gl_screenheight * 50)/ 100) ); 
		$gl_detail_ap_windows->border_width( 5 );
		my $signals = $gl_detail_ap_windows->signal_connect( 'delete_event', sub {$gl_detail_ap_windows->hide();TRUE});

		my $vbox = new Gtk::VBox (FALSE,1);
		$gl_detail_ap_windows->add($vbox);
		
		
		#-- Add a scrolled area --#
		my $scrollbox = new Gtk::ScrolledWindow ("","");
		$scrollbox->set_policy('automatic', 'automatic');
		$vbox->pack_start($scrollbox,TRUE,TRUE,FALSE);
		#$scrollbox->set_usize(200,200);
		#--Add the close button to the lower area --#
		my $closebutton = new Gtk::Button ('Close');
		$closebutton->signal_connect("clicked",sub{$gl_detail_ap_windows->hide();});
		$vbox->pack_end($closebutton,FALSE,FALSE,FALSE);
		$closebutton->show();

		#-- Add the clist to hold the infos
		$gl_detail_ap_clist = new_with_titles Gtk::CList( "Wert-Name","Wert-Wert"); 
		$gl_detail_ap_clist->column_titles_hide();
		$gl_detail_ap_clist->set_selection_mode( 'single' ); #Only one can be selected 
		$gl_detail_ap_clist->set_shadow_type( 'etched_in' );
		$gl_detail_ap_clist->set_column_width(0, 200);
		$gl_detail_ap_clist->set_column_width(1, 20);
		#$gl_detail_ap_clist->set_usize (300,300);
		$scrollbox->add_with_viewport($gl_detail_ap_clist);
		$scrollbox->signal_connect("button_press_event" => sub {
									my ($data, $event) = @_;
									if ($event->{button} == 3) 
									{
										build_popupmenu($event);
									}
									 return 1;});
#
		$gl_detail_ap_clist->show();
		$scrollbox->show();	
		$vbox->show();
		$gl_detail_ap_windows->show();
		
		# Add a timeout 
		$tmprefreshtimer = Gtk->timeout_add(3000,\&get_details)
	}
	else
	{
		$gl_detail_ap_windows->show();
		$gl_detail_ap_windows->title("-=[ Detail view of $gl_detail_ap_name ]=-");
	}

} # end detail window
sub get_details
{
	if ($gl_detail_ap_windows->visible)
	{
		$gl_detail_ap_clist->freeze();
		$gl_detail_ap_clist->clear();
		$gl_detail_ap_clist->thaw();
		$gl_detail_ap_clist->append ('Object name',$gl_detail_ap_name);
		my $tmpobjreference;
		foreach $tmpobjreference (@gl_accesspoints)
	  	{	
			if ($tmpobjreference->{sendmac} eq $gl_detail_ap_name)
			{
	
			      if ($tmpobjreference->{isaccesspoint} == 1 && $tmpobjreference->{ISAP} == 1)
			      {
				$gl_detail_ap_clist->append ('Accesspoint name',$gl_detail_ap_name);
			      }
			      elsif ($tmpobjreference->{isaccesspoint} == 1 && $tmpobjreference->{ISAH} == 1)
	      		      {	
				$gl_detail_ap_clist->append ('AD-HOC Station name',$gl_detail_ap_name);
			      }

			      if ($tmpobjreference->{WEP} == 1)
      			      {
				$gl_detail_ap_clist->append ('WEP encryption','Enabled');
			      }
			      elsif ($tmpobjreference->{WEP} == 0)
	      		      {
				$gl_detail_ap_clist->append ('WEP encryption','Disabled');	
	      		      }
	
			      $gl_detail_ap_clist->append ('Channel number',$tmpobjreference->{Channel});
			      $gl_detail_ap_clist->append ('Network ID (ESSID)',$tmpobjreference->{essid});
			      $gl_detail_ap_clist->append ('ESSID length',$tmpobjreference->{essid_len});
		
			      if ($tmpobjreference->{detssid} ne '')
			      {
				      $gl_detail_ap_clist->append ('Detected ESSID',$tmpobjreference->{detssid});
				      $gl_detail_ap_clist->append ('Detected by',$tmpobjreference->{detssidby});
			      }	

			      $gl_detail_ap_clist->append ('Macaddress',$tmpobjreference->{sendmac});
			      my $manuf = uc(substr ($tmpobjreference->{sendmac},0,6));

			      #$gl_detail_ap_clist->append ('Manufacturer',$manufactor{$manuf});

			      $gl_detail_ap_clist->append ('BSSID',$tmpobjreference->{bssmac});

			      open(PROCWLAN, '</proc/net/wireless') || die "Cannot open /proc/net/wireless: $!\n";
			      while(<PROCWLAN>) 
		              {
			         if ($_ =~ /^\s+(\w+):\s+\w+\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+/)	
				 {
					my $tmpint_name = $1;
					my $tmplinkq = $2;
					my $tmplevelq = $3;
					my $tmpnoiseq = $4;
					if ($tmpint_name eq $gl_sniff_dev->{dev_name})
					{
						my $tmpvalues = "Link: $tmplinkq / Level: $tmplevelq  / Noise: $tmpnoiseq"; 
						$gl_detail_ap_clist->append ('Current quality',	$tmpvalues);
					}
				 }
			      }
			      close (PROCWLAN);
				
			      if ($tmpobjreference->{lat} ne '')
			      {
			        $gl_detail_ap_clist->append ('GPS Latitude',$tmpobjreference->{lat});
			      }
			      if ($tmpobjreference->{long} ne '')
			      {
			        $gl_detail_ap_clist->append ('GPS Longitude',$tmpobjreference->{long});
			      }
			      if ($tmpobjreference->{speed} ne '')
			      {
			        $gl_detail_ap_clist->append ('Speed',$tmpobjreference->{speed});
			      }
            
			      if ($tmpobjreference->{Arp_comment1} ne '')
			      {
			      	$gl_detail_ap_clist->append ('Arp traffic',$tmpobjreference->{Arp_comment1});
			      }
			      if ($tmpobjreference->{Arp_comment2} ne '')
			      {
			      	$gl_detail_ap_clist->append ('Arp traffic',$tmpobjreference->{Arp_comment2});
			      }
			      if ($tmpobjreference->{Arp_comment3} ne '')
			      {
			      	$gl_detail_ap_clist->append ('Arp traffic',$tmpobjreference->{Arp_comment3});
			      }
		
			      if ($tmpobjreference->{Dhcp_comment} ne '')
			      {
			  	$gl_detail_ap_clist->append ('DHCP traffic',$tmpobjreference->{Dhcp_comment});
			  	$gl_detail_ap_clist->append ('DHCP server',$tmpobjreference->{DHCPserverIdentifier_Ip_1});
			  	$gl_detail_ap_clist->append ('DHCP requester',$tmpobjreference->{Your_ip_addr});
			  	$gl_detail_ap_clist->append ('DHCP subnetmask',$tmpobjreference->{subnetMask_Ip_1});
			  	$gl_detail_ap_clist->append ('DHCP router',$tmpobjreference->{routerList_Ip_1});
			  	$gl_detail_ap_clist->append ('DHCP domainname',$tmpobjreference->{domainName});
			  	$gl_detail_ap_clist->append ('DHCP DNS server',$tmpobjreference->{dnsServerList_Ip_1});
			  	$gl_detail_ap_clist->append ('DHCP DNS server',$tmpobjreference->{dnsServerList_Ip_2});
			      }      
			
			      if ($tmpobjreference->{comment} ne '')
			      {
			        my $tmpcomment = $tmpobjreference->{comment};
			        $tmpcomment =~ s/::NewLine::/\n/g;
			        $gl_detail_ap_clist->append ('User comment',$tmpcomment);
			      }
	
			} # end if
		

		} # end foreach
	} # End if visible	
	return(TRUE);
} # end of sub
sub rebuild_clist
{
	my $filter = shift(@_);
	$gl_clist->clear;
	my $tmprowpos;
	my $tmpmanuf = get_manuf $gl_tmphashref->{sendmac};
	my $tmpstyle = $mainwindow->get_style()->bg('normal');

	foreach my $tmpapref (@gl_accesspoints)
	{
		if ($tmpapref->{Channel} == $filter || $filter == 0)
		{

			my $tmpmanuf = get_manuf $tmpapref->{sendmac};
			#Add it to the clist
			if ($tmpapref->{detssid})
			{
				$tmprowpos = $gl_clist->append (undef,$tmpapref->{Channel},$tmpapref->{detssid},$tmpapref->{sendmac},
		                                           undef,$tmpmanuf,undef);
			}
			else
			{
				$tmprowpos = $gl_clist->append (undef,$tmpapref->{Channel},$tmpapref->{essid},$tmpapref->{sendmac},
		                                           undef,$tmpmanuf,undef);
			}
			





			#Add it also to a hash for faster locate macaddress in row
			my $tmpnamekey = $tmpapref->{essid} . "-" . $tmpapref->{sendmac} . "-" .$tmpapref->{Channel};
			$gl_clist_objects{$tmpnamekey} = $tmprowpos; 

			#-- Add the pixmaps for the clist entries --#
			if ($tmpapref->{essid} eq "Non-broadcasting")
			{
				my ($tmppixmap1,$tmpmask1) = Gtk::Gdk::Pixmap->create_from_xpm_d ($mainwindow->window,$tmpstyle,@gl_logo_network_nonbroadcasting);
				$gl_clist->set_pixmap($tmprowpos,0,$tmppixmap1,$tmpmask1);
			}
			else
			{
				($tmppixmap1,$tmpmask1) = Gtk::Gdk::Pixmap->create_from_xpm_d ($mainwindow->window,$tmpstyle,@gl_logo_network_broadcasting);
				$gl_clist->set_pixmap($tmprowpos,0,$tmppixmap1,$tmpmask1);
			}
			if ($tmpapref->{WEP} == 0)
			{
				my ($tmppixmap1,$tmpmask1) = Gtk::Gdk::Pixmap->create_from_xpm_d ($mainwindow->window,$tmpstyle,@gl_nowep);
				$gl_clist->set_pixtext($tmprowpos,4,"Off",2,$tmppixmap1,$tmpmask1);
			}
			else
			{
				my ($tmppixmap1,$tmpmask1) = Gtk::Gdk::Pixmap->create_from_xpm_d ($mainwindow->window,$tmpstyle,@gl_logo_encrypted);
				$gl_clist->set_pixtext($tmprowpos,4,"On",2,$tmppixmap1,$tmpmask1);
			}
			
			if ($tmpapref->{ISAP})
			{
				my ($tmppixmap1,$tmpmask1) = Gtk::Gdk::Pixmap->create_from_xpm_d ($mainwindow->window,$tmpstyle,@gl_accesspoint_icon);
				$gl_clist->set_pixtext($tmprowpos,6,"ESS",2,$tmppixmap1,$tmpmask1);
			}
			if ($tmpapref->{ISAH})
			{
				my ($tmppixmap1,$tmpmask1) = Gtk::Gdk::Pixmap->create_from_xpm_d ($mainwindow->window,$tmpstyle,@gl_wireless_card_icon);
				$gl_clist->set_pixtext($tmprowpos,6,"IBSS",2,$tmppixmap1,$tmpmask1);
			}


		}

	}

}


#reset
sub reset
{
	# Clear the clist
	$gl_clist->clear();
	# Remove all accesspoints
	undef @gl_accesspoints;
	#clear the tree
	$gl_tree->freeze();
	$gl_tree->clear();

	# Remove the channel tree nodes
	undef @gl_channeltrees;

	# rebuild the tree
	@gl_channeltrees[$gl_clist_objects] = $gl_tree->insert_node(undef,undef,["Show all channels"],2,$channel_icon,$channel_mask,$channel_icon,$channel_mask,FALSE,TRUE);
	#-- Need to get all the channels now --#
	#get_channels;

	# Add the channels to the left
	foreach my $sup_channel (@{$gl_sniff_dev->{sup_channels}})
	{
		@gl_channeltrees[$sup_channel] = $gl_tree->insert_node(undef,undef,["Channel $sup_channel"],2,$channel_icon,$channel_mask,$channel_icon,$channel_mask,FALSE,FALSE);
	}
	$gl_tree->thaw();
	
        undef $gl_clist_objects;
	undef %gl_clist_objects;
	
	$gl_ap_count = 0;

}
sub build_sound_window
{
	
	# Generating the sound window 
	$gl_sound_Window = new Gtk::Window( 'toplevel' );
	$gl_sound_Window->set_transient_for ($mainwindow);
	$gl_sound_Window->title("-=[ Event configuration ]=-");
	$gl_sound_Window->set_default_size(800,300);
	$gl_sound_Window->border_width( 5 );
	my $signals = $gl_sound_Window->signal_connect( 'delete_event', sub{$gl_sound_Window->destroy();$gl_sound_Window=undef;} );

	my $vbox = new Gtk::VBox (FALSE,1);
	$gl_sound_Window->add($vbox);
	my $frame_top = new Gtk::Frame ('');
	my $label_top = new Gtk::Label (' Configure the action you like to bind to specific events ');
	$frame_top->add($label_top);
	$label_top->show();
	$frame_top->show();	
	$vbox->pack_start($frame_top,TRUE,TRUE,FALSE);
	
	my $frame_new_broadcasting_ap_without_wep = new Gtk::Frame ('Found a new broadcasting, cleartext network');
	$frame_new_broadcasting_ap_without_wep->show();
	$vbox->pack_start($frame_new_broadcasting_ap_without_wep,TRUE,TRUE,FALSE);
	my $input_new_broadcasting_ap_without_wep = new Gtk::Entry ( 512 );
	$frame_new_broadcasting_ap_without_wep->add($input_new_broadcasting_ap_without_wep);
	$input_new_broadcasting_ap_without_wep->set_text($gl_conf{new_b_ap_clear});
	$input_new_broadcasting_ap_without_wep->show();
	
	my $frame_new_broadcasting_ap_with_wep = new Gtk::Frame ('Found a new broadcasting, encrypted network');
	$frame_new_broadcasting_ap_with_wep->show();
	$vbox->pack_start($frame_new_broadcasting_ap_with_wep,TRUE,TRUE,FALSE);
	my $input_new_broadcasting_ap_with_wep = new Gtk::Entry ( 512 );
	$frame_new_broadcasting_ap_with_wep->add($input_new_broadcasting_ap_with_wep);
	$input_new_broadcasting_ap_with_wep->set_text($gl_conf{new_b_ap_wep});
	$input_new_broadcasting_ap_with_wep->show();

	my $frame_new_nonbroadcasting_ap_without_wep = new Gtk::Frame ('Found a new non-broadcasting, encrypted network');
	$frame_new_nonbroadcasting_ap_without_wep->show();
	$vbox->pack_start($frame_new_nonbroadcasting_ap_without_wep,TRUE,TRUE,FALSE);
	my $input_new_nonbroadcasting_ap_without_wep = new Gtk::Entry ( 512 );
	$frame_new_nonbroadcasting_ap_without_wep->add($input_new_nonbroadcasting_ap_without_wep);
	$input_new_nonbroadcasting_ap_without_wep->set_text($gl_conf{new_nb_ap_clear});
	$input_new_nonbroadcasting_ap_without_wep->show();

	my $frame_new_nonbroadcasting_ap_with_wep = new Gtk::Frame ('Found a new non-broadcasting, encrypted network');
	$frame_new_nonbroadcasting_ap_with_wep->show();
	$vbox->pack_start($frame_new_nonbroadcasting_ap_with_wep,TRUE,TRUE,FALSE);
	my $input_new_nonbroadcasting_ap_with_wep = new Gtk::Entry ( 512 );
	$frame_new_nonbroadcasting_ap_with_wep->add($input_new_nonbroadcasting_ap_with_wep);
	$input_new_nonbroadcasting_ap_with_wep->set_text($gl_conf{new_nb_ap_wep});
	$input_new_nonbroadcasting_ap_with_wep->show();

	my $frame_uncloacked = new Gtk::Frame ('Discovered a new ESSID of a non-broadcasting network');
	$frame_uncloacked->show();
	$vbox->pack_start($frame_uncloacked,TRUE,TRUE,FALSE);
	my $input_uncloacked = new Gtk::Entry ( 512 );
	$frame_uncloacked->add($input_uncloacked);
	$input_uncloacked->set_text($gl_conf{discovered});
	$input_uncloacked->show();

	my $button_hbox = new Gtk::HBox (FALSE,1);
	
	my $button_ok = new Gtk::Button ('OK');
	my $button_chancel = new Gtk::Button ('Chancel');
	$button_ok->show();
	$button_chancel->show();
	$button_chancel->signal_connect( "clicked", sub {$gl_sound_Window->destroy(); TRUE});

	$button_ok->signal_connect ( "clicked", sub {
							$gl_conf{new_b_ap_clear} = $input_new_broadcasting_ap_without_wep->get_text();
							$gl_conf{new_b_ap_wep} = $input_new_broadcasting_ap_with_wep->get_text();
							$gl_conf{new_nb_ap_clear} = $input_new_nonbroadcasting_ap_without_wep->get_text();
							$gl_conf{new_nb_ap_wep} = $input_new_nonbroadcasting_ap_with_wep->get_text();
							$gl_conf{discovered} = $input_uncloacked->get_text();
							write_conf;
							$gl_sound_Window->destroy();TRUE;
							 });

	$button_hbox->pack_start($button_ok,TRUE,TRUE,FALSE);
	$button_hbox->pack_start($button_chancel,TRUE,TRUE,FALSE);
	$vbox->pack_start($button_hbox,TRUE,TRUE,FALSE);
	$button_hbox->show();
	$vbox->show();	
	$gl_sound_Window->show();

} # End of sub build_sound_window
#All the config file specific stuff
sub write_conf
{
        open (CONFFILE,">$ENV{HOME}/.wellenreiter.conf") or die "could not write to $ENV{HOME}/.wellenreiter.conf";
        print CONFFILE "new_b_ap_wep = $gl_conf{new_b_ap_wep}\n";
        print CONFFILE "new_b_ap_clear = $gl_conf{new_b_ap_clear}\n";
        print CONFFILE "new_nb_ap_wep = $gl_conf{new_nb_ap_wep}\n";
        print CONFFILE "new_nb_ap_clear = $gl_conf{new_nb_ap_clear}\n";
	print CONFFILE "discovered = $gl_conf{discovered}\n";
	close (CONFFILE);
}

sub readin_conf
{
	if (check_conf)
	{
		##-- Read the configfile into the hash %fromconf --##
	        open (CONFFILE,"$ENV{HOME}/.wellenreiter.conf");
	        while (<CONFFILE>) 	
		{
        	        chomp;
   	             #-- Removeing any whitespaces --#
    	            $_ =~ s/ =/=/;
       	            $_ =~ s/= /=/;
                    #-- Splitting at the = so left side is key and right side the value --#
                    if ($_ =~ /^([^\#=]+)=(.*)/) 
                    {
                        $gl_conf{$1} = $2;
                    }
                }
                close (CONFFILE);
	}
	else 
	{
		$gl_conf{new_b_ap_wep} = 'printf "\a"';
		$gl_conf{new_b_ap_clear} = 'printf "\a"';
		$gl_conf{new_nb_ap_wep} = 'printf "\a"';
		$gl_conf{new_nb_ap_clear} = 'printf "\a"';
		$gl_conf{discovered} = 'printf "\a"';
		write_conf;
	}
} #End readin_conf

sub check_conf
{
	if (open (CONFIGFILE,"$ENV{HOME}/.wellenreiter.conf"))
	{
		close (CONFIGFILE);
		return TRUE;
	}
	else
	{
		close (CONFIGFILE);
		return FALSE;
	}
}
#--- probe response frame decoding ---#
sub decode_probe_response
{
	my $packet = $_[0];
	my $retval = 1;
		
	if (length($packet) < 37)
	{ #at least 37 bytes are needed for a probe response frame, otherwise drop it
      		$gl_tmphashref->{type_text} = 'Shit';
   	  	return(0);
	}

    	$gl_tmphashref->{type_text} = 'Probe response frame';

	#-- Get the timestamp
	$gl_tmphashref->{timestamp} = reverse(decode_bytes($packet,'H*',8));
			
        #-- Get the beacon interval
        $gl_tmphashref->{beaconinterval} = reverse(decode_bytes($packet,'h*',2));

	#-- Get the capability flags
	my @capability_flags = split(//,decode_bytes($packet,'b16',2));
	$gl_tmphashref->{ISAP} = @capability_flags[$CP_FLAG_IS_ASCCESSPOINT];
	$gl_tmphashref->{ISAH} = @capability_flags[$CP_FLAG_IS_ADHOC];
    	$gl_tmphashref->{cap_flag_IS_POLLABLE} = @capability_flags[$CP_FLAG_CF_POLLABLE];
        $gl_tmphashref->{cap_flag_POLLREQUEST} = @capability_flags[$CP_FLAG_CF_POLLREQ];
	$gl_tmphashref->{WEP} = @capability_flags[$CP_FLAG_WEP_REQUIRED];
        $gl_tmphashref->{cap_flag_SHORT_PREAMBLE} = @capability_flags[$CP_FLAG_SHORT_PREAMBLE];
        $gl_tmphashref->{cap_flag_PBCC} = @capability_flags[$CP_FLAG_PBCC];
        $gl_tmphashref->{cap_flag_CHANNEL_AGILITY} = @capability_flags[$CP_FLAG_CHANNEL_AGILITY];

	while ($gl_packet_pos < length($packet))
	{
		#-- Get the tagtype and the taglength 
		my $tmptagtype = decode_bytes($packet,'C*',1);
		my $tmptaglen = decode_bytes($packet,'C*',1);
				
		if ($tmptagtype == $TAG_TYPE_SSID)
		{
			if ($tmptaglen > 34)
			{ #at max 34 length on essid possible, otherwise its noise
    		  		$gl_tmphashref->{type_text} = 'Shit';
		  		return(0);
			}

       			$gl_tmphashref->{essid} = decode_bytes($packet,'A*',$tmptaglen);
			$gl_tmphashref->{essid_len} = $tmptaglen;

			if ($gl_tmphashref->{essid_len} > 0 && $gl_tmphashref->{essid} !~ /[a-zA-Z0-9]/)
			{
				$gl_tmphashref->{essid} = "Non-broadcasting";
			}
		}
		elsif ($tmptagtype == $TAG_TYPE_DS_PARAM_CHANNEL)
		{
        		$gl_tmphashref->{Channel} = decode_bytes($packet,'C*',$tmptaglen);
		}
		else
		{
			# unhandled type
			#Jump over the amount of bytes
			$gl_packet_pos = $gl_packet_pos + $tmptaglen; 
		}
			$gl_tmphashref->{isaccesspoint} = 1;
	} #-- Until end of packet --#

	if ($gl_tmphashref->{Channel} > 15 || length($gl_tmphashref->{essid}) < 1)
	{ #This is a shitty packet
		$gl_tmphashref->{type_text} = 'Shit';
		 return(0);
	}


#------------- Adding entrys into tree -------#
		foreach my $entry (@gl_accesspoints)
		{
 			if ($entry->{essid} eq 'Non-broadcasting') #-- When the net got no essid--#
 			{
				 if ($entry->{sendmac} eq $gl_tmphashref->{sendmac}) #--When the response comes from this accesspoint--#
			 	{
			 		if ($entry->{detssid} ne $gl_tmphashref->{essid}) #--When there is not allready a detected essid--#
			 		{
			 			$entry->{detssid} = $gl_tmphashref->{essid};
			 			$entry->{detssidby} = $gl_tmphashref->{type_text};
					 	writetologwin ("The essid of $gl_tmphashref->{sendmac} is $gl_tmphashref->{essid} detected by $gl_tmphashref->{type_text}");
						if ($gl_do_soundevents == 1)
						{
							system("$gl_conf{discovered} &");
						}

					   # Correct the ctree view:
					   my $tmpnamekey = $gl_tmphashref->{essid} . "-" . $gl_tmphashref->{sendmac} . "-" .$gl_tmphashref->{Channel};
					   my $tmprowpos = $gl_clist_objects{$tmpnamekey};
					   $gl_clist->set_text( $tmprowpos, 2, $entry->{detssid});
				 	}
			 	}
			 } 
		} #-- End foreach --#
#Cleanup
$gl_tmphashref = undef;
return ($retval);







} #-- end of sub decode_beacon --#
sub hex_to_IP
{
	my $inputip = shift;
	my $outputip = oct ('0x' . substr($inputip,0,2)) . "." .
     						  oct ('0x' . substr($inputip,2,2)) . "." .
     						  oct ('0x' . substr($inputip,4,2)) . "." . 
     						  oct ('0x' . substr($inputip,6,2));
    return($outputip);
}
#--- Dataframe - Arp - decoding ---#
sub decode_arp
{
	my $packet = $_[0];
	my $retval = 1;

	# 
	# List of opcode values
	#

	my $ARP_OPCODE_REQUEST  = 1;
	my $ARP_OPCODE_REPLY    = 2;
	my $RARP_OPCODE_REQUEST = 3;
	my $RARP_OPCODE_REPLY   = 4;


	#-- decode the arp entry --#
	 my $hw_type = decode_bytes($packet,'n',2);
	 my $proto_type = decode_bytes($packet,'n',2);
	 my $hw_len = decode_bytes($packet,'C',1);
	 my $proto_len = decode_bytes($packet,'C',1);
	 my $opcode = decode_bytes($packet,'n',2);
	 my $src_HW_addr = decode_bytes($packet,'H*',6);
	 my $src_IPhex_addr = decode_bytes($packet,'H*',4);
	 my $dst_HW_addr = decode_bytes($packet,'H*',6);
	 my $dst_IPhex_addr = decode_bytes($packet,'H*',4);
         my $src_IP_addr = oct ('0x' . substr($src_IPhex_addr,0,2)) . "." .
     						  oct ('0x' . substr($src_IPhex_addr,2,2)) . "." .
     						  oct ('0x' . substr($src_IPhex_addr,4,2)) . "." . 
     						  oct ('0x' . substr($src_IPhex_addr,6,2));

	 my $dst_IP_addr = oct ('0x' . substr($dst_IPhex_addr,0,2)) . "." .
     						  oct ('0x' . substr($dst_IPhex_addr,2,2)) . "." .
     						  oct ('0x' . substr($dst_IPhex_addr,4,2)) . "." . 
     						  oct ('0x' . substr($dst_IPhex_addr,6,2));

#------------- Adding arp infos to the object into tree -------#
		foreach my $entry (@gl_accesspoints)
		{
			 if ($entry->{sendmac} eq $gl_tmphashref->{bssmac}) #--When the response comes from this accesspoint--#
		 	{
						if ($opcode == $ARP_OPCODE_REQUEST)
						{
							if (! $entry->{Arp_comment1} || $entry->{Arp_last_used} == 3)
							{
								$entry->{Arp_last_used} = 1;
								$entry->{Arp_comment1} = "$src_IP_addr requesting $dst_IP_addr"; 
							}
							else
							{
								my $tmpkeyname = "Arp_comment" . ($entry->{Arp_last_used} + 1);
								$entry->{$tmpkeyname} = "$src_IP_addr requesting $dst_IP_addr"; 
								$entry->{Arp_last_used} ++;
							}
							writetologwin ("Arp request traffic on bssid $entry->{bssmac}: $src_IP_addr -> $dst_IP_addr\n");
						}
						elsif ($opcode == $ARP_OPCODE_REPLY)
						{
							if (! $entry->{Arp_comment1} || $entry->{Arp_last_used} == 3)
							{
								$entry->{Arp_last_used} = 1;
								$entry->{Arp_comment1} = "$src_IP_addr reply $dst_IP_addr"; 
							}
							else
							{
								my $tmpkeyname = "Arp_comment" . ($entry->{Arp_last_used} + 1);
								$entry->{$tmpkeyname} = "$src_IP_addr reply $dst_IP_addr"; 
								$entry->{Arp_last_used} ++;
							}
						    writetologwin ("Arp reply traffic on bssid $entry->{bssmac}: $src_IP_addr -> $dst_IP_addr\n");
						}
			 } 
		} #-- End foreach --#
	return ($retval);
}
#--- dhcp decoding ---#
sub decode_dhcp
{
	my $packet = $_[0];
	my $retval = 1;

	$gl_tmphashref->{Dop} = decode_bytes($packet,'C',1);

	if ($gl_tmphashref->{Dop} != 2) 
	{
		#-- Only looking for dhcp reply's --#
		return(0);
	}

	$gl_tmphashref->{Htype} = decode_bytes($packet,'H*',1);
	$gl_tmphashref->{Hhlen} = decode_bytes($packet,'C',1);
	$gl_tmphashref->{Hhops} = decode_bytes($packet,'C',1);
	$gl_tmphashref->{Hxid} = decode_bytes($packet,'H*',4);
	$gl_tmphashref->{Dsecs} = decode_bytes($packet,'H*',2);
	$gl_tmphashref->{Hflags} = decode_bytes($packet,'H*',2);
	$gl_tmphashref->{Client_ip_addr} = hex_to_IP (decode_bytes($packet,'H*',4));
	$gl_tmphashref->{Your_ip_addr} = hex_to_IP (decode_bytes($packet,'H*',4));
	$gl_tmphashref->{Next_server_ip_addr} = hex_to_IP (decode_bytes($packet,'H*',4));
	$gl_tmphashref->{Relay_ip_addr} = hex_to_IP (decode_bytes($packet,'H*',4));
	$gl_tmphashref->{Client_haddr} = substr(decode_bytes($packet,'H*',16),0,($gl_tmphashref->{Hhlen} * 2));
	$gl_tmphashref->{dhcp_server_name} = decode_bytes($packet,'H*',64);
	$gl_tmphashref->{dhcp_bootfile_name} = decode_bytes($packet,'H*',128);
	$gl_tmphashref->{dhcp_cookie} = decode_bytes($packet,'H*',4);
	if ($gl_tmphashref->{dhcp_cookie} ne $Magic_cookie)
	{
		#-- Dhcp packets must have the magic cookie, otherwise could be a bootp packet --#
		#-- Skip packets without the cookie --#
		return(0);
	}
	while ($gl_packet_pos < length($packet))
	{
		#-- While in the option field --#
		my $tmpoptiontype = decode_bytes($packet,'C',1);
		my $tmpoptionlen = decode_bytes($packet,'C',1);
		if ($tmpoptiontype == 53)
		{
			my $tmp_value = decode_bytes ($packet,'C',$tmpoptionlen);
			if ($tmp_value == 5) 
			{   #--If it is a DHCP ACK Packet--#
				$gl_tmphashref->{@bootpOptions[$tmpoptiontype]} = "ACK";
			}
			elsif ($tmp_value == 2)
			{
				#--If its is a DHCP offer packet --#
				$gl_tmphashref->{@bootpOptions[$tmpoptiontype]} = "Offer";				
			}
			else 
			{
				#-- Other DHCP message types are not interresting so skip the packet --#
				return(0);
			}   
		}
		elsif ($tmpoptiontype == 54 || $tmpoptiontype == 1 || $tmpoptiontype == 3 || $tmpoptiontype == 6)		
		{
			#-- When it is a ip address from the option --#
			#-- ServerIP, netmask, routerIP , dnsserverIP --#
			my $tmp_count = 0;
			my $tmp_offset = 0;
			my $tmp_value = decode_bytes ($packet,'H*',$tmpoptionlen);
			my $tmp_numof_ip_add = ($tmpoptionlen / 4);
			while ($tmp_count < $tmp_numof_ip_add) 
			{
				#-- While there are some addresses to get --#
				my $tmp_name = @bootpOptions[$tmpoptiontype] . "_Ip_" . ($tmp_count + 1);
				$gl_tmphashref->{$tmp_name} = hex_to_IP (substr($tmp_value,$tmp_offset,8));
				$tmp_count++;
				$tmp_offset = $tmp_offset + 8;
			}
		
		}
		elsif ($tmpoptiontype == 15)
		{
			#-- When it is the domainname option --#
			my $tmp_value = decode_bytes ($packet,'a*',$tmpoptionlen);
			$gl_tmphashref->{@bootpOptions[$tmpoptiontype]} = $tmp_value;
		}
		else
		{
			#-- If it is an uninterresting option, skip it --#
			$gl_packet_pos = $gl_packet_pos + $tmpoptionlen;
		}
		
	} #-- End of packet reached --#

	#-- Display now the dhcp connection to the accesspoint --#
	foreach my $ref_obj (@gl_accesspoints)
	{
		if ($ref_obj->{bssmac} eq $gl_tmphashref->{bssmac})
		{
			writetologwin ("Found dhcp \"$gl_tmphashref->{@bootpOptions[53]}\" traffic on bssid: $ref_obj->{bssmac} on channel: $ref_obj->{Channel}");
	    	$ref_obj->{Dhcp_comment} = "Dhcp $gl_tmphashref->{@bootpOptions[53]}"; 
	    	$ref_obj->{DHCPserverIdentifier_Ip_1} = $gl_tmphashref->{DHCPserverIdentifier_Ip_1};
	    	$ref_obj->{subnetMask_Ip_1} = $gl_tmphashref->{subnetMask_Ip_1};
	    	$ref_obj->{routerList_Ip_1} = $gl_tmphashref->{routerList_Ip_1};
	    	$ref_obj->{domainName} = $gl_tmphashref->{domainName};
	    	$ref_obj->{dnsServerList_Ip_1} = $gl_tmphashref->{dnsServerList_Ip_1};
	    	$ref_obj->{dnsServerList_Ip_2} = $gl_tmphashref->{dnsServerList_Ip_2};
	    	$ref_obj->{Your_ip_addr} = $gl_tmphashref->{Your_ip_addr};
		}
	}
	
}
sub build_popupmenu
{
	my ($event) = @_;
   	my $popupmenu = new Gtk::Menu();
   	$popupmenu->set_title( 'Options' );
	$popupmenu->popup( undef, undef,0,$event->{'button'},undef,undef);

	my $add_comment_menuitem = new Gtk::MenuItem ("Add comment");
   	$popupmenu->append($add_comment_menuitem);
	my $edit_comment_menuitem = new Gtk::MenuItem ("Edit comment");
   	$popupmenu->append($edit_comment_menuitem);
	my $del_comment_menuitem = new Gtk::MenuItem ("Delete comment");
   	$popupmenu->append($del_comment_menuitem);

	#-- Connect the menu events --#
	$add_comment_menuitem->signal_connect('activate', (\&add_comment,$gl_detail_ap_name));
	$edit_comment_menuitem->signal_connect('activate', (\&add_comment,$gl_detail_ap_name));
	$del_comment_menuitem->signal_connect('activate', (\&del_comment,$gl_detail_ap_name));
	$add_comment_menuitem->show();
	$edit_comment_menuitem->show();
	$del_comment_menuitem->show();

} #-- end build_popup_window

#-- Called when menu add comment is clicked --#
sub add_comment
{
	my ($object, $mac) = @_;
	my $comment;
	foreach my $reference (@gl_accesspoints)
	{
		if ($reference->{sendmac} eq $mac)
		{
			if (!$reference->{comment}){$reference->{comment} = ''}; 
			build_textentry_dialog "-=[ Comment ]=-",\$reference->{comment},"Add or edit your comment please";
		}
	}
};

sub del_comment
{
	my ($object, $mac) = @_;
	foreach my $reference (@gl_accesspoints)
	{
		if ($reference->{sendmac} eq $mac)
		{
			$reference->{comment} = '';
			#build_info_dialog "-=[ Confirmation ]=-","The comment is removed";
		}
	}
};

sub build_textentry_dialog
{
 my ($title,$ref_to_buffer,$text_to_display) = @_;
 my $textentry_dialog = new Gtk::Dialog();
 $textentry_dialog->title($title);
 $textentry_dialog->border_width( 5 );
 my $signals = $textentry_dialog->signal_connect( 'delete_event', sub{$textentry_dialog->destroy();} );
 my $label = new Gtk::Label ("\n $text_to_display \n");
 $textentry_dialog->vbox->pack_start($label,TRUE,TRUE,0);
 $label->show();
 #-- Adding the textbox below --#
 my $entrybox = new Gtk::Text(undef,undef);
 $textentry_dialog->vbox->pack_start($entrybox,TRUE,TRUE,0);
 $entrybox->insert(undef,undef,undef,$$ref_to_buffer);
 $entrybox->set_editable(TRUE);
 $entrybox->set_line_wrap(TRUE);
 $entrybox->set_word_wrap(TRUE);

 $entrybox->show();

 #-- Adding the OK Button --#
 my $okbutton = new Gtk::Button('OK');
 $textentry_dialog->action_area->pack_start($okbutton,TRUE,TRUE,0);
 $okbutton->show();
 $okbutton->signal_connect("clicked", 
 							sub{
 								$$ref_to_buffer = $entrybox->get_chars(0,$entrybox->get_length());
 								$$ref_to_buffer =~ s/\n/::NewLine::/g;
 								$textentry_dialog->destroy();
 								});

$textentry_dialog->show(); 
}
##-- This declares all the manufactor --#
#Holding the manufactorlist
sub get_manuf
{
  my $input = shift(@_);
  $input = uc(substr ($input,0,6)); 
  my (%manufactor,$manufactor);

%manufactor = ('000000' => 'XEROX',
'000001' => 'SUPERLAN-2U',
'000002' => 'BBN',
'000003' => 'XEROX',
'000004' => 'XEROX',
'000005' => 'XEROX',
'000006' => 'XEROX',
'000007' => 'XEROX',
'000008' => 'XEROX',
'000009' => 'POWERPIPES',
'00000A' => 'OMRON',
'00000B' => 'MATRIX',
'00000C' => 'CISCO',
'00000D' => 'FIBRONICS',
'00000E' => 'FUJITSU',
'00000F' => 'NEXT',
'000010' => 'HUGHES',
'000011' => 'TEKTRNIX',
'000012' => 'INFORMATION',
'000013' => 'CAMEX',
'000014' => 'NETRONIX',
'000015' => 'DATAPNT',
'000016' => 'DU',
'000017' => 'TEKELEC',
'000018' => 'WEBSTER',
'000019' => 'APPLIED',
'00001A' => 'AMD',
'00001B' => 'NOVELL',
'00001C' => 'JDR',
'00001D' => 'CTRON',
'00001E' => 'TELSIST',
'00001F' => 'CRYPTALL',
'000020' => 'DIAB',
'000021' => 'SC&C',
'000022' => 'VISLTECH',
'000023' => 'ABB',
'000024' => 'OLICOM',
'000025' => 'RAMTEK',
'000026' => 'SHA-KEN',
'000027' => 'JAPAN',
'000028' => 'PRODIGY',
'000029' => 'IMC',
'00002A' => 'TRW',
'00002B' => 'CRISP',
'00002C' => 'NRC',
'00002D' => 'CHROMATICS',
'00002E' => 'SOCIETE',
'00002F' => 'TIMEPLEX',
'000030' => 'VG',
'000031' => 'QPSX',
'000032' => 'GPT',
'000033' => 'EGAN',
'000034' => 'NETWORK',
'000035' => 'SPECTRAGRAPHICS',
'000036' => 'ATARI',
'000037' => 'OXFORD',
'000038' => 'CSS',
'000039' => 'INTEL',
'00003A' => 'CHYRON',
'00003B' => 'HYUNDAI/AXIL',
'00003C' => 'AUSPEX',
'00003D' => 'AT&T',
'00003E' => 'SIMPACT',
'00003F' => 'SYNTREX',
'000040' => 'APPLICON',
'000041' => 'ICE',
'000042' => 'METIER',
'000043' => 'MICRO',
'000044' => 'CASTELL',
'000045' => 'FORD',
'000046' => 'ISC-BR',
'000047' => 'NICOLET',
'000048' => 'EPSON',
'000049' => 'APRICOT',
'00004A' => 'ADC',
'00004B' => 'APT',
'00004C' => 'NEC',
'00004D' => 'DCI',
'00004E' => 'AMPEX',
'00004F' => 'LOGICRAFT',
'000050' => 'RADISYS',
'000051' => 'HOB',
'000052' => 'OPTICAL',
'000053' => 'COMPUCORP',
'000054' => 'MODICON',
'000055' => 'AT&T',
'000056' => 'DR',
'000057' => 'SCITEX',
'000058' => 'RACORE',
'000059' => 'HELLIGE',
'00005A' => 'SK',
'00005B' => 'ELTEC',
'00005C' => 'TELEMATICS',
'00005D' => 'RCE',
'00005E' => 'U',
'00005F' => 'SUMITOMO',
'000060' => 'KONTRON',
'000061' => 'GATEWAY',
'000062' => 'HNEYWELL',
'000063' => 'HP',
'000064' => 'YOKOGAWA',
'000065' => 'NETGENRL',
'000066' => 'TALARIS',
'000067' => 'SOFT',
'000068' => 'ROSEMOUNT',
'000069' => 'SGI',
'00006A' => 'COMPUTER',
'00006B' => 'MIPS',
'00006C' => 'PRIVATE',
'00006D' => 'CASE',
'00006E' => 'ARTISOFT',
'00006F' => 'MADGE',
'000070' => 'HCL',
'000071' => 'ADRA',
'000072' => 'MINIWARE',
'000073' => 'DUPONT',
'000074' => 'RICOH',
'000075' => 'BELL',
'000076' => 'ABEKAS',
'000077' => 'INTERPHASE',
'000078' => 'LABTAM',
'000079' => 'NETWORTH',
'00007A' => 'ARDENT',
'00007B' => 'RESEARCH',
'00007C' => 'AMPERE',
'00007D' => 'CRAY',
'00007E' => 'NETFRAME',
'00007F' => 'LINOTYPE-HELL',
'000080' => 'CRAY',
'000081' => 'SYNOPTCS',
'000082' => 'LECTRA',
'000083' => 'TADPOLE',
'000084' => 'AQUILA',
'000085' => 'CANON',
'000086' => 'GATEWAY',
'000087' => 'HITACHI',
'000088' => 'COMPUTER',
'000089' => 'CAYMAN',
'00008A' => 'DATAHOUSE',
'00008B' => 'INFOTRON',
'00008C' => 'ALLOY',
'00008D' => 'VERDIX',
'00008E' => 'SOLBOURNE',
'00008F' => 'RAYTHEON',
'000090' => 'MICROCOM',
'000091' => 'ANRITSU',
'000092' => 'UNISYS',
'000093' => 'PROTEON',
'000094' => 'ASANTE',
'000095' => 'SONY',
'000096' => 'MARCONI',
'000097' => 'EPOCH',
'000098' => 'CROSS',
'000099' => 'MEMOREX',
'00009A' => 'RC',
'00009B' => 'INFORMATION',
'00009C' => 'ROLM',
'00009D' => 'LOCUS',
'00009E' => 'MARLI',
'00009F' => 'AMERISTAR',
'0000A0' => 'SANYO',
'0000A1' => 'MARQUETTE',
'0000A2' => 'WELLFLT',
'0000A3' => 'NAT',
'0000A4' => 'ACORN',
'0000A5' => 'CSC',
'0000A6' => 'NETWORK',
'0000A7' => 'NCD',
'0000A8' => 'STRATUS',
'0000A9' => 'NETSYS',
'0000AA' => 'XEROX',
'0000AB' => 'LOGIC',
'0000AC' => 'CONWARE',
'0000AD' => 'BRUKER',
'0000AE' => 'DASSAULT',
'0000AF' => 'NUCLEAR',
'0000B0' => 'RND',
'0000B1' => 'ALPHA',
'0000B2' => 'TELEVIDEO',
'0000B3' => 'CIMLINC',
'0000B4' => 'EDIMAX',
'0000B5' => 'DATABILITY',
'0000B6' => 'MICRO-MATIC',
'0000B7' => 'DOVE',
'0000B8' => 'SEIKOSHA',
'0000B9' => 'MCDONNELL',
'0000BA' => 'SIIG',
'0000BB' => 'TRI-DATA',
'0000BC' => 'ALLEN-BRADLEY',
'0000BD' => 'MITSUBISHI',
'0000BE' => 'THE',
'0000BF' => 'SYMMETRIC',
'0000C0' => 'WESTERN',
'0000C1' => 'OLICOM',
'0000C2' => 'INFORMATION',
'0000C3' => 'HARRIS',
'0000C4' => 'WATERS',
'0000C5' => 'FARALLON',
'0000C6' => 'HP',
'0000C7' => 'ARIX',
'0000C8' => 'ALTOS',
'0000C9' => 'EMULEX',
'0000CA' => 'LANCITY',
'0000CB' => 'COMPU-SHACK',
'0000CC' => 'DENSAN',
'0000CD' => 'INDUSTRIAL',
'0000CE' => 'MEGADATA',
'0000CF' => 'HAYES',
'0000D0' => 'DEVELCON',
'0000D1' => 'ADAPTEC',
'0000D2' => 'SBE',
'0000D3' => 'WANG',
'0000D4' => 'PUREDATA',
'0000D5' => 'MICROGNOSIS',
'0000D6' => 'PUNCH',
'0000D7' => 'DARTMOUTH',
'0000D8' => 'OLD',
'0000D9' => 'NIPPON',
'0000DA' => 'ATEX',
'0000DB' => 'BRITISH',
'0000DC' => 'HAYES',
'0000DD' => 'GOULD',
'0000DE' => 'UNIGRAPH',
'0000DF' => 'BELL',
'0000E0' => 'QUADRAM',
'0000E1' => 'HITACHI',
'0000E2' => 'ACER',
'0000E3' => 'INTEGRATED',
'0000E4' => 'MIPS',
'0000E5' => 'SIGMEX',
'0000E6' => 'APTOR',
'0000E7' => 'STAR',
'0000E8' => 'ACCTON',
'0000E9' => 'ISICAD',
'0000EA' => 'UPNOD',
'0000EB' => 'MATSUSHITA',
'0000EC' => 'MICROPROCESS',
'0000ED' => 'APRIL',
'0000EE' => 'NETWORK',
'0000EF' => 'ALANTEC',
'0000F0' => 'SAMSUNG',
'0000F1' => 'MAGNA',
'0000F2' => 'SPIDER',
'0000F3' => 'GANDALF',
'0000F4' => 'ALLIED',
'0000F5' => 'DIAMOND',
'0000F6' => 'MADGE',
'0000F7' => 'YOUTH',
'0000F8' => 'DEC',
'0000F9' => 'QUOTRON',
'0000FA' => 'MICROSAGE',
'0000FB' => 'RECHNER',
'0000FC' => 'MEIKO',
'0000FD' => 'HIGH',
'0000FE' => 'ANNAPOLIS',
'0000FF' => 'CAMTEC',
'000100' => 'EQUIP TRANS',
'000101' => 'PRIVATE',
'000102' => 'BBN',
'000103' => '3COM',
'000104' => 'DVICO',
'000105' => 'BECKHOFF',
'000106' => 'TEWS',
'000107' => 'LEISER',
'000108' => 'AVLAB',
'000109' => 'NAGANO',
'00010A' => 'CIS',
'00010B' => 'SPACE',
'00010C' => 'SYSTEM',
'00010D' => 'CORECO',
'00010E' => 'BRI-LINK',
'00010F' => 'NISHAN',
'000110' => 'GOTHAM',
'000111' => 'IDIGM',
'000112' => 'SHARK',
'000113' => 'OLYMPUS',
'000114' => 'KANDA',
'000115' => 'EXTRATECH',
'000116' => 'NETSPECT',
'000117' => 'CANAL',
'000118' => 'EZ',
'000119' => 'ACTION',
'00011A' => 'EEH',
'00011B' => 'UNIZONE',
'00011C' => 'UNIVERSAL',
'00011D' => 'CENTILLIUM',
'00011E' => 'PRECIDIA',
'00011F' => 'RC',
'000120' => 'OSCILLOQUARTZ',
'000121' => 'RAPIDSTREAM',
'000122' => 'TREND',
'000123' => 'DIGITAL',
'000124' => 'ACER',
'000125' => 'YAESU',
'000126' => 'PAC',
'000127' => 'THE',
'000128' => 'ENJOYWEB',
'000129' => 'DFI',
'00012A' => 'TELEMATICA',
'00012B' => 'TELENET',
'00012C' => 'ARAVOX',
'00012D' => 'KOMODO',
'00012E' => 'PC',
'00012F' => 'TWINHEAD',
'000130' => 'EXTREME',
'000131' => 'DETECTION',
'000132' => 'DRANETZ',
'000133' => 'KYOWA',
'000134' => 'SIG',
'000135' => 'KDC',
'000136' => 'CYBERTAN',
'000137' => 'IT',
'000138' => 'XAVI',
'000139' => 'POINT',
'00013A' => 'SHELCAD',
'00013B' => 'BNA',
'00013C' => 'TIW',
'00013D' => 'RISCSTATION',
'00013E' => 'ASCOM',
'00013F' => 'NEIGHBOR',
'000140' => 'SENDTEK',
'000141' => 'CABLE',
'000142' => 'CISCO',
'000143' => 'IEEE',
'000144' => 'CEREVA',
'000145' => 'WINSYSTEMS',
'000146' => 'TESCO',
'000147' => 'ZHONE',
'000148' => 'X-TRAWEB',
'000149' => 'T',
'00014A' => 'SONY',
'00014B' => 'ENNOVATE',
'00014C' => 'BERKELEY',
'00014D' => 'SHIN',
'00014E' => 'WIN',
'00014F' => 'LUMINOUS',
'000150' => 'MEGAHERTZ',
'000151' => 'ENSEMBLE',
'000152' => 'CHROMATEK',
'000153' => 'ARCHTEK',
'000154' => 'G3M',
'000155' => 'PROMISE',
'000156' => 'FIREWIREDIRECT',
'000157' => 'SYSWAVE',
'000158' => 'ELECTRO',
'000159' => 'S1',
'00015A' => 'DIGITAL',
'00015B' => 'ITALTEL',
'00015C' => 'CADANT',
'00015D' => 'PIRUS',
'00015E' => 'BEST',
'00015F' => 'DIGITAL',
'000160' => 'ELMEX',
'000161' => 'META',
'000162' => 'CYGNET',
'000163' => 'NDC',
'000164' => 'CISCO',
'000165' => 'AIRSWITCH',
'000166' => 'TC',
'000167' => 'HIOKI',
'000168' => 'W&G',
'000169' => 'CELESTIX',
'00016A' => 'ALITEC',
'00016B' => 'LIGHTCHIP',
'00016C' => 'FOXCONN',
'00016D' => 'TRITON',
'00016E' => 'CONKLIN',
'00016F' => 'HAITAI',
'000170' => 'ESE',
'000171' => 'ALLIED',
'000172' => 'TECHNOLAND',
'000173' => 'JNI',
'000174' => 'CYBEROPTICS',
'000175' => 'RADIANT',
'000176' => 'ORIENT',
'000177' => 'EDSL',
'000178' => 'MARGI',
'000179' => 'WIRELESS',
'00017A' => 'CHENGDU',
'00017B' => 'HEIDELBERGER',
'00017C' => 'AG-E',
'00017D' => 'THERMOQUEST',
'00017E' => 'ADTEK',
'00017F' => 'EXPERIENCE',
'000180' => 'AOPEN',
'000181' => 'NORTEL',
'000182' => 'DICA',
'000183' => 'ANITE',
'000184' => 'SIEB',
'000185' => 'ALOKA',
'000186' => 'DISCH',
'000187' => 'I2SE',
'000188' => 'LXCO',
'000189' => 'REFRACTION',
'00018A' => 'ROI',
'00018B' => 'NETLINKS',
'00018C' => 'MEGA',
'00018D' => 'AUDESI',
'00018E' => 'LOGITEC',
'00018F' => 'KENETEC',
'000190' => 'SMK-M',
'000191' => 'SYRED',
'000192' => 'TEXAS',
'000193' => 'HANBYUL',
'000194' => 'CAPITAL',
'000195' => 'SENA',
'000196' => 'CISCO',
'000197' => 'CISCO',
'000198' => 'DARIM',
'000199' => 'HEISEI',
'00019A' => 'LEUNIG',
'00019B' => 'KYOTO',
'00019C' => 'JDS',
'00019D' => 'E-CONTROL',
'00019E' => 'ESS',
'00019F' => 'PHONEX',
'0001A0' => 'INFINILINK',
'0001A1' => 'MAG-TEK',
'0001A2' => 'LOGICAL',
'0001A3' => 'GENESYS',
'0001A4' => 'MICROLINK',
'0001A5' => 'NEXTCOMM',
'0001A6' => 'SCIENTIFIC-ATLANTA',
'0001A7' => 'UNEX',
'0001A8' => 'WELLTECH',
'0001A9' => 'BMW',
'0001AA' => 'AIRSPAN',
'0001AB' => 'MAIN',
'0001AC' => 'SITARA',
'0001AD' => 'COACH',
'0001AE' => 'TREX',
'0001AF' => 'MOTOROLA',
'0001B0' => 'FULLTEK',
'0001B1' => 'GENERAL',
'0001B2' => 'DIGITAL',
'0001B3' => 'PRECISION',
'0001B4' => 'WAYPORT',
'0001B5' => 'TURIN',
'0001B6' => 'SAEJIN',
'0001B7' => 'CENTOS',
'0001B8' => 'NETSENSITY',
'0001B9' => 'SKF',
'0001BA' => 'IC-NET',
'0001BB' => 'FREQUENTIS',
'0001BC' => 'BRAINS',
'0001BD' => 'PETERSON',
'0001BE' => 'GIGALINK',
'0001BF' => 'TELEFORCE',
'0001C0' => 'COMPULAB',
'0001C1' => 'EXBIT',
'0001C2' => 'ARK',
'0001C3' => 'ACROMAG',
'0001C4' => 'NEOWAVE',
'0001C5' => 'SIMPLER',
'0001C6' => 'QUARRY',
'0001C7' => 'CISCO',
'0001C8' => 'THOMAS',
'0001C9' => 'CISCO',
'0001CA' => 'GEOCAST',
'0001CB' => 'NETGAME',
'0001CC' => 'JAPAN',
'0001CD' => 'ARTEM',
'0001CE' => 'CUSTOM',
'0001CF' => 'ALPHA',
'0001D0' => 'VITALPOINT',
'0001D1' => 'CONET',
'0001D2' => 'MACPOWER',
'0001D3' => 'PAXCOMM',
'0001D4' => 'LEISURE',
'0001D5' => 'HAEDONG',
'0001D6' => 'MAN',
'0001D7' => 'F5',
'0001D8' => 'TELTRONICS',
'0001D9' => 'SIGMA',
'0001DA' => 'WINCOMM',
'0001DB' => 'FREECOM',
'0001DC' => 'ACTIVETELCO',
'0001DD' => 'AVAIL',
'0001DE' => 'TRANGO',
'0001DF' => 'ISDN',
'0001E0' => 'FAST',
'0001E1' => 'KINPO',
'0001E2' => 'ANDO',
'0001E3' => 'SIEMENS',
'0001E4' => 'SITERA',
'0001E5' => 'SUPERNET',
'0001E6' => 'HEWLETT-PACKARD',
'0001E7' => 'HEWLETT-PACKARD',
'0001E8' => 'FORCE10',
'0001E9' => 'LITTON',
'0001EA' => 'CIRILIUM',
'0001EB' => 'C-COM',
'0001EC' => 'ERICSSON',
'0001ED' => 'SETA',
'0001EE' => 'COMTROL',
'0001EF' => 'CAMTEL',
'0001F0' => 'TRIDIUM',
'0001F1' => 'INNOVATIVE',
'0001F2' => 'MARK',
'0001F3' => 'QPS',
'0001F4' => 'ENTERASYS',
'0001F5' => 'ERIM',
'0001F6' => 'ASSOCIATION',
'0001F7' => 'IMAGE',
'0001F8' => 'ADHERENT',
'0001F9' => 'TERAGLOBAL',
'0001FA' => 'COMPAQ',
'0001FB' => 'DOTOP',
'0001FC' => 'KEYENCE',
'0001FD' => 'DIGITAL',
'0001FE' => 'DIGITAL',
'0001FF' => 'DATA',
'000200' => 'NET',
'000201' => 'IFM',
'000202' => 'AMINO',
'000203' => 'WOONSANG',
'000204' => 'NOVELL',
'000205' => 'HAMILTON',
'000206' => 'TELITAL',
'000207' => 'VISIONGLOBAL',
'000208' => 'UNIFY',
'000209' => 'SHENZHEN',
'00020A' => 'GEFRAN',
'00020B' => 'NATIVE',
'00020C' => 'METRO-OPTIX',
'00020D' => 'MICRONPC',
'00020E' => 'LAUREL',
'00020F' => 'AATR',
'000210' => 'FENECOM',
'000211' => 'NATURE',
'000212' => 'SIERRACOM',
'000213' => 'S',
'000214' => 'DTVRO',
'000215' => 'COTAS',
'000216' => 'ESI',
'000217' => 'CISCO',
'000218' => 'ADVANCED',
'000219' => 'PARALON',
'00021A' => 'ZUMA',
'00021B' => 'KOLLMORGEN-SERVOTRONIX',
'00021C' => 'NETWORK',
'00021D' => 'DATA',
'00021E' => 'SIMTEL',
'00021F' => 'ACULAB',
'000220' => 'CANON',
'000221' => 'DSP',
'000222' => 'CHROMISYS',
'000223' => 'CLICKTV',
'000224' => 'LANTERN',
'000225' => 'CERTUS',
'000226' => 'XESYSTEMS',
'000227' => 'ESD',
'000228' => 'NECSOM',
'000229' => 'ADTEC',
'00022A' => 'ASOUND',
'00022B' => 'TAMURA',
'00022C' => 'ABB',
'00022D' => 'Lucent/Agere/Apple',
'00022E' => 'TEAC',
'00022F' => 'P-CUBE',
'000230' => 'INTERSOFT',
'000231' => 'AXIS',
'000232' => 'AVISION',
'000233' => 'MANTRA',
'000234' => 'IMPERIAL',
'000235' => 'PARAGON',
'000236' => 'INIT',
'000237' => 'COSMO',
'000238' => 'SEROME',
'000239' => 'VISICOM',
'00023A' => 'ZSK',
'00023B' => 'REDBACK',
'00023C' => 'CREATIVE',
'00023D' => 'NUSPEED',
'00023E' => 'SELTA',
'00023F' => 'COMPAL',
'000240' => 'SEEDEK',
'000241' => 'AMER',
'000242' => 'VIDEOFRAME',
'000243' => 'RAYSIS',
'000244' => 'SURECOM',
'000245' => 'LAMPUS',
'000246' => 'ALL-WIN',
'000247' => 'GREAT',
'000248' => 'PILA',
'000249' => 'AVIV',
'00024A' => 'CISCO',
'00024B' => 'CISCO',
'00024C' => 'SIBYTE',
'00024D' => 'MANNESMAN',
'00024E' => 'DATACARD',
'00024F' => 'IPM',
'000250' => 'GEYSER',
'000251' => 'SOMA',
'000252' => 'CARRIER',
'000253' => 'TELEVIDEO',
'000254' => 'WORLDGATE',
'000255' => 'IBM',
'000256' => 'ALPHA',
'000257' => 'MICROCOM',
'000258' => 'FLYING',
'000259' => 'TSANN',
'00025A' => 'CATENA',
'00025B' => 'CAMBRIDGE',
'00025C' => 'SCI',
'00025D' => 'CALIX',
'00025E' => 'HIGH',
'00025F' => 'NORTEL',
'000260' => 'ACCORDION',
'000261' => 'I3',
'000262' => 'SOYO',
'000263' => 'UPS',
'000264' => 'AUDIORAMP',
'000265' => 'VIRDITECH',
'000266' => 'THERMALOGIC',
'000267' => 'NODE',
'000268' => 'HARRIS',
'000269' => 'NADATEL',
'00026A' => 'COCESS',
'00026B' => 'BCM',
'00026C' => 'PHILIPS',
'00026D' => 'ADEPT',
'00026E' => 'NEGEN',
'00026F' => 'SENAO',
'000270' => 'CREWAVE',
'000271' => 'VPACKET',
'000272' => 'CC&C',
'000273' => 'CORIOLIS',
'000274' => 'TOMMY',
'000275' => 'SMART',
'000276' => 'PRIMAX',
'000277' => 'CASH',
'000278' => 'SAMSUNG',
'000279' => 'CONTROL',
'00027A' => 'IOI',
'00027B' => 'AMPLIFY',
'00027C' => 'TRILITHIC',
'00027D' => 'CISCO',
'00027E' => 'CISCO',
'00027F' => 'ASK-TECHNOLOGIES',
'000280' => 'MU',
'000281' => 'RED-M',
'000282' => 'VIACLIX',
'000283' => 'SPECTRUM',
'000284' => 'ALSTOM',
'000285' => 'RIVERSTONE',
'000286' => 'OCCAM',
'000287' => 'ADAPCOM',
'000288' => 'GLOBAL',
'000289' => 'DNE',
'00028A' => 'AMBIT',
'00028B' => 'VDSL',
'00028C' => 'MICREL-SYNERGY',
'00028D' => 'MOVITA',
'00028E' => 'RAPID',
'00028F' => 'GLOBETEK',
'000290' => 'WOORIGISOOL',
'000291' => 'OPEN',
'000292' => 'LOGIC',
'000293' => 'SOLID',
'000294' => 'TOKYO',
'000295' => 'IP',
'000296' => 'LECTRON',
'000297' => 'C-COR',
'000298' => 'BROADFRAME',
'000299' => 'APEX',
'00029A' => 'STORAGE',
'00029B' => 'KREATEL',
'00029C' => '3COM',
'00029D' => 'MERIX',
'00029E' => 'INFORMATION',
'00029F' => 'L-3',
'0002A0' => 'FLATSTACK',
'0002A1' => 'WORLD',
'0002A2' => 'HILSCHER',
'0002A3' => 'ABB',
'0002A4' => 'ADDPAC',
'0002A5' => 'COMPAQ',
'0002A6' => 'EFFINET',
'0002A7' => 'VIVACE',
'0002A8' => 'AIR',
'0002A9' => 'RACOM',
'0002AA' => 'PLCOM',
'0002AB' => 'CTC',
'0002AC' => '3PAR',
'0002AD' => 'ASAHI',
'0002AE' => 'SCANNEX',
'0002AF' => 'TELECRUZ',
'0002B0' => 'HOKUBU',
'0002B1' => 'ANRITSU',
'0002B2' => 'CABLEVISION',
'0002B3' => 'INTEL',
'0002B4' => 'DAPHNE',
'0002B5' => 'AVNET',
'0002B6' => 'ACROSSER',
'0002B7' => 'WATANABE',
'0002B8' => 'WHI',
'0002B9' => 'CISCO',
'0002BA' => 'CISCO',
'0002BB' => 'CONTINUOUS',
'0002BC' => 'LVL',
'0002BD' => 'BIONET',
'0002BE' => 'TOTSU',
'0002BF' => 'DOTROCKET',
'0002C0' => 'BENCENT',
'0002C1' => 'INNOVATIVE',
'0002C2' => 'NET',
'0002C3' => 'ARELNET',
'0002C4' => 'VECTOR',
'0002C5' => 'EVERTZ',
'0002C6' => 'DATA',
'0002C7' => 'ALPS',
'0002C8' => 'TECHNOCOM',
'0002C9' => 'MELLANOX',
'0002CA' => 'ENDPOINTS',
'0002CB' => 'TRISTATE',
'0002CC' => 'M',
'0002CD' => 'TELEDREAM',
'0002CE' => 'FOXJET',
'0002CF' => 'ZYGATE',
'0002D0' => 'COMDIAL',
'0002D1' => 'VIVOTEK',
'0002D2' => 'WORKSTATION',
'0002D3' => 'NETBOTZ',
'0002D4' => 'PDA',
'0002D5' => 'ACR',
'0002D6' => 'NICE',
'0002D7' => 'EMPEG',
'0002D8' => 'BRECIS',
'0002D9' => 'RELIABLE',
'0002DA' => 'EXIO',
'0002DB' => 'NETSEC',
'0002DC' => 'FUJITSU',
'0002DD' => 'BROMAX',
'0002DE' => 'ASTRODESIGN',
'0002DF' => 'NET',
'0002E0' => 'ETAS',
'0002E1' => 'INTEGRATED',
'0002E2' => 'NDC',
'0002E3' => 'LITE-ON',
'0002E4' => 'JC',
'0002E5' => 'TIMEWARE',
'0002E6' => 'GOULD',
'0002E7' => 'CAB',
'0002E8' => 'E',
'0002E9' => 'CS',
'0002EA' => 'VIDEONICS',
'0002EB' => 'PICO',
'0002EC' => 'MASCHOFF',
'0002ED' => 'DXO',
'0002EE' => 'NOKIA',
'0002EF' => 'CCC',
'0002F0' => 'AME',
'0002F1' => 'PINETRON',
'0002F2' => 'EDEVICE',
'0002F3' => 'MEDIA',
'0002F4' => 'PCTEL',
'0002F5' => 'VIVE',
'0002F6' => 'EQUIPE',
'0002F7' => 'ARM',
'0002F8' => 'SEAKR',
'0002F9' => 'MIMOS',
'0002FA' => 'DX',
'0002FB' => 'BAUMULLER',
'0002FC' => 'CISCO',
'0002FD' => 'CISCO',
'0002FE' => 'VIDITEC',
'0002FF' => 'HANDAN',
'000300' => 'NETCONTINUUM',
'000301' => 'AVANTAS',
'000302' => 'OASYS',
'000303' => 'JAMA',
'000304' => 'PACIFIC',
'000305' => 'SMART',
'000306' => 'FUSION',
'000307' => 'SECURE',
'000308' => 'AM',
'000309' => 'TEXCEL',
'00030A' => 'ARGUS',
'00030B' => 'HUNTER',
'00030C' => 'TELESOFT',
'00030D' => 'UNIWILL',
'00030E' => 'CORE',
'00030F' => 'LEGEND',
'000310' => 'LINK',
'000311' => 'MICRO',
'000312' => 'TR-SYSTEMTECHNIK',
'000313' => 'ACCESS',
'000314' => 'TELEWARE',
'000315' => 'CIDCO',
'000316' => 'NOBELL',
'000317' => 'MERLIN',
'000318' => 'CYRAS',
'000319' => 'INFINEON',
'00031A' => 'BEIJING',
'00031B' => 'CELLVISION',
'00031C' => 'SVENSKA',
'00031D' => 'TAIWAN',
'00031E' => 'OPTRANET',
'00031F' => 'CONDEV',
'000320' => 'XPEED',
'000321' => 'RECO',
'000322' => 'IDIS',
'000323' => 'CORNET',
'000324' => 'TOTTORI',
'000325' => 'ARIMA',
'000326' => 'IWASAKI',
'000327' => 'ACT-L',
'000328' => 'MACE',
'000329' => 'F3',
'00032A' => 'UNIDATA',
'00032B' => 'GAI',
'00032C' => 'ABB',
'00032D' => 'IBASE',
'00032E' => 'SCOPE',
'00032F' => 'GLOBAL',
'000330' => 'IMAGENICS',
'000331' => 'CISCO',
'000332' => 'CISCO',
'000333' => 'DIGITEL',
'000334' => 'NEWPORT',
'000335' => 'MIRAE',
'000336' => 'ZETES',
'000337' => 'VAONE',
'000338' => 'OAK',
'000339' => 'EUROLOGIC',
'00033A' => 'SILICON',
'00033B' => 'TAMI',
'00033C' => 'DAIDEN',
'00033D' => 'ILSHIN',
'00033E' => 'TATEYAMA',
'00033F' => 'BIGBAND',
'000340' => 'FLOWARE',
'000341' => 'AXON',
'000342' => 'NORTEL',
'000343' => 'MARTIN',
'000344' => 'TIETECH',
'000345' => 'ROUTREK',
'000346' => 'HITACHI',
'000347' => 'INTEL',
'000348' => 'NORSCAN',
'000349' => 'VIDICODE',
'00034A' => 'RIAS',
'00034B' => 'NORTEL',
'00034C' => 'SHANGHAI',
'00034D' => 'CHIARO',
'00034E' => 'POS',
'00034F' => 'SUR-GARD',
'000350' => 'BTICINO',
'000351' => 'DIEBOLD',
'000352' => 'COLUBRIS',
'000353' => 'MITAC',
'000354' => 'FIBER',
'000355' => 'TERABEAM',
'000356' => 'WINCOR',
'000357' => 'INTERVOICE-BRITE',
'000358' => 'ICABLE',
'000359' => 'DIGITALSIS',
'00035A' => 'PHOTOTRON',
'00035B' => 'BRIDGEWAVE',
'00035C' => 'SAINT',
'00035D' => 'BOSUNG',
'00035E' => 'METROPOLITAN',
'00035F' => 'SCHUEHLE',
'000360' => 'PAC',
'000361' => 'WIDCOMM',
'000362' => 'VODTEL',
'000363' => 'MIRAESYS',
'000364' => 'SCENIX',
'000365' => 'KIRA',
'000366' => 'ASM',
'000367' => 'JASMINE',
'000368' => 'EMBEDONE',
'000369' => 'NIPPON',
'00036A' => 'MAINNET',
'00036B' => 'CISCO',
'00036C' => 'CISCO',
'00036D' => 'RUNTOP',
'00036E' => 'NICON',
'00036F' => 'TELSEY',
'000370' => 'NXTV',
'000371' => 'ACOMZ',
'000372' => 'ULAN',
'000373' => 'ASELSAN',
'000374' => 'HUNTER',
'000375' => 'NETMEDIA',
'000376' => 'GRAPHTEC',
'000377' => 'GIGABIT',
'000378' => 'HUMAX',
'000379' => 'PROSCEND',
'00037A' => 'TAIYO',
'00037B' => 'IDEC',
'00037C' => 'COAX',
'00037D' => 'STELLCOM',
'00037E' => 'PORTECH',
'00037F' => 'ATHEROS',
'000380' => 'SSH',
'000381' => 'INGENICO',
'000382' => 'A-ONE',
'000383' => 'METERA',
'000384' => 'AETA',
'000385' => 'ACTELIS',
'000386' => 'HO',
'000387' => 'BLAZE',
'000388' => 'FASTFAME',
'000389' => 'PLANTRONICS',
'00038A' => 'AMERICA',
'00038B' => 'PLUS-ONE',
'00038C' => 'TOTAL',
'00038D' => 'PCS',
'00038E' => 'ATOGA',
'00038F' => 'WEINSCHEL',
'000390' => 'DIGITAL',
'000391' => 'ADVANCED',
'000392' => 'HYUNDAI',
'000393' => 'APPLE',
'000394' => 'CONNECT',
'000395' => 'CALIFORNIA',
'000396' => 'EZ',
'000397' => 'WATCHFRONT',
'000398' => 'WISI',
'000399' => 'DONGJU',
'00039A' => 'NSINE',
'00039B' => 'NETCHIP',
'00039C' => 'OPTIMIGHT',
'00039D' => 'ACER',
'00039E' => 'TERA',
'00039F' => 'CISCO',
'0003A0' => 'CISCO',
'0003A1' => 'HIPER',
'0003A2' => 'CATAPULT',
'0003A3' => 'MAVIX',
'0003A4' => 'DATA',
'0003A5' => 'MEDEA',
'0003A6' => 'PRIVATE',
'0003A7' => 'UNIXTAR',
'0003A8' => 'IDOT',
'0003A9' => 'AXCENT',
'0003AA' => 'WATLOW',
'0003AB' => 'BRIDGE',
'0003AC' => 'FRONIUS',
'0003AD' => 'EMERSON',
'0003AE' => 'ALLIED',
'0003AF' => 'PARAGEA',
'0003B0' => 'XSENSE',
'0003B1' => 'ABBOTT',
'0003B2' => 'RADWARE',
'0003B3' => 'IA',
'0003B4' => 'MACROTEK',
'0003B5' => 'ENTRA',
'0003B6' => 'QSI',
'0003B7' => 'ZACCESS',
'0003B8' => 'NETKIT',
'0003B9' => 'HUALONG',
'0003BA' => 'SUN',
'0003BB' => 'SIGNAL',
'0003BC' => 'COT',
'0003BD' => 'OMNICLUSTER',
'0003BE' => 'NETILITY',
'0003BF' => 'CENTERPOINT',
'0003C0' => 'RFTNC',
'0003C1' => 'PACKET',
'0003C2' => 'SOLPHONE',
'0003C3' => 'MICRONIK',
'0003C4' => 'TOMRA',
'0003C5' => 'MOBOTIX',
'0003C6' => 'MORNING',
'0003C7' => 'HOPF',
'0003C8' => 'CML',
'0003C9' => 'TECOM',
'0003CA' => 'MTS',
'0003CB' => 'NIPPON',
'0003CC' => 'MOMENTUM',
'0003CD' => 'CLOVERTECH',
'0003CE' => 'ETEN',
'0003CF' => 'MUXCOM',
'0003D0' => 'KOANKEISO',
'0003D1' => 'TAKAYA',
'0003D2' => 'CROSSBEAM',
'0003D3' => 'INTERNET',
'0003D4' => 'ALLOPTIC',
'0003D5' => 'ADVANCED',
'0003D6' => 'RADVISION',
'0003D7' => 'NEXTNET',
'0003D8' => 'IMPATH',
'0003D9' => 'SECHERON',
'0003DA' => 'TAKAMISAWA',
'0003DB' => 'APOGEE',
'0003DC' => 'LEXAR',
'0003DD' => 'COMARK',
'0003DE' => 'OTC',
'0003DF' => 'DESANA',
'0003E0' => 'RADIOFRAME',
'0003E1' => 'WINMATE',
'0003E2' => 'COMSPACE',
'0003E3' => 'CISCO',
'0003E4' => 'CISCO',
'0003E5' => 'HERMSTEDT',
'0003E6' => 'ENTONE',
'0003E7' => 'LOGOSTEK',
'0003E8' => 'WAVELENGTH',
'0003E9' => 'AKARA',
'0003EA' => 'MEGA',
'0003EB' => 'ATRICA',
'0003EC' => 'ICG',
'0003ED' => 'SHINKAWA',
'0003EE' => 'MKNET',
'0003EF' => 'ONELINE',
'0003F0' => 'REDFERN',
'0003F1' => 'CICADA',
'0003F2' => 'SENECA',
'0003F3' => 'DAZZLE',
'0003F4' => 'NETBURNER',
'0003F5' => 'CHIP2CHIP',
'0003F6' => 'ALLEGRO',
'0003F7' => 'PLAST-CONTROL',
'0003F8' => 'SANCASTLE',
'0003F9' => 'PLEIADES',
'0003FA' => 'TIMETRA',
'0003FB' => 'TOKO',
'0003FC' => 'INTERTEX',
'0003FD' => 'CISCO',
'0003FE' => 'CISCO',
'0003FF' => 'CONNECTIX',
'000400' => 'LEXMARK',
'000401' => 'OSAKI',
'000402' => 'NEXSAN',
'000403' => 'NEXSI',
'000404' => 'MAKINO',
'000405' => 'ACN',
'000406' => 'FA',
'000407' => 'TOPCON',
'000408' => 'SANKO',
'000409' => 'CRATOS',
'00040A' => 'SAGE',
'00040B' => '3COM',
'00040C' => 'KANNO',
'00040D' => 'AVAYA',
'00040E' => 'AVM',
'00040F' => 'ASUS',
'000410' => 'SPINNAKER',
'000411' => 'INKRA',
'000412' => 'WAVESMITH',
'000413' => 'SNOM',
'000414' => 'UMEZAWA',
'000415' => 'RASTEME',
'000416' => 'PARKS',
'000417' => 'ELAU',
'000418' => 'TELTRONIC',
'000419' => 'FIBERCYCLE',
'00041A' => 'INES',
'00041B' => 'DIGITAL',
'00041C' => 'IPDIALOG',
'00041D' => 'COREGA',
'00041E' => 'SHIKOKU',
'00041F' => 'SONY',
'000420' => 'SLIM',
'000421' => 'OCULAR',
'000422' => 'GORDON',
'000423' => 'INTEL',
'000424' => 'TMC',
'000425' => 'ATMEL',
'000426' => 'AUTOSYS',
'000427' => 'CISCO',
'000428' => 'CISCO',
'000429' => 'PIXORD',
'00042A' => 'WIRELESS',
'00042B' => 'IT',
'00042C' => 'MINET',
'00042D' => 'SARIAN',
'00042E' => 'NETOUS',
'00042F' => 'INTERNATIONAL',
'000430' => 'NETGEM',
'000431' => 'GLOBALSTREAMS',
'000432' => 'VOYETRA',
'000433' => 'CYBERBOARD',
'000434' => 'ACCELENT',
'000435' => 'COMPTEK',
'000436' => 'ELANSAT',
'000437' => 'POWIN',
'000438' => 'NORTEL',
'000439' => 'ROSCO',
'00043A' => 'INTELLIGENT',
'00043B' => 'LAVA',
'00043C' => 'SONOS',
'00043D' => 'INDEL',
'00043E' => 'TELENCOMM',
'00043F' => 'ELECTRONIC',
'000440' => 'CYBERPIXIE',
'000441' => 'HALF',
'000442' => 'NACT',
'000443' => 'AGILENT',
'000444' => 'WESTERN',
'000445' => 'LMS',
'000446' => 'CYZENTECH',
'000447' => 'ACROWAVE',
'000448' => 'POLAROID',
'000449' => 'MAPLETREE',
'00044A' => 'IPOLICY',
'00044B' => 'NVIDIA',
'00044C' => 'JENOPTIK',
'00044D' => 'CISCO',
'00044E' => 'CISCO',
'00044F' => 'LEUKHARDT',
'000450' => 'DMD',
'000451' => 'MEDRAD',
'000452' => 'ROCKETLOGIX',
'000453' => 'YOTTA',
'000454' => 'QUADRIGA',
'000455' => 'ANTARA',
'000456' => 'PIPINGHOT',
'000457' => 'UNIVERSAL',
'000458' => 'FUSION',
'000459' => 'VERISTAR',
'00045A' => 'THE',
'00045B' => 'TECHSAN',
'00045C' => 'MOBIWAVE',
'00045D' => 'BEKA',
'00045E' => 'POLY',
'00045F' => 'EVALUE',
'000460' => 'KNILINK',
'000461' => 'EPOX',
'000462' => 'DAKOS',
'000463' => 'PHILIPS',
'000464' => 'FANTASMA',
'000465' => 'IST',
'000466' => 'ARMITEL',
'000467' => 'WUHAN',
'000468' => 'VIVITY',
'000469' => 'INNOCOM',
'00046A' => 'NAVINI',
'00046B' => 'PALM',
'00046C' => 'CYBER',
'00046D' => 'CISCO',
'00046E' => 'CISCO',
'00046F' => 'DIGITEL',
'000470' => 'IPUNPLUGGED',
'000471' => 'IPRAD',
'000472' => 'TELELYNX',
'000473' => 'PHOTONEX',
'000474' => 'LEGRAND',
'000475' => '3',
'000476' => '3',
'000477' => 'SCALANT',
'000478' => 'G',
'000479' => 'RADIUS',
'00047A' => 'AXXESSIT',
'00047B' => 'SCHLUMBERGER',
'00047C' => 'SKIDATA',
'00047D' => 'PELCO',
'00047E' => 'NKF',
'00047F' => 'CHR',
'000480' => 'FOUNDRY',
'000481' => 'ECONOLITE',
'000482' => 'MEDIALOGIC',
'000483' => 'DELTRON',
'000484' => 'AMANN',
'000485' => 'PICOLIGHT',
'000486' => 'ITTC',
'000487' => 'COGENCY',
'000488' => 'EUROTHERM',
'000489' => 'YAFO',
'00048A' => 'TEMIA',
'00048B' => 'POSCON',
'00048C' => 'NAYNA',
'00048D' => 'TONE',
'00048E' => 'OHM',
'00048F' => 'TD',
'000490' => 'OPTICAL',
'000491' => 'TECHNOVISION',
'000492' => 'HIVE',
'000493' => 'TSINGHUA',
'000494' => 'BREEZECOM',
'000495' => 'TEJAS',
'000496' => 'EXTREME',
'000497' => 'MACROSYSTEM',
'000498' => 'PRIVATE',
'000499' => 'CHINO',
'00049A' => 'CISCO',
'00049B' => 'CISCO',
'00049C' => 'SURGIENT',
'00049D' => 'IPANEMA',
'00049E' => 'WIRELINK',
'00049F' => 'METROWERKS',
'0004A0' => 'VERITY',
'0004A1' => 'PATHWAY',
'0004A2' => 'L',
'0004A3' => 'MICROCHIP',
'0004A4' => 'NETENABLED',
'0004A5' => 'BARCO',
'0004A6' => 'SAF',
'0004A7' => 'FABIATECH',
'0004A8' => 'BROADMAX',
'0004A9' => 'SANDSTREAM',
'0004AA' => 'JETSTREAM',
'0004AB' => 'COMVERSE',
'0004AC' => 'IBM',
'0004AD' => 'MALIBU',
'0004AE' => 'LIQUID',
'0004AF' => 'DIGITAL',
'0004B0' => 'ELESIGN',
'0004B1' => 'SIGNAL',
'0004B2' => 'ESSEGI',
'0004B3' => 'VIDEOTEK',
'0004B4' => 'CIAC',
'0004B5' => 'EQUITRAC',
'0004B6' => 'TELLUMAT',
'0004B7' => 'AMB',
'0004B8' => 'KUMAHIRA',
'0004B9' => 'S',
'0004BA' => 'KDD',
'0004BB' => 'BARDAC',
'0004BC' => 'GIANTEC',
'0004BD' => 'MOTOROLA',
'0004BE' => 'OPTXCON',
'0004BF' => 'VERSA',
'0004C0' => 'CISCO',
'0004C1' => 'CISCO',
'0004C2' => 'MAGNIPIX',
'0004C3' => 'CASTOR',
'0004C4' => 'ALLEN',
'0004C5' => 'ASE',
'0004C6' => 'YAMAHA',
'0004C7' => 'NETMOUNT',
'0004C8' => 'LIBA',
'0004C9' => 'MICRO',
'0004CA' => 'FREEMS',
'0004CB' => 'TDSOFT',
'0004CC' => 'PEEK',
'0004CD' => 'INFORMEDIA',
'0004CE' => 'PATRIA',
'0004CF' => 'SEAGATE',
'0004D0' => 'SOFTLINK',
'0004D1' => 'DREW',
'0004D2' => 'ADCON',
'0004D3' => 'TOYOKEIKI',
'0004D4' => 'PROVIEW',
'0004D5' => 'HITACHI',
'0004D6' => 'TAKAGI',
'0004D7' => 'OMITEC',
'0004D8' => 'IPWIRELESS',
'0004D9' => 'TITAN',
'0004DA' => 'RELAX',
'0004DB' => 'TELLUS',
'0004DC' => 'NORTEL',
'0004DD' => 'CISCO',
'0004DE' => 'CISCO',
'0004DF' => 'TERACOM',
'0004E0' => 'PROCKET',
'0004E1' => 'INFINIOR',
'0004E2' => 'SMC',
'0004E3' => 'ACCTON',
'0004E4' => 'DAERYUNG',
'0004E5' => 'GLONET',
'0004E6' => 'BANYAN',
'0004E7' => 'LIGHTPOINTE',
'0004E8' => 'IER',
'0004E9' => 'INFINISWITCH',
'0004EA' => 'HEWLETT-PACKARD',
'0004EB' => 'PAXONET',
'0004EC' => 'MEMOBOX',
'0004ED' => 'BILLION',
'0004EE' => 'LINCOLN',
'0004EF' => 'POLESTAR',
'0004F0' => 'INTERNATIONAL',
'0004F1' => 'WHERENET',
'0004F2' => 'CIRCA',
'0004F3' => 'FS',
'0004F4' => 'INFINITE',
'0004F5' => 'SNOWSHORE',
'0004F6' => 'AMPHUS',
'0004F7' => 'OMEGA',
'0004F8' => 'QUALICABLE',
'0004F9' => 'XTERA',
'0004FA' => 'MIST',
'0004FB' => 'COMMTECH',
'0004FC' => 'STRATUS',
'0004FD' => 'JAPAN',
'0004FE' => 'PELAGO',
'0004FF' => 'ACRONET',
'000500' => 'CISCO',
'000501' => 'CISCO',
'000502' => 'APPLE',
'000503' => 'ICONAG',
'000504' => 'NARAY',
'000505' => 'SYSTEMS',
'000506' => 'REDDO',
'000507' => 'FINE',
'000508' => 'INETCAM',
'000509' => 'AVOC',
'00050A' => 'ICS',
'00050B' => 'SICOM',
'00050C' => 'NETWORK',
'00050D' => 'MIDSTREAM',
'00050E' => '3WARE',
'00050F' => 'TANAKA',
'000510' => 'INFINITE',
'000511' => 'COMPLEMENTATY',
'000512' => 'MESHNETWORKS',
'000513' => 'VTLINX',
'000514' => 'KDT',
'000515' => 'NUARK',
'000516' => 'SMART',
'000517' => 'SHELLCOMM',
'000518' => 'JUPITERS',
'000519' => 'SIEMENS',
'00051A' => '3COM',
'00051B' => 'MAGIC',
'00051C' => 'XNET',
'00051D' => 'AIROCON',
'00051E' => 'RHAPSODY',
'00051F' => 'TAIJIN',
'000520' => 'SMARTRONIX',
'000521' => 'CONTROL',
'000522' => 'LEA*D',
'000523' => 'AVL',
'000524' => 'BTL',
'000525' => 'PURETEK',
'000526' => 'IPAS',
'000527' => 'SJ',
'000528' => 'NEW',
'000529' => 'SHANGHAI',
'00052A' => 'IKEGAMI',
'00052B' => 'HORIBA',
'00052C' => 'SUPREME',
'00052D' => 'ZOLTRIX',
'00052E' => 'CINTA',
'00052F' => 'LEVITON',
'000530' => 'ANDIAMO',
'000531' => 'CISCO',
'000532' => 'CISCO',
'000533' => 'SANERA',
'000534' => 'NORTHSTAR',
'000535' => 'CHIP',
'000536' => 'DANAM',
'000537' => 'NETS',
'000538' => 'MERILUS',
'000539' => 'A',
'00053A' => 'WILLOWGLEN',
'00053B' => 'HARBOUR',
'00053C' => 'XIRCOM',
'00053D' => 'AGERE',
'00053E' => 'KID',
'00053F' => 'VISIONTEK',
'000540' => 'FAST',
'000541' => 'ADVANCED',
'000542' => 'OTARI',
'000543' => 'IQ',
'000544' => 'VALLEY',
'000545' => 'INTERNET',
'000546' => 'KDD',
'000547' => 'STARENT',
'000548' => 'DISCO',
'000549' => 'SALIRA',
'00054A' => 'ARIO',
'00054B' => 'MICRO',
'00054C' => 'RF',
'00054D' => 'BRANS',
'00054E' => 'PHILIPS',
'00054F' => 'PRIVATE',
'000550' => 'DIGI-TECH',
'000551' => 'F',
'000552' => 'XYCOTEC',
'000553' => 'DVC',
'000554' => 'RANGESTAR',
'000555' => 'JAPAN',
'000556' => '360',
'000557' => 'AGILE',
'000558' => 'SYNCHRONOUS',
'000559' => 'INTRACOM',
'00055A' => 'POWER',
'00055B' => 'CHARLES',
'00055C' => 'KOWA',
'00055D' => 'D-LINK',
'00055E' => 'CISCO',
'00055F' => 'CISCO',
'000560' => 'LEADER',
'000561' => 'NAC',
'000562' => 'DIGITAL',
'000563' => 'J-WORKS',
'000564' => 'TSINGHUA',
'000565' => 'TAILYN',
'000566' => 'SECUI',
'000567' => 'ETYMONIC',
'000568' => 'PILTOFISH',
'000569' => 'VMWARE',
'00056A' => 'HEUFT',
'00056B' => 'C',
'00056C' => 'HUNG',
'00056D' => 'PACIFIC',
'00056E' => 'NATIONAL',
'00056F' => 'INNOMEDIA',
'000570' => 'BAYDEL',
'000571' => 'SEIWA',
'000572' => 'DEONET',
'000573' => 'CISCO',
'000574' => 'CISCO',
'000575' => 'CDS-ELECTRONICS',
'000576' => 'NSM',
'000577' => 'SM',
'000578' => 'PRIVATE',
'000579' => 'UNIVERSAL',
'00057A' => 'HATTERAS',
'00057B' => 'CHUNG',
'00057C' => 'RCO',
'00057D' => 'SUN',
'00057E' => 'ECKELMANN',
'00057F' => 'ACQIS',
'000580' => 'FIBROLAN',
'000581' => 'SNELL',
'000582' => 'CLEARCUBE',
'000583' => 'IMAGECOM',
'000584' => 'ABSOLUTEVALUE',
'000585' => 'JUNIPER',
'000586' => 'LUCENT',
'000587' => 'LOCUS',
'000588' => 'SENSORIA',
'000589' => 'NATIONAL',
'00058A' => 'NETCOM',
'00058B' => 'IPMENTAL',
'00058C' => 'OPENTECH',
'00058D' => 'LYNX',
'00058E' => 'AHEAD',
'00058F' => 'CLCSOFT',
'000590' => 'SWISSVOICE',
'000591' => 'ACTIVE',
'000592' => 'PULTEX',
'000593' => 'GRAMMAR',
'000594' => 'IXXAT',
'000595' => 'ALESIS',
'000596' => 'GENOTECH',
'000597' => 'EAGLE',
'000598' => 'CRONOS',
'000599' => 'PEI',
'00059A' => 'POWERCOMPUTING',
'00059B' => 'CISCO',
'00059C' => 'KLEINKNECHT',
'00059D' => 'DANIEL',
'00059E' => 'ZINWELL',
'00059F' => 'YOTTA',
'0005A0' => 'MOBILINE',
'0005A1' => 'ZENOCOM',
'0005A2' => 'CELOX',
'0005A3' => 'QEI',
'0005A4' => 'LUCID',
'0005A5' => 'KOTT',
'0005A6' => 'EXTRON',
'0005A7' => 'HYPERCHIP',
'0005A8' => 'POWERCOMPUTING',
'0005A9' => 'PRINCETON',
'0005AA' => 'MOORE',
'0005AB' => 'CYBER',
'0005AC' => 'NORTHERN',
'0005AD' => 'TOPSPIN',
'0005AE' => 'MEDIAPORT',
'0005AF' => 'INNOSCAN',
'0005B0' => 'KOREA',
'0005B1' => 'ASB',
'0005B2' => 'MEDISON',
'0005B3' => 'ASAHI-ENGINEERING',
'0005B4' => 'ACEEX',
'0005B5' => 'BROADCOM',
'0005B6' => 'INSYS',
'0005B7' => 'ARBOR',
'0005B8' => 'ELECTRONIC',
'0005B9' => 'AIRVANA',
'0005BA' => 'AREA',
'0005BB' => 'PRIVATE',
'0005BC' => 'RESORSYS',
'0005BD' => 'ROAX',
'0005BE' => 'KONGSBERG',
'0005BF' => 'JUSTEZY',
'0005C0' => 'DIGITAL',
'0005C1' => 'A-KYUNG',
'0005C2' => 'DIGITAL',
'0005C3' => 'PACIFIC',
'0005C4' => 'TELECT',
'0005C5' => 'FLAGA',
'0005C6' => 'TRIZ',
'0005C7' => 'I/F-COM',
'0005C8' => 'VERYTECH',
'0005C9' => 'LG',
'0005CA' => 'HITRON',
'0005CB' => 'ROIS',
'0005CC' => 'SUMTEL',
'0005CD' => 'NIPPON',
'0005CE' => 'PROLINK',
'0005CF' => 'THUNDER',
'0005D0' => 'SOLINET',
'0005D1' => 'METAVECTOR',
'0005D2' => 'DAP',
'0005D3' => 'EPRODUCTION',
'0005D4' => 'FUTURESMART',
'0005D5' => 'SPEEDCOM',
'0005D6' => 'TITAN',
'0005D7' => 'VISTA',
'0005D8' => 'ARESCOM',
'0005D9' => 'TECHNO',
'0005DA' => 'APEX',
'0005DB' => 'NENTEC',
'0005DC' => 'CISCO',
'0005DD' => 'CISCO',
'0005DE' => 'GI',
'0005DF' => 'ELECTRONIC',
'0005E0' => 'EMPIRIX',
'0005E1' => 'TRELLIS',
'0005E2' => 'CREATIV',
'0005E3' => 'LIGHTSAND',
'0005E4' => 'RED',
'0005E5' => 'RENISHAW',
'0005E6' => 'EGENERA',
'0005E7' => 'NETRAKE',
'0005E8' => 'TURBOWAVE',
'0005E9' => 'UNICESS',
'0005EA' => 'REDNIX',
'0005EB' => 'BLUE',
'0005EC' => 'MOSAIC',
'0005ED' => 'TECHNIKUM',
'0005EE' => 'BEWATOR',
'0005EF' => 'ADOIR',
'0005F0' => 'SATEC',
'0005F1' => 'VRCOM',
'0005F2' => 'POWER',
'0005F3' => 'WEBOYN',
'0005F4' => 'SYSTEMBASE',
'0005F5' => 'OYO',
'0005F6' => 'YOUNG',
'0005F7' => 'ANALOG',
'0005F8' => 'REAL',
'0005F9' => 'TOA',
'0005FA' => 'IPOPTICAL',
'0005FB' => 'SHAREGATE',
'0005FC' => 'SCHENCK',
'0005FD' => 'PACKETLIGHT',
'0005FE' => 'TRAFICON',
'0005FF' => 'SNS',
'000600' => 'TOKYO',
'000601' => 'OTANIKEIKI',
'000602' => 'CIRKITECH',
'000603' => 'BAKER',
'000604' => '@TRACK',
'000605' => 'INNCOM',
'000606' => 'RAPIDWAN',
'000607' => 'OMNI-DIRECTIONAL',
'000608' => 'AT-SKY',
'000609' => 'CROSSPORT',
'00060A' => 'BLUE2SPACE',
'00060B' => 'PACELINE',
'00060C' => 'MELCO',
'00060D' => 'HP',
'00060E' => 'IGSYS',
'00060F' => 'NARAD',
'000610' => 'ABEONA',
'000611' => 'ZEUS',
'000612' => 'ACCUSYS',
'000613' => 'KAWASAKI',
'000614' => 'PRISM',
'000615' => 'KIMOTO',
'000616' => 'TEL',
'000617' => 'REDSWITCH',
'000618' => 'DIGIPOWER',
'000619' => 'CONNECTION',
'00061A' => 'ZETARI',
'00061B' => 'PORTABLE',
'00061C' => 'HOSHINO',
'00061D' => 'MIP',
'00061E' => 'MAXAN',
'00061F' => 'VISION',
'000620' => 'SERIAL',
'000621' => 'HINOX',
'000622' => 'CHUNG',
'000623' => 'MGE',
'000624' => 'GENTNER',
'000625' => 'THE',
'000626' => 'MWE',
'000627' => 'UNIWIDE',
'000628' => 'CISCO',
'000629' => 'IBM',
'00062A' => 'CISCO',
'00062B' => 'INTRASERVER',
'00062C' => 'NETWORK',
'00062D' => 'TOUCHSTAR',
'00062E' => 'ARISTOS',
'00062F' => 'PIVOTECH',
'000630' => 'ADTRANZ',
'000631' => 'OPTICAL',
'000632' => 'MESCO',
'000633' => 'HEIMANN',
'000634' => 'GTE',
'000635' => 'PACKETAIR',
'000636' => 'JEDAI',
'000637' => 'TOPTREND-META',
'000638' => 'SUNGJIN',
'000639' => 'NEWTEC',
'00063A' => 'DURA',
'00063B' => 'LINEO',
'00063C' => 'NMI',
'00063D' => 'MICROWAVE',
'00063E' => 'OPTHOS',
'00063F' => 'EVEREX',
'000640' => 'WHITE',
'000641' => 'ITCN',
'000642' => 'GENETEL',
'000643' => 'SONO',
'000644' => 'NEIX',
'000645' => 'MEISEI',
'000646' => 'SHENZHEN',
'000647' => 'ETRALI',
'000648' => 'SEEDSWARE',
'000649' => 'QUANTE',
'00064A' => 'HONEYWELL',
'00064B' => 'ALEXON',
'00064C' => 'INVICTA',
'00064D' => 'SENCORE',
'00064E' => 'BROAD',
'00064F' => 'PRO-NETS',
'000650' => 'TIBURON',
'000651' => 'ASPEN',
'000652' => 'CISCO',
'000653' => 'CISCO',
'000654' => 'MAXXIO',
'000655' => 'YIPEE',
'000656' => 'TACTEL',
'000657' => 'MARKET',
'000658' => 'HELMUT',
'000659' => 'EAL',
'00065A' => 'STRIX',
'00065B' => 'DELL',
'00065C' => 'MALACHITE',
'00065D' => 'HEIDELBERG',
'00065E' => 'PHOTURIS',
'00065F' => 'ECI',
'000660' => 'NADEX',
'000661' => 'NIA',
'000662' => 'MBM',
'000663' => 'HUMAN',
'000664' => 'FOSTEX',
'000665' => 'SUNNY',
'000666' => 'ROVING',
'000667' => 'TRIPP',
'000668' => 'VICON',
'000669' => 'DATASOUND',
'00066A' => 'INFINICON',
'00066B' => 'SYSMEX',
'00066C' => 'ROBINSON',
'00066D' => 'COMPUPRINT',
'00066E' => 'DELTA',
'00066F' => 'KOREA',
'000670' => 'UPPONETTI',
'000671' => 'SOFTING',
'000672' => 'NETEZZA',
'000673' => 'OPTELECOM',
'000674' => 'SPECTRUM',
'000675' => 'BANDERACOM',
'000676' => 'NOVRA',
'000677' => 'SICK',
'000678' => 'MARANTZ',
'000679' => 'KONAMI',
'00067A' => 'JMP',
'00067B' => 'TOPLINK',
'00067C' => 'CISCO',
'00067D' => 'TAKASAGO',
'00067E' => 'WINCOM',
'00067F' => 'REARDEN',
'000680' => 'CARD',
'000681' => 'GOEPEL',
'000682' => 'CONVEDIA',
'000683' => 'BRAVARA',
'000684' => 'BIACORE',
'000685' => 'NETNEARU',
'000686' => 'ZARDCOM',
'000687' => 'OMNITRON',
'000688' => 'TELWAYS',
'000689' => 'YLEZ',
'00068A' => 'NEURONNET',
'00068B' => 'AIR',
'00068C' => '3COM',
'00068D' => 'SANGATE',
'00068E' => 'HID',
'00068F' => 'TELEMONITOR',
'000690' => 'EURACOM',
'000691' => 'PT',
'000692' => 'INTRUVERT',
'000693' => 'FLEXUS',
'000694' => 'MOBILLIAN',
'000695' => 'ENSURE',
'000696' => 'ADVENT',
'000697' => 'R',
'000698' => 'EGNITE',
'000699' => 'VIDA',
'00069A' => 'E',
'00069B' => 'AVT',
'00069C' => 'TRANSMODE',
'00069D' => 'PETARDS',
'00069E' => 'UNIQA',
'00069F' => 'KUOKOA',
'0006A0' => 'MX',
'0006A1' => 'CELSIAN',
'0006A2' => 'TRANSILICA',
'0006A3' => 'BITRAN',
'0006A4' => 'INNOWELL',
'0006A5' => 'PINON',
'0006A6' => 'ARTISTIC',
'0006A7' => 'PRIMARION',
'0006A8' => 'KC',
'0006A9' => 'UNIVERSAL',
'0006AA' => 'MILTOPE',
'0006AB' => 'W-LINK',
'0006AC' => 'INTERSOFT',
'0006AD' => 'KB',
'0006AE' => 'HIMACHAL',
'0006AF' => 'PRIVATE',
'0006B0' => 'COMTECH',
'0006B1' => 'SONICWALL',
'0006B2' => 'LINXTEK',
'0006B3' => 'DIAGRAPH',
'0006B4' => 'VORNE',
'0006B5' => 'LUMINENT',
'0006B6' => 'NIR-OR',
'0006B7' => 'TELEM',
'0006B8' => 'BANDSPEED',
'0006B9' => 'A5TEK',
'0006BA' => 'WESTWAVE',
'0006BB' => 'ATI',
'0006BC' => 'MACROLINK',
'0006BD' => 'BNTECHNOLOGY',
'0006BE' => 'BAUMER',
'0006BF' => 'ACCELLA',
'0006C0' => 'UNITED',
'0006C1' => 'CISCO',
'0006C2' => 'SMARTMATIC',
'0006C3' => 'SCHINDLER',
'0006C4' => 'PIOLINK',
'0006C5' => 'INNOVI',
'0006C6' => 'LESSWIRE',
'0006C7' => 'RFNET',
'0006C8' => 'SUMITOMO',
'0006C9' => 'TECHNICAL',
'0006CA' => 'AMERICAN',
'0006CB' => 'JOTRON',
'0006CC' => 'JMI',
'0006CD' => 'CREOSCITEX',
'0006CE' => 'DATENO',
'0006CF' => 'THALES',
'0006D0' => 'ELGAR',
'0006D1' => 'TAHOE',
'0006D2' => 'TUNDRA',
'0006D3' => 'ALPHA',
'0006D4' => 'INTERACTIVE',
'0006D5' => 'DIAMOND',
'0006D6' => 'CISCO',
'0006D7' => 'CISCO',
'0006D8' => 'MAPLE',
'0006D9' => 'IPM-NET',
'0006DA' => 'ITRAN',
'0006DB' => 'ICHIPSCO',
'0006DC' => 'SYABAS',
'0006DD' => 'AT',
'0006DE' => 'FLASH',
'0006DF' => 'AIDONIC',
'0006E0' => 'MAT',
'0006E1' => 'TECHNO',
'0006E2' => 'CEEMAX',
'0006E3' => 'QUANTITATIVE',
'0006E4' => 'CITEL',
'0006E5' => 'FUJIAN',
'0006E6' => 'DONGYANG',
'0006E7' => 'BIT',
'0006E8' => 'OPTICAL',
'0006E9' => 'INTIME',
'0006EA' => 'ELZET80',
'0006EB' => 'GLOBAL',
'0006EC' => 'M/A',
'0006ED' => 'INARA',
'0006EE' => 'SHENYANG',
'0006EF' => 'MAXXAN',
'0006F0' => 'DIGEO',
'0006F1' => 'OPTILLION',
'0006F2' => 'PLATYS',
'0006F3' => 'ACCELIGHT',
'0006F4' => 'PRIME',
'0006F8' => 'PRIVATE',
'0006F9' => 'MITSUI',
'0006FA' => 'IP',
'0006FB' => 'HITACHI',
'0006FC' => 'FNET',
'0006FD' => 'COMJET',
'0006FE' => 'CELION',
'0006FF' => 'SHEBA',
'000700' => 'ZETTAMEDIA',
'000701' => 'CISCO',
'000702' => 'VARIAN',
'000703' => 'CSEE',
'000705' => 'ENDRESS',
'000706' => 'SANRITZ',
'000707' => 'INTERALIA',
'000708' => 'BITRAGE',
'000709' => 'WESTERSTRAND',
'00070A' => 'UNICOM',
'00070B' => 'OCTAL',
'00070C' => 'SVA-INTRUSION',
'00070D' => 'CISCO',
'00070E' => 'CISCO',
'00070F' => 'FUJANT',
'000710' => 'ADAX',
'000711' => 'ACTERNA',
'000712' => 'JAL',
'000713' => 'IP',
'000714' => 'BRIGHTCOM',
'000715' => 'GENERAL',
'000716' => 'J',
'000717' => 'WIELAND',
'000718' => 'ICANTEK',
'000719' => 'MOBIIS',
'00071A' => 'FINEDIGITAL',
'00071B' => 'POSITION',
'00071C' => 'AT&T',
'00071D' => 'SATELSA',
'00071E' => 'TRI-M',
'00071F' => 'EUROPEAN',
'000720' => 'TRUTZSCHLER',
'000721' => 'FORMAC',
'000722' => 'NIELSEN',
'000723' => 'ELCON',
'000724' => 'TELEMAX',
'000725' => 'BEMATECH',
'000727' => 'ZI',
'000728' => 'NEO',
'000729' => 'KISTLER',
'00072A' => 'INNOVANCE',
'00072B' => 'JUNG',
'00072C' => 'FABRICOM',
'00072D' => 'CNSYSTEMS',
'00072E' => 'NORTH',
'00072F' => 'INSTRANSA',
'000730' => 'HUTCHISON',
'000731' => 'SPIRICON',
'000732' => 'AAEON',
'000733' => 'DANCONTROL',
'000734' => 'AGILE',
'000735' => 'FLARION',
'000736' => 'DATA',
'000737' => 'SORIYA',
'000738' => 'YOUNG',
'000739' => 'MOTION',
'00073A' => 'INVENTEL',
'00073B' => 'TENOVIS',
'00073C' => 'TELECOM',
'00073D' => 'NANJING',
'00073E' => 'CHINA',
'00073F' => 'WOOJYUN',
'000740' => 'MELCO',
'000741' => 'SIERRA',
'000742' => 'CURRENT',
'000743' => 'CHELSIO',
'000744' => 'UNICO',
'000745' => 'RADLAN',
'000746' => 'INTERLINK',
'000747' => 'MECALC',
'000748' => 'THE',
'000749' => 'CENIX',
'00074A' => 'CARL',
'00074B' => 'DAIHEN',
'00074C' => 'BEICOM',
'00074D' => 'ZEBRA',
'00074E' => 'NAUGHTY',
'00074F' => 'CISCO',
'000750' => 'CISCO',
'000751' => 'M',
'000752' => 'RHYTHM',
'000753' => 'BEIJING',
'000754' => 'XYTERRA',
'000755' => 'LAFON',
'000756' => 'JUYOUNG',
'000757' => 'TOPCALL',
'000758' => 'DRAGONWAVE',
'000759' => 'BORIS',
'00075A' => 'AIR',
'00075B' => 'GIBSON',
'00075C' => 'ENCAD',
'00075D' => 'CELLERITAS',
'00075E' => 'PULSAR',
'00075F' => 'VCS',
'000760' => 'TOMIS',
'000761' => 'LOGITECH',
'000762' => 'GROUP',
'000763' => 'SUNNIWELL',
'000764' => 'YOUNGWOO',
'000765' => 'JADE',
'000766' => 'CHOU',
'000767' => 'YUXING',
'000768' => 'DANFOSS',
'000769' => 'ITALIANA',
'00076A' => 'NEXTEYE',
'00076B' => 'STRALFORS',
'00076C' => 'DAEHANET',
'00076D' => 'FLEXLIGHT',
'00076E' => 'SINETICA',
'00076F' => 'SYNOPTICS',
'000770' => 'LOCUSNETWORKS',
'000771' => 'EMBEDDED',
'000772' => 'SHANGHAI',
'000773' => 'ASCOM',
'000774' => 'GUANGZHOU',
'000775' => 'VALENCE',
'000776' => 'FEDERAL',
'000777' => 'MOTAH',
'000778' => 'GERSTEL',
'000779' => 'SUNGIL',
'00077A' => 'INFOWARE',
'00077B' => 'MILLIMETRIX',
'00077C' => 'ONTIME',
'00077E' => 'ELREST',
'00077F' => 'J',
'000780' => 'BLUEGIGA',
'000781' => 'ITRON',
'000782' => 'NAUTICUS',
'000783' => 'SYNCOM',
'000784' => 'CISCO',
'000785' => 'CISCO',
'000786' => 'WIRELESS',
'000787' => 'IDEA',
'000788' => 'CLIPCOMM',
'000789' => 'EASTEL',
'00078A' => 'MENTOR',
'00078B' => 'WEGENER',
'00078C' => 'ELEKTRONIKSPECIALISTEN',
'00078D' => 'NETENGINES',
'00078E' => 'GARZ',
'00078F' => 'EMKAY',
'000790' => 'TRI-M',
'000791' => 'INTERNATIONAL',
'000792' => 'SUETRON',
'000793' => 'PRIVATE',
'000794' => 'SIMPLE',
'000795' => 'ELITEGROUP',
'000796' => 'LSI',
'000797' => 'NETPOWER',
'000798' => 'SELEA',
'000799' => 'TIPPING',
'00079A' => 'SMARTSIGHT',
'00079B' => 'AURORA',
'00079C' => 'GOLDEN',
'00079D' => 'MUSASHI',
'00079E' => 'ILINX',
'00079F' => 'ACTION',
'0007A0' => 'E-WATCH',
'0007A1' => 'VIASYS',
'0007A2' => 'OPTEON',
'0007A3' => 'OSITIS',
'0007A4' => 'GN',
'0007A5' => 'Y',
'0007A6' => 'HOME',
'0007A7' => 'A-Z',
'0007A8' => 'HAIER',
'0007A9' => 'NOVASONICS',
'0007AA' => 'QUANTUM',
'0007AC' => 'EOLRING',
'0007AD' => 'PENTACON',
'0007AE' => 'LAYER',
'0007AF' => 'N-TRON',
'0007B0' => 'OFFICE',
'0007B1' => 'EQUATOR',
'0007B2' => 'TRANSACCESS',
'0007B3' => 'CISCO',
'0007B4' => 'CISCO',
'0007B5' => 'ANY',
'0007B6' => 'TELECOM',
'0007B7' => 'SAMURAI',
'0007B8' => 'AMERICAN',
'0007B9' => 'GINGANET',
'0007BA' => 'XEBEO',
'0007BB' => 'CONFLUENCE',
'0007BC' => 'IDENTIX',
'0007BD' => 'RADIONET',
'0007BE' => 'DATALOGIC',
'0007BF' => 'ARMILLAIRE',
'0007C0' => 'NETZERVER',
'0007C1' => 'OVERTURE',
'0007C2' => 'NETSYS',
'0007C3' => 'CIRPACK',
'0007C4' => 'JEAN',
'0007C5' => 'GCOM',
'0007C6' => 'VDS',
'0007C7' => 'SYNECTICS',
'0007C8' => 'BRAIN21',
'0007C9' => 'TECHNOL',
'0007CA' => 'CREATIX',
'0007CB' => 'FREEBOX',
'0007CC' => 'KABA',
'0007CD' => 'NMTEL',
'0007CE' => 'CABLETIME',
'0007CF' => 'ANOTO',
'0007D0' => 'AUTOMAT',
'0007D1' => 'SPECTRUM',
'0007D2' => 'LOGOPAK',
'0007D3' => 'STORK',
'0007D4' => 'ZHEJIANG',
'0007D5' => '3E',
'0007D6' => 'COMMIL',
'0007D7' => 'CAPORIS',
'0007D8' => 'HITRON',
'0007D9' => 'SPLICECOM',
'0007DA' => 'NEURO',
'0007DB' => 'KIRANA',
'0007DC' => 'ATEK',
'0007DD' => 'CRADLE',
'0007DE' => 'ECOPILT',
'0007DF' => 'VBRICK',
'0007E0' => 'PALM',
'0007E1' => 'WIS',
'0007E2' => 'BITWORKS',
'0007E3' => 'NAVCOM',
'0007E4' => 'SOFTRADIO',
'0007E5' => 'COUP',
'0007E6' => 'EDGEFLOW',
'0007E7' => 'FREEWAVE',
'0007E8' => 'ST',
'0007E9' => 'INTEL',
'0007EA' => 'MASSANA',
'0007EB' => 'CISCO',
'0007EC' => 'CISCO',
'0007ED' => 'ALTERA',
'0007EE' => 'TELCO',
'0007EF' => 'LOCKHEED',
'0007F0' => 'LOGISYNC',
'0007F1' => 'TERABURST',
'0007F2' => 'IOA',
'0007F3' => 'THINK',
'0007F4' => 'ELETEX',
'0007F5' => 'BRIDGECO',
'0007F6' => 'QQEST',
'0007F7' => 'GALTRONICS',
'0007F8' => 'ITDEVICES',
'0007F9' => 'PHONETICS',
'0007FA' => 'ITT',
'0007FB' => 'GIGA',
'0007FC' => 'ADEPT',
'0007FD' => 'LANERGY',
'0007FE' => 'RIGAKU',
'0007FF' => 'GLUON',
'000800' => 'MULTITECH',
'000801' => 'HIGHSPEED',
'000802' => 'COMPAQ',
'000803' => 'COS',
'000804' => 'ICA',
'000805' => 'TECHNO-HOLON',
'000806' => 'RAONET',
'000807' => 'ACCESS',
'000808' => 'PPT',
'000809' => 'SYSTEMONIC',
'00080A' => 'ESPERA-WERKE',
'00080B' => 'BIRKA',
'00080C' => 'VDA',
'00080D' => 'TOSHIBA',
'00080E' => 'MOTOROLA',
'00080F' => 'PROXIMION',
'000810' => 'KEY',
'000811' => 'VOIX',
'000812' => 'GM-2',
'000813' => 'DISKBANK',
'000814' => 'TIL',
'000815' => 'CATS',
'000816' => 'BLUETAGS',
'000817' => 'EMERGECORE',
'000818' => 'PIXELWORKS',
'000819' => 'BANKSYS',
'00081A' => 'SANRAD',
'00081B' => 'WINDIGO',
'00081C' => '@POS',
'00081D' => 'IPSIL',
'00081E' => 'REPEATIT',
'00081F' => 'POU',
'000820' => 'CISCO',
'000821' => 'CISCO',
'000822' => 'INPRO',
'000823' => 'TEXA',
'000824' => 'PROMATEK',
'000825' => 'ACME',
'000826' => 'COLORADO',
'000827' => 'PIRELLI',
'000828' => 'KOEI',
'000829' => 'AVAL',
'00082A' => 'POWERWALLZ',
'00082B' => 'WOOKSUNG',
'00082C' => 'HOMAG',
'00082D' => 'INDUS',
'00082E' => 'MULTITONE',
'00084E' => 'DIVERGENET',
'00084F' => 'QUALSTAR',
'000850' => 'ARIZONA',
'000851' => 'CANADIAN',
'000852' => 'TECHNICALLY',
'000853' => 'SCHLEICHER',
'000854' => 'NETRONIX',
'000855' => 'FERMILAB',
'000856' => 'GAMATRONIC',
'000857' => 'POLARIS',
'000858' => 'NOVATECHNOLOGY',
'000859' => 'SHENZHEN',
'00085A' => 'INTIGATE',
'00085B' => 'HANBIT',
'00085C' => 'SHANGHAI',
'00085D' => 'AASTRA',
'00085E' => 'PCO',
'00085F' => 'PICANOL',
'000860' => 'LODGENET',
'000861' => 'SOFTENERGY',
'000862' => 'NEC',
'000863' => 'ENTRISPHERE',
'000864' => 'FASY',
'000865' => 'JASCOM',
'000866' => 'DSX',
'000867' => 'UPTIME',
'000868' => 'PUROPTIX',
'000869' => 'COMMAND-E',
'00086A' => 'INDUSTRIE',
'00086B' => 'MIPSYS',
'00086C' => 'PLASMON',
'00086D' => 'MISSOURI',
'00086E' => 'HYGLO',
'00086F' => 'RESOURCES',
'000870' => 'RASVIA',
'000871' => 'NORTHDATA',
'000872' => 'SORENSON',
'000873' => 'DAP',
'000874' => 'DELL',
'000875' => 'ACORP',
'000876' => 'SDSYSTEM',
'000877' => 'LIEBERT',
'000878' => 'BENCHMARK',
'000879' => 'CEM',
'00087A' => 'WIPOTEC',
'00087B' => 'RTX',
'00087C' => 'CISCO',
'00087D' => 'CISCO',
'00087E' => 'BON',
'00087F' => 'SPAUN',
'000880' => 'BROADTEL',
'000881' => 'DIGITAL',
'000882' => 'SIGMA',
'000883' => 'HEWLETT-PACKARD',
'000884' => 'INDEX',
'000885' => 'EMS',
'000886' => 'HANSUNG',
'000887' => 'PRIVATE',
'000888' => 'OULLIM',
'000889' => 'ECHOSTAR',
'00088A' => 'MINDS@WORK',
'00088B' => 'TROPIC',
'00088C' => 'QUANTA',
'00088D' => 'SIGMA-LINKS',
'00088E' => 'NIHON',
'00088F' => 'ADVANCED',
'000890' => 'AVILINKS',
'000891' => 'LYAN',
'000892' => 'EM',
'000893' => 'PRIVATE',
'000894' => 'INNOVISION',
'000895' => 'PRIVATE',
'000896' => 'PRINTRONIX',
'000897' => 'QUAKE',
'000898' => 'GIGABIT',
'000899' => 'NETBIND',
'00089A' => 'ALCATEL',
'00089B' => 'ICP',
'00089C' => 'ELECS',
'00089D' => 'UHD-ELEKTRONIK',
'00089E' => 'BEIJING',
'00089F' => 'EFM',
'0008A0' => 'STOTZ',
'0008A1' => 'CNET',
'0008A2' => 'ADI',
'0008A3' => 'CISCO',
'0008A4' => 'CISCO',
'0008A5' => 'PENINSULA',
'0008A6' => 'MULTIWARE',
'0008A7' => 'ILOGIC',
'0008A8' => 'SYSTEC',
'0008A9' => 'SANGSANG',
'0008AA' => 'KARAM',
'0008AB' => 'ENERLINX',
'0008AC' => 'PRIVATE',
'0008AD' => 'TOYO-LINX',
'0008AE' => 'PACKETFRONT',
'0008AF' => 'NOVATEC',
'0008B0' => 'BKTEL',
'0008B1' => 'AVIANCOMMUNICATIONS',
'0008B2' => 'SHENZHEN',
'0008B3' => 'FASTWEL',
'0008B4' => 'SYSPOL',
'0008B5' => 'TAI',
'0008B6' => 'ROUTEFREE',
'0008B7' => 'HIT',
'0008B8' => 'E',
'0008B9' => 'KAON',
'0008BA' => 'ERSKINE',
'0008BB' => 'NETEXCELL',
'0008BC' => 'ILEVO',
'0008BD' => 'TEPG-US',
'0008BE' => 'XENPAK',
'0008BF' => 'APTUS',
'0008C0' => 'ASA',
'0008C1' => 'AVISTAR',
'0008C2' => 'CISCO',
'0008C3' => 'CONTEX',
'0008C4' => 'PRIVATE',
'0008C5' => 'LIONTECH',
'0008C6' => 'PHILIPS',
'0008C7' => 'COMPAQ',
'0008C8' => 'SONETICOM',
'0008C9' => 'TECHNISAT',
'0008CA' => 'TWINHAN',
'0008CB' => 'ZETA',
'0008CC' => 'REMOTEC',
'0008CD' => 'WITH-NET',
'0008CE' => 'PRIVATE',
'0008CF' => 'NIPPON',
'0008D0' => 'MUSASHI',
'0008D1' => 'KAREL',
'0008D2' => 'ZOOM',
'0008D3' => 'HERCULES',
'0008D4' => 'INEOQUEST',
'0008D5' => 'VANGUARD',
'0008D6' => 'HASSNET',
'0008D7' => 'HOW',
'0008D8' => 'DOWKEY',
'0008D9' => 'MITADENSI',
'000A27' => 'APPLE',
'001000' => 'CABLE',
'001001' => 'MCK',
'001002' => 'ACTIA',
'001003' => 'IMATRON',
'001004' => 'THE',
'001005' => 'UEC',
'001006' => 'THALES',
'001007' => 'CISCO',
'001008' => 'VIENNA',
'001009' => 'HORO',
'00100A' => 'WILLIAMS',
'00100B' => 'CISCO',
'00100C' => 'ITO',
'00100D' => 'CISCO',
'00100E' => 'MICRO',
'00100F' => 'INDUSTRIAL',
'001010' => 'INITIO',
'001011' => 'CISCO',
'001012' => 'PROCESSOR',
'001013' => 'INDUSTRIAL',
'001014' => 'CISCO',
'001015' => 'OOMON',
'001016' => 'T',
'001017' => 'MICOS',
'001018' => 'BROADCOM',
'001019' => 'SIRONA',
'00101A' => 'PICTURETEL',
'00101B' => 'CORNET',
'00101C' => 'OHM',
'00101D' => 'WINBOND',
'00101E' => 'MATSUSHITA',
'00101F' => 'CISCO',
'001020' => 'WELCH',
'001021' => 'ENCANTO',
'001022' => 'SATCOM',
'001023' => 'FLOWWISE',
'001024' => 'NAGOYA',
'001025' => 'GRAYHILL',
'001026' => 'ACCELERATED',
'001027' => 'L-3',
'001028' => 'COMPUTER',
'001029' => 'CISCO',
'00102A' => 'ZF',
'00102B' => 'UMAX',
'00102C' => 'LASAT',
'00102D' => 'HITACHI',
'00102E' => 'NETWORK',
'00102F' => 'CISCO',
'001030' => 'WI-LAN',
'001031' => 'OBJECTIVE',
'001032' => 'ALTA',
'001033' => 'ACCESSLAN',
'001034' => 'GNP',
'001035' => 'ELITEGROUP',
'001036' => 'INTER-TEL',
'001037' => 'CYQ-VE',
'001038' => 'MICRO',
'001039' => 'VECTRON',
'00103A' => 'DIAMOND',
'00103B' => 'HIPPI',
'00103C' => 'IC',
'00103D' => 'PHASECOM',
'00103E' => 'NETSCHOOLS',
'00103F' => 'TOLLGRADE',
'001040' => 'INTERMEC',
'001041' => 'BRISTOL',
'001042' => 'ALACRITECH',
'001043' => 'A2',
'001044' => 'INNOLABS',
'001045' => 'NORTEL',
'001046' => 'ALCORN',
'001047' => 'ECHO',
'001048' => 'HTRC',
'001049' => 'SHORELINE',
'00104A' => 'THE',
'00104B' => '3COM',
'00104C' => 'COMPUTER',
'00104D' => 'SURTEC',
'00104E' => 'CEOLOGIC',
'00104F' => 'STORAGE',
'001050' => 'RION',
'001051' => 'CMICRO',
'001052' => 'METTLER-TOLEDO',
'001053' => 'COMPUTER',
'001054' => 'CISCO',
'001055' => 'FUJITSU',
'001056' => 'SODICK',
'001057' => 'REBEL',
'001058' => 'ARROWPOINT',
'001059' => 'DIABLO',
'00105A' => '3COM',
'00105B' => 'NET',
'00105C' => 'QUANTUM',
'00105D' => 'DRAGER',
'00105E' => 'HEKIMIAN',
'00105F' => 'IN-SNEC',
'001060' => 'BILLINGTON',
'001061' => 'HOSTLINK',
'001062' => 'NX',
'001063' => 'STARGUIDE',
'001064' => 'DIGITAL',
'001065' => 'RADYNE',
'001066' => 'ADVANCED',
'001067' => 'REDBACK',
'001068' => 'COMOS',
'001069' => 'HELIOSS',
'00106A' => 'DIGITAL',
'00106B' => 'SONUS',
'00106C' => 'INFRATEC',
'00106D' => 'INTEGRITY',
'00106E' => 'TADIRAN',
'00106F' => 'TRENTON',
'001070' => 'CARADON',
'001071' => 'ADVANET',
'001072' => 'GVN',
'001073' => 'TECHNOBOX',
'001074' => 'ATEN',
'001075' => 'MAXTOR',
'001076' => 'EUREM',
'001077' => 'SAF',
'001078' => 'NUERA',
'001079' => 'CISCO',
'00107A' => 'AMBICOM',
'00107B' => 'CISCO',
'00107C' => 'P-COM',
'00107D' => 'AURORA',
'00107E' => 'BACHMANN',
'00107F' => 'CRESTRON',
'001080' => 'METAWAVE',
'001081' => 'DPS',
'001082' => 'JNA',
'001083' => 'HP-UX',
'001084' => 'K-BOT',
'001085' => 'POLARIS',
'001086' => 'ATTO',
'001087' => 'XSTREAMIS',
'001088' => 'AMERICAN',
'001089' => 'WEBSONIC',
'00108A' => 'TERALOGIC',
'00108B' => 'LASERANIMATION',
'00108C' => 'FUJITSU',
'00108D' => 'JOHNSON',
'00108E' => 'HUGH',
'00108F' => 'RAPTOR',
'001090' => 'CIMETRICS',
'001091' => 'NO',
'001092' => 'NETCORE',
'001093' => 'CMS',
'001094' => 'ADTECH',
'001095' => 'THOMSON',
'001096' => 'TRACEWELL',
'001097' => 'WINNET',
'001098' => 'STARNET',
'001099' => 'INNOMEDIA',
'00109A' => 'NETLINE',
'00109B' => 'VIXEL',
'00109C' => 'M-SYSTEM',
'00109D' => 'CLARINET',
'00109E' => 'AWARE',
'00109F' => 'PAVO',
'0010A0' => 'INNOVEX',
'0010A1' => 'KENDIN',
'0010A2' => 'TNS',
'0010A3' => 'OMNITRONIX',
'0010A4' => 'XIRCOM',
'0010A5' => 'OXFORD',
'0010A6' => 'CISCO',
'0010A7' => 'UNEX',
'0010A8' => 'RELIANCE',
'0010A9' => 'ADHOC',
'0010AA' => 'MEDIA4',
'0010AB' => 'KOITO',
'0010AC' => 'IMCI',
'0010AD' => 'SOFTRONICS',
'0010AE' => 'SHINKO',
'0010AF' => 'TAC',
'0010B0' => 'MERIDIAN',
'0010B1' => 'FOR-A',
'0010B2' => 'COACTIVE',
'0010B3' => 'NOKIA',
'0010B4' => 'ATMOSPHERE',
'0010B5' => 'ACCTON',
'0010B6' => 'ENTRATA',
'0010B7' => 'COYOTE',
'0010B8' => 'ISHIGAKI',
'0010B9' => 'MAXTOR',
'0010BA' => 'MARTINHO-DAVIS',
'0010BB' => 'DATA',
'0010BC' => 'NORTEL',
'0010BD' => 'THE',
'0010BE' => 'TELEXIS',
'0010BF' => 'INTER',
'0010C0' => 'ARMA',
'0010C1' => 'OI',
'0010C2' => 'WILLNET',
'0010C3' => 'CSI-CONTROL',
'0010C4' => 'MEDIA',
'0010C5' => 'PROTOCOL',
'0010C6' => 'USI',
'0010C7' => 'DATA',
'0010C8' => 'COMMUNICATIONS',
'0010C9' => 'MITSUBISHI',
'0010CA' => 'INTEGRAL',
'0010CB' => 'FACIT',
'0010CC' => 'CLP',
'0010CD' => 'INTERFACE',
'0010CE' => 'VOLAMP',
'0010CF' => 'FIBERLANE',
'0010D0' => 'WITCOM',
'0010D1' => 'TOP',
'0010D2' => 'NITTO',
'0010D3' => 'GRIPS',
'0010D4' => 'STORAGE',
'0010D5' => 'IMASDE',
'0010D6' => 'ITT',
'0010D7' => 'ARGOSY',
'0010D8' => 'CALISTA',
'0010D9' => 'IBM',
'0010DA' => 'MOTION',
'0010DB' => 'NETSCREEN',
'0010DC' => 'MICRO-STAR',
'0010DD' => 'ENABLE',
'0010DE' => 'INTERNATIONAL',
'0010DF' => 'RISE',
'0010E0' => 'COBALT',
'0010E1' => 'S',
'0010E2' => 'ARRAYCOMM',
'0010E3' => 'COMPAQ',
'0010E4' => 'NSI',
'0010E5' => 'SOLECTRON',
'0010E6' => 'APPLIED',
'0010E7' => 'BREEZECOM',
'0010E8' => 'TELOCITY',
'0010E9' => 'RAIDTEC',
'0010EA' => 'ADEPT',
'0010EB' => 'SELSIUS',
'0010EC' => 'RPCG',
'0010ED' => 'SUNDANCE',
'0010EE' => 'CTI',
'0010EF' => 'DBTEL',
'0010F0' => 'RITTAL-WERK',
'0010F1' => 'I-O',
'0010F2' => 'ANTEC',
'0010F3' => 'NEXCOM',
'0010F4' => 'VERTICAL',
'0010F5' => 'AMHERST',
'0010F6' => 'CISCO',
'0010F7' => 'IRIICHI',
'0010F8' => 'KENWOOD',
'0010F9' => 'UNIQUE',
'0010FA' => 'ZAYANTE',
'0010FB' => 'ZIDA',
'0010FC' => 'BROADBAND',
'0010FD' => 'COCOM',
'0010FE' => 'DIGITAL',
'0010FF' => 'CISCO',
'001700' => 'KABEL',
'001C7C' => 'PERQ',
'002000' => 'LEXMARK',
'002001' => 'DSP',
'002002' => 'SERITECH',
'002003' => 'PIXEL',
'002004' => 'YAMATAKE-HONEYWELL',
'002005' => 'SIMPLETECH',
'002006' => 'GARRETT',
'002007' => 'SFA',
'002008' => 'CABLE',
'002009' => 'PACKARD',
'00200A' => 'SOURCE-COMM',
'00200B' => 'OCTAGON',
'00200C' => 'ADASTRA',
'00200D' => 'CARL',
'00200E' => 'SATELLITE',
'00200F' => 'TANBAC',
'002010' => 'JEOL',
'002011' => 'CANOPUS',
'002012' => 'CAMTRONICS',
'002013' => 'DIVERSIFIED',
'002014' => 'GLOBAL',
'002015' => 'ACTIS',
'002016' => 'SHOWA',
'002017' => 'ORBOTECH',
'002018' => 'REALTEK',
'002019' => 'OHLER',
'00201A' => 'NBASE',
'00201B' => 'NORTHERN',
'00201C' => 'EXCEL',
'00201D' => 'KATANA',
'00201E' => 'NETQUEST',
'00201F' => 'BEST',
'002020' => 'MEGATRON',
'002021' => 'ALGORITHMS',
'002022' => 'TEKNIQUE',
'002023' => 'T',
'002024' => 'PACIFIC',
'002025' => 'CONTROL',
'002026' => 'AMKLY',
'002027' => 'MING',
'002028' => 'BLOOMBERG',
'002029' => 'TELEPROCESSING',
'00202A' => 'N',
'00202B' => 'ATML',
'00202C' => 'WELLTRONIX',
'00202D' => 'TAIYO',
'00202E' => 'DAYSTAR',
'00202F' => 'ZETA',
'002030' => 'ANALOG',
'002031' => 'ERTEC',
'002032' => 'ALCATEL',
'002033' => 'SYNAPSE',
'002034' => 'ROTEC',
'002035' => 'IBM',
'002036' => 'BMC',
'002037' => 'SEAGATE',
'002038' => 'VME',
'002039' => 'SCINETS',
'00203A' => 'DIGITAL',
'00203B' => 'WISDM',
'00203C' => 'EUROTIME',
'00203D' => 'NOVAR',
'00203E' => 'LOGICAN',
'00203F' => 'JUKI',
'002040' => 'MOTOROLA',
'002041' => 'DATA',
'002042' => 'DATAMETRICS',
'002043' => 'NEURON',
'002044' => 'GENITECH',
'002045' => 'SOLCOM',
'002046' => 'CIPRICO',
'002047' => 'STEINBRECHER',
'002048' => 'FORE',
'002049' => 'COMTRON',
'00204A' => 'PRONET',
'00204B' => 'AUTOCOMPUTER',
'00204C' => 'MITRON',
'00204D' => 'INOVIS',
'00204E' => 'NETWORK',
'00204F' => 'DEUTSCHE',
'002050' => 'KOREA',
'002051' => 'PHOENIX',
'002052' => 'RAGULA',
'002053' => 'HUNTSVILLE',
'002054' => 'EASTERN',
'002055' => 'ALTECH',
'002056' => 'NEOPRODUCTS',
'002057' => 'TITZE',
'002058' => 'ALLIED',
'002059' => 'MIRO',
'00205A' => 'COMPUTER',
'00205B' => 'SKYLINE',
'00205C' => 'INTERNET',
'00205D' => 'NANOMATIC',
'00205E' => 'CASTLE',
'00205F' => 'GAMMADATA',
'002060' => 'ALCATEL',
'002061' => 'DYNATECH',
'002062' => 'SCORPION',
'002063' => 'WIPRO',
'002064' => 'PROTEC',
'002065' => 'SUPERNET',
'002066' => 'GENERAL',
'002067' => 'NODE',
'002068' => 'ISDYNE',
'002069' => 'ISDN',
'00206A' => 'OSAKA',
'00206B' => 'MINOLTA',
'00206C' => 'EVERGREEN',
'00206D' => 'DATA',
'00206E' => 'XACT',
'00206F' => 'FLOWPOINT',
'002070' => 'HYNET',
'002071' => 'IBR',
'002072' => 'WORKLINK',
'002073' => 'FUSION',
'002074' => 'SUNGWOON',
'002075' => 'MOTOROLA',
'002076' => 'REUDO',
'002077' => 'KARDIOS',
'002078' => 'RUNTOP',
'002079' => 'MIKRON',
'00207A' => 'WISE',
'00207B' => 'LEVEL',
'00207C' => 'AUTEC',
'00207D' => 'ADVANCED',
'00207E' => 'FINECOM',
'00207F' => 'KYOEI',
'002080' => 'SYNERGY',
'002081' => 'TITAN',
'002082' => 'ONEAC',
'002083' => 'PRESTICOM',
'002084' => 'OCE',
'002085' => '3COM',
'002086' => 'MICROTECH',
'002087' => 'MEMOTEC',
'002088' => 'GLOBAL',
'002089' => 'T3PLUS',
'00208A' => 'SONIX',
'00208B' => 'FOCUS',
'00208C' => 'GALAXY',
'00208D' => 'CMD',
'00208E' => 'CHEVIN',
'00208F' => 'ECI',
'002090' => 'ADVANCED',
'002091' => 'J125',
'002092' => 'CHESS',
'002093' => 'LANDINGS',
'002094' => 'CUBIX',
'002095' => 'RIVA',
'002096' => 'INVENSYS',
'002097' => 'APPLIED',
'002098' => 'HECTRONIC',
'002099' => 'BON',
'00209A' => 'THE',
'00209B' => 'ERSAT',
'00209C' => 'PRIMARY',
'00209D' => 'LIPPERT',
'00209E' => 'BROWN-S',
'00209F' => 'MERCURY',
'0020A0' => 'OA',
'0020A1' => 'DOVATRON',
'0020A2' => 'GALCOM',
'0020A3' => 'DIVICOM',
'0020A4' => 'MULTIPOINT',
'0020A5' => 'NEWER',
'0020A6' => 'PROXIM',
'0020A7' => 'PAIRGAIN',
'0020A8' => 'SAST',
'0020A9' => 'WHITE',
'0020AA' => 'DIGIMEDIA',
'0020AB' => 'MICRO',
'0020AC' => 'INTERFLEX',
'0020AD' => 'LINQ',
'0020AE' => 'ORNET',
'0020AF' => '3COM',
'0020B0' => 'GATEWAY',
'0020B1' => 'COMTECH',
'0020B2' => 'CSP',
'0020B3' => 'SCLTEC',
'0020B4' => 'TERMA',
'0020B5' => 'YASKAWA',
'0020B6' => 'AGILE',
'0020B7' => 'NAMAQUA',
'0020B8' => 'PRIME',
'0020B9' => 'METRICOM',
'0020BA' => 'CENTER',
'0020BB' => 'ZAX',
'0020BC' => 'JTEC',
'0020BD' => 'NIOBRARA',
'0020BE' => 'LAN',
'0020BF' => 'AEHR',
'0020C0' => 'PULSE',
'0020C1' => 'TAIKO',
'0020C2' => 'TEXAS',
'0020C3' => 'COUNTER',
'0020C4' => 'INET',
'0020C5' => 'EAGLE',
'0020C6' => 'NECTEC',
'0020C7' => 'AKAI',
'0020C8' => 'LARSCOM',
'0020C9' => 'VICTRON',
'0020CA' => 'DIGITAL',
'0020CB' => 'PRETEC',
'0020CC' => 'DIGITAL',
'0020CD' => 'HYBRID',
'0020CE' => 'LOGICAL',
'0020CF' => 'TEST',
'0020D0' => 'VERSALYNX',
'0020D1' => 'MICROCOMPUTER',
'0020D2' => 'RAD',
'0020D3' => 'OST',
'0020D4' => 'CABLETRON',
'0020D5' => 'VIPA',
'0020D6' => 'BREEZECOM',
'0020D7' => 'JAPAN',
'0020D8' => 'NETWAVE',
'0020D9' => 'PANASONIC',
'0020DA' => 'XYLAN',
'0020DB' => 'XNET',
'0020DC' => 'DENSITRON',
'0020DD' => 'AWA',
'0020DE' => 'JAPAN',
'0020DF' => 'KYOSAN',
'0020E0' => 'PREMAX',
'0020E1' => 'ALAMAR',
'0020E2' => 'INFORMATION',
'0020E3' => 'MCD',
'0020E4' => 'HSING',
'0020E5' => 'APEX',
'0020E6' => 'LIDKOPING',
'0020E7' => 'B&W',
'0020E8' => 'DATATREK',
'0020E9' => 'DANTEL',
'0020EA' => 'EFFICIENT',
'0020EB' => 'CINCINNATI',
'0020EC' => 'TECHWARE',
'0020ED' => 'GIGA-BYTE',
'0020EE' => 'GTECH',
'0020EF' => 'USC',
'0020F0' => 'UNIVERSAL',
'0020F1' => 'ALTOS',
'0020F2' => 'SUN',
'0020F3' => 'RAYNET',
'0020F4' => 'SPECTRIX',
'0020F5' => 'PANDATEL',
'0020F6' => 'NET',
'0020F7' => 'CYBERDATA',
'0020F8' => 'CARRERA',
'0020F9' => 'PARALINK',
'0020FA' => 'GDE',
'0020FB' => 'OCTEL',
'0020FC' => 'MATROX',
'0020FD' => 'ITV',
'0020FE' => 'TOPWARE',
'0020FF' => 'SYMMETRICAL',
'003000' => 'ALLWELL',
'003001' => 'SMP',
'003002' => 'EXPAND',
'003003' => 'PHASYS',
'003004' => 'LEADTEK',
'003005' => 'FUJITSU',
'003006' => 'SUPERPOWER',
'003007' => 'OPTI',
'003008' => 'AVIO',
'003009' => 'TACHION',
'00300A' => 'AZTECH',
'00300B' => 'MPHASE',
'00300C' => 'CONGRUENCY',
'00300D' => 'MMC',
'00300E' => 'KLOTZ',
'00300F' => 'IMT',
'003010' => 'VISIONETICS',
'003011' => 'HMS',
'003012' => 'DIGITAL',
'003013' => 'NEC',
'003014' => 'DIVIO',
'003015' => 'CP',
'003016' => 'ISHIDA',
'003017' => 'TERASTACK',
'003018' => 'JETWAY',
'003019' => 'CISCO',
'00301A' => 'SMARTBRIDGES',
'00301B' => 'SHUTTLE',
'00301C' => 'ALTVATER',
'00301D' => 'SKYSTREAM',
'00301E' => '3COM',
'00301F' => 'OPTICAL',
'003020' => 'TSI',
'003021' => 'HSING',
'003022' => 'FONG',
'003023' => 'COGENT',
'003024' => 'CISCO',
'003025' => 'CHECKOUT',
'003026' => 'HEITEL',
'003027' => 'KERBANGO',
'003028' => 'FASE',
'003029' => 'OPICOM',
'00302A' => 'SOUTHERN',
'00302B' => 'INALP',
'00302C' => 'SYLANTRO',
'00302D' => 'QUANTUM',
'00302E' => 'HOFT',
'00302F' => 'SMITHS',
'003030' => 'HARMONIX',
'003031' => 'LIGHTWAVE',
'003032' => 'MAGICRAM',
'003033' => 'ORIENT',
'003034' => 'PRIVATE',
'003035' => 'PRIVATE',
'003036' => 'RMP',
'003037' => 'PACKARD',
'003038' => 'XCP',
'003039' => 'SOFTBOOK',
'00303A' => 'MAATEL',
'00303B' => 'POWERCOM',
'00303C' => 'ONNTO',
'00303D' => 'IVA',
'00303E' => 'RADCOM',
'00303F' => 'TURBOCOMM',
'003040' => 'CISCO',
'003041' => 'SAEJIN',
'003042' => 'DETEWE-DEUTSCHE',
'003043' => 'IDREAM',
'003044' => 'PORTSMITH',
'003045' => 'VILLAGE',
'003046' => 'CONTROLLED',
'003047' => 'NISSEI',
'003048' => 'SUPERMICRO',
'003049' => 'BRYANT',
'00304A' => 'FRAUNHOFER',
'00304B' => 'ORBACOM',
'00304C' => 'APPIAN',
'00304D' => 'ESI',
'00304E' => 'BUSTEC',
'00304F' => 'PLANET',
'003050' => 'VERSA',
'003051' => 'ORBIT',
'003052' => 'ELASTIC',
'003053' => 'BASLER',
'003054' => 'CASTLENET',
'003055' => 'HITACHI',
'003056' => 'BECK',
'003057' => 'E-TEL',
'003058' => 'API',
'003059' => 'DIGITAL-LOGIC',
'00305A' => 'TELGEN',
'00305B' => 'MODULE',
'00305C' => 'SMAR',
'00305D' => 'DIGITRA',
'00305E' => 'ABELKO',
'00305F' => 'IMACON',
'003060' => 'STARMATIX',
'003061' => 'MOBYTEL',
'003062' => 'PATH',
'003063' => 'SANTERA',
'003064' => 'ADLINK',
'003065' => 'APPLE',
'003066' => 'DIGITAL',
'003067' => 'BIOSTAR',
'003068' => 'CYBERNETICS',
'003069' => 'IMPACCT',
'00306A' => 'PENTA',
'00306B' => 'CMOS',
'00306C' => 'HITEX',
'00306D' => 'LUCENT',
'00306E' => 'HEWLETT',
'00306F' => 'SEYEON',
'003070' => '1NET',
'003071' => 'CISCO',
'003072' => 'INTELLIBYTE',
'003073' => 'INTERNATIONAL',
'003074' => 'EQUIINET',
'003075' => 'ADTECH',
'003076' => 'AKAMBA',
'003077' => 'ONPREM',
'003078' => 'CISCO',
'003079' => 'CQOS',
'00307A' => 'ADVANCED',
'00307B' => 'CISCO',
'00307C' => 'ADID',
'00307D' => 'GRE',
'00307E' => 'REDFLEX',
'00307F' => 'IRLAN',
'003080' => 'CISCO',
'003081' => 'ALTOS',
'003082' => 'TAIHAN',
'003083' => 'IVRON',
'003084' => 'ALLIED',
'003085' => 'CISCO',
'003086' => 'TRANSISTOR',
'003087' => 'VEGA',
'003088' => 'SIARA',
'003089' => 'SPECTRAPOINT',
'00308A' => 'NICOTRA',
'00308B' => 'BRIX',
'00308C' => 'ADVANCED',
'00308D' => 'PINNACLE',
'00308E' => 'CROSS',
'00308F' => 'MICRILOR',
'003090' => 'CYRA',
'003091' => 'TAIWAN',
'003092' => 'MODUNORM',
'003093' => 'SONNET',
'003094' => 'CISCO',
'003095' => 'PROCOMP',
'003096' => 'CISCO',
'003097' => 'EXOMATIC',
'003098' => 'GLOBAL',
'003099' => 'BOENIG',
'00309A' => 'ASTRO',
'00309B' => 'SMARTWARE',
'00309C' => 'TIMING',
'00309D' => 'NIMBLE',
'00309E' => 'WORKBIT',
'00309F' => 'AMBER',
'0030A0' => 'TYCO',
'0030A1' => 'OPTI',
'0030A2' => 'LIGHTNER',
'0030A3' => 'CISCO',
'0030A4' => 'WOODWIND',
'0030A5' => 'ACTIVE',
'0030A6' => 'VIANET',
'0030A7' => 'SCHWEITZER',
'0030A8' => 'OL-E',
'0030A9' => 'NETIVERSE',
'0030AA' => 'AXUS',
'0030AB' => 'DELTA',
'0030AC' => 'SYSTEME',
'0030AD' => 'SHANGHAI',
'0030AE' => 'TIMES',
'0030AF' => 'HONEYWELL',
'0030B0' => 'CONVERGENET',
'0030B1' => 'GOC',
'0030B2' => 'WESCAM',
'0030B3' => 'SAN',
'0030B4' => 'INTERSIL',
'0030B5' => 'TADIRAN',
'0030B6' => 'CISCO',
'0030B7' => 'TELETROL',
'0030B8' => 'RIVERDELTA',
'0030B9' => 'ECTEL',
'0030BA' => 'AC&T',
'0030BB' => 'CACHEFLOW',
'0030BC' => 'OPTRONIC',
'0030BD' => 'BELKIN',
'0030BE' => 'CITY-NET',
'0030BF' => 'MULTIDATA',
'0030C0' => 'LARA',
'0030C1' => 'HEWLETT-PACKARD',
'0030C2' => 'COMONE',
'0030C3' => 'FLUECKIGER',
'0030C4' => 'NIIGATA',
'0030C5' => 'CADENCE',
'0030C6' => 'CONTROL',
'0030C7' => 'MACROMATE',
'0030C8' => 'GAD',
'0030C9' => 'LUXN',
'0030CA' => 'DISCOVERY',
'0030CB' => 'OMNI',
'0030CC' => 'TENOR',
'0030CD' => 'CONEXANT',
'0030CE' => 'ZAFFIRE',
'0030CF' => 'TWO',
'0030D0' => 'PRIVATE',
'0030D1' => 'INOVA',
'0030D2' => 'WIN',
'0030D3' => 'AGILENT',
'0030D4' => 'COMTIER',
'0030D5' => 'DRESEARCH',
'0030D6' => 'MSC',
'0030D7' => 'INNOVATIVE',
'0030D8' => 'SITEK',
'0030D9' => 'DATACORE',
'0030DA' => 'COMTREND',
'0030DB' => 'MINDREADY',
'0030DC' => 'RIGHTECH',
'0030DD' => 'INDIGITA',
'0030DE' => 'WAGO',
'0030DF' => 'KB/TEL',
'0030E0' => 'OXFORD',
'0030E1' => 'ACROTRON',
'0030E2' => 'GARNET',
'0030E3' => 'SEDONA',
'0030E4' => 'CHIYODA',
'0030E5' => 'AMPER',
'0030E6' => 'SIEMENS',
'0030E7' => 'CNF',
'0030E8' => 'ENSIM',
'0030E9' => 'GMA',
'0030EA' => 'TERAFORCE',
'0030EB' => 'TURBONET',
'0030EC' => 'BORGARDT',
'0030ED' => 'EXPERT',
'0030EE' => 'DSG',
'0030EF' => 'NEON',
'0030F0' => 'UNIFORM',
'0030F1' => 'ACCTON',
'0030F2' => 'CISCO',
'0030F3' => 'AT',
'0030F4' => 'STARDOT',
'0030F5' => 'WILD',
'0030F6' => 'SECURELOGIX',
'0030F7' => 'RAMIX',
'0030F8' => 'DYNAPRO',
'0030F9' => 'SOLLAE',
'0030FA' => 'TELICA',
'0030FB' => 'AZS',
'0030FC' => 'TERAWAVE',
'0030FD' => 'INTEGRATED',
'0030FE' => 'DSA',
'0030FF' => 'DATAFAB',
'004000' => 'PCI',
'004001' => 'ZERO',
'004002' => 'PERLE',
'004003' => 'WESTINGHOUSE',
'004004' => 'ICM',
'004005' => 'TRENDWARE',
'004006' => 'SAMPO',
'004007' => 'TELMAT',
'004008' => 'A',
'004009' => 'TACHIBANA',
'00400A' => 'PIVOTAL',
'00400B' => 'CRESCENDO',
'00400C' => 'GENERAL',
'00400D' => 'LANNET',
'00400E' => 'MEMOTEC',
'00400F' => 'DATACOM',
'004010' => 'SONIC',
'004011' => 'FACILITIES',
'004012' => 'WINDATA',
'004013' => 'NTT',
'004014' => 'COMSOFT',
'004015' => 'ASCOM',
'004016' => 'HADAX',
'004017' => 'XCD',
'004018' => 'ADOBE',
'004019' => 'AEON',
'00401A' => 'FUJI',
'00401B' => 'PRINTER',
'00401C' => 'AST',
'00401D' => 'INVISIBLE',
'00401E' => 'ICC',
'00401F' => 'COLORGRAPH',
'004020' => 'PILKINGTON',
'004021' => 'RASTER',
'004022' => 'KLEVER',
'004023' => 'LOGIC',
'004024' => 'COMPAC',
'004025' => 'MOLECULAR',
'004026' => 'MELCO',
'004027' => 'SMC',
'004028' => 'NETCOMM',
'004029' => 'COMPEX',
'00402A' => 'CANOGA-PERKINS',
'00402B' => 'TRIGEM',
'00402C' => 'ISIS',
'00402D' => 'HARRIS',
'00402E' => 'PRECISION',
'00402F' => 'XLNT',
'004030' => 'GK',
'004031' => 'KOKUSAI',
'004032' => 'DIGITAL',
'004033' => 'ADDTRON',
'004034' => 'BUSTEK',
'004035' => 'OPCOM',
'004036' => 'TRIBESTAR',
'004037' => 'SEA-ILAN',
'004038' => 'TALENT',
'004039' => 'OPTEC',
'00403A' => 'IMPACT',
'00403B' => 'SYNERJET',
'00403C' => 'FORKS',
'00403D' => 'TERADATA',
'00403E' => 'RASTER',
'00403F' => 'SSANGYONG',
'004040' => 'RING',
'004041' => 'FUJIKURA',
'004042' => 'N',
'004043' => 'NOKIA',
'004044' => 'QNIX',
'004045' => 'TWINHEAD',
'004046' => 'UDC',
'004047' => 'WIND',
'004048' => 'SMD',
'004049' => 'TEGIMENTA',
'00404A' => 'WEST',
'00404B' => 'MAPLE',
'00404C' => 'HYPERTEC',
'00404D' => 'TELECOMM',
'00404E' => 'FLUENT',
'00404F' => 'SPACE',
'004050' => 'IRONICS',
'004051' => 'GRACILIS',
'004052' => 'STAR',
'004053' => 'DATUM',
'004054' => 'THINKING',
'004055' => 'METRONIX',
'004056' => 'MCM',
'004057' => 'LOCKHEED-SANDERS',
'004058' => 'KRONOS',
'004059' => 'YOSHIDA',
'00405A' => 'GOLDSTAR',
'00405B' => 'FUNASSET',
'00405C' => 'FUTURE',
'00405D' => 'STAR-TEK',
'00405E' => 'NORTH',
'00405F' => 'AFE',
'004060' => 'COMENDEC',
'004061' => 'DATATECH',
'004062' => 'E-SYSTEMS',
'004063' => 'VIA',
'004064' => 'KLA',
'004065' => 'GTE',
'004066' => 'HITACHI',
'004067' => 'OMNIBYTE',
'004068' => 'EXTENDED',
'004069' => 'LEMCOM',
'00406A' => 'KENTEK',
'00406B' => 'SYSGEN',
'00406C' => 'COPERNIQUE',
'00406D' => 'LANCO',
'00406E' => 'COROLLARY',
'00406F' => 'SYNC',
'004070' => 'INTERWARE',
'004071' => 'ATM',
'004072' => 'APPLIED',
'004073' => 'BASS',
'004074' => 'CABLE',
'004075' => 'M-TRADE',
'004076' => 'AMP',
'004077' => 'MAXTON',
'004078' => 'WEARNES',
'004079' => 'JUKO',
'00407A' => 'SOCIETE',
'00407B' => 'SCIENTIFIC',
'00407C' => 'QUME',
'00407D' => 'EXTENSION',
'00407E' => 'EVERGREEN',
'00407F' => 'AGEMA',
'004080' => 'ATHENIX',
'004081' => 'MANNESMANN',
'004082' => 'LABORATORY',
'004083' => 'TDA',
'004084' => 'HONEYWELL',
'004085' => 'SAAB',
'004086' => 'MICHELS',
'004087' => 'UBITREX',
'004088' => 'MOBUIS',
'004089' => 'MEIDENSHA',
'00408A' => 'TPS',
'00408B' => 'RAYLAN',
'00408C' => 'AXIS',
'00408D' => 'THE',
'00408E' => 'CXR/DIGILOG',
'00408F' => 'WM-DATA',
'004090' => 'ANSEL',
'004091' => 'PROCOMP',
'004092' => 'ASP',
'004093' => 'PAXDATA',
'004094' => 'SHOGRAPHICS',
'004095' => 'EAGLE',
'004096' => 'AIRONET',
'004097' => 'DATEX',
'004098' => 'DRESSLER',
'004099' => 'NEWGEN',
'00409A' => 'NETWORK',
'00409B' => 'HAL',
'00409C' => 'TRANSWARE',
'00409D' => 'DIGIBOARD',
'00409E' => 'CONCURRENT',
'00409F' => 'LANCAST/CASAT',
'0040A0' => 'GOLDSTAR',
'0040A1' => 'ERGO',
'0040A2' => 'KINGSTAR',
'0040A3' => 'MICROUNITY',
'0040A4' => 'ROSE',
'0040A5' => 'CLINICOMP',
'0040A6' => 'CRAY',
'0040A7' => 'ITAUTEC',
'0040A8' => 'IMF',
'0040A9' => 'DATACOM',
'0040AA' => 'VALMET',
'0040AB' => 'ROLAND',
'0040AC' => 'SUPER',
'0040AD' => 'SMA',
'0040AE' => 'DELTA',
'0040AF' => 'DIGITAL',
'0040B0' => 'BYTEX',
'0040B1' => 'CODONICS',
'0040B2' => 'SYSTEMFORSCHUNG',
'0040B3' => 'PAR',
'0040B4' => '3COM',
'0040B5' => 'VIDEO',
'0040B6' => 'COMPUTERM',
'0040B7' => 'STEALTH',
'0040B8' => 'IDEA',
'0040B9' => 'MACQ',
'0040BA' => 'ALLIANT',
'0040BB' => 'GOLDSTAR',
'0040BC' => 'ALGORITHMICS',
'0040BD' => 'STARLIGHT',
'0040BE' => 'BOEING',
'0040BF' => 'CHANNEL',
'0040C0' => 'VISTA',
'0040C1' => 'BIZERBA-WERKE',
'0040C2' => 'APPLIED',
'0040C3' => 'FISCHER',
'0040C4' => 'KINKEI',
'0040C5' => 'MICOM',
'0040C6' => 'FIBERNET',
'0040C7' => 'DANPEX',
'0040C8' => 'MILAN',
'0040C9' => 'NCUBE',
'0040CA' => 'FIRST',
'0040CB' => 'LANWAN',
'0040CC' => 'SILCOM',
'0040CD' => 'TERA',
'0040CE' => 'NET-SOURCE',
'0040CF' => 'STRAWBERRY',
'0040D0' => 'DEC/COMPAQ',
'0040D1' => 'FUKUDA',
'0040D2' => 'PAGINE',
'0040D3' => 'KIMPSION',
'0040D4' => 'GAGE',
'0040D5' => 'SARTORIUS',
'0040D6' => 'LOCAMATION',
'0040D7' => 'STUDIO',
'0040D8' => 'OCEAN',
'0040D9' => 'AMERICAN',
'0040DA' => 'TELSPEC',
'0040DB' => 'ADVANCED',
'0040DC' => 'TRITEC',
'0040DD' => 'HONG',
'0040DE' => 'ELETTRONICA',
'0040DF' => 'DIGALOG',
'0040E0' => 'ATOMWIDE',
'0040E1' => 'MARNER',
'0040E2' => 'MESA',
'0040E3' => 'QUIN',
'0040E4' => 'E-M',
'0040E5' => 'SYBUS',
'0040E6' => 'C',
'0040E7' => 'ARNOS',
'0040E8' => 'CHARLES',
'0040E9' => 'ACCORD',
'0040EA' => 'PLAINTREE',
'0040EB' => 'MARTIN',
'0040EC' => 'MIKASA',
'0040ED' => 'NETWORK',
'0040EE' => 'OPTIMEM',
'0040EF' => 'HYPERCOM',
'0040F0' => 'MICRO',
'0040F1' => 'CHUO',
'0040F2' => 'JANICH',
'0040F3' => 'NETCOR',
'0040F4' => 'CAMEO',
'0040F5' => 'OEM',
'0040F6' => 'KATRON',
'0040F7' => 'POLAROID',
'0040F8' => 'SYSTEMHAUS',
'0040F9' => 'COMBINET',
'0040FA' => 'MICROBOARDS',
'0040FB' => 'CASCADE',
'0040FC' => 'IBR',
'0040FD' => 'LXE',
'0040FE' => 'SYMPLEX',
'0040FF' => 'TELEBIT',
'004854' => 'DIGITAL',
'004F49' => 'REALTEK',
'004F4B' => 'PINE',
'005000' => 'NEXO',
'005001' => 'YAMASHITA',
'005002' => 'OMNISEC',
'005003' => 'GRETAG',
'005004' => '3COM',
'005006' => 'TAC',
'005007' => 'SIEMENS',
'005008' => 'TIVA',
'005009' => 'PHILIPS',
'00500A' => 'IRIS',
'00500B' => 'CISCO',
'00500C' => 'ETEK',
'00500D' => 'SATORI',
'00500E' => 'CHROMATIS',
'00500F' => 'CISCO',
'005010' => 'NOVANET',
'005012' => 'CBL',
'005013' => 'CHAPARRAL',
'005014' => 'CISCO',
'005015' => 'BRIGHT',
'005016' => 'SST/WOODHEAD',
'005017' => 'RSR',
'005018' => 'ADVANCED',
'005019' => 'SPRING',
'00501A' => 'UISIQN',
'00501B' => 'ABL',
'00501C' => 'JATOM',
'00501E' => 'MIRANDA',
'00501F' => 'MRG',
'005020' => 'MEDIASTAR',
'005021' => 'EIS',
'005022' => 'ZONET',
'005023' => 'PG',
'005024' => 'NAVIC',
'005026' => 'COSYSTEMS',
'005027' => 'GENICOM',
'005028' => 'AVAL',
'005029' => '1394',
'00502A' => 'CISCO',
'00502B' => 'GENRAD',
'00502C' => 'SOYO',
'00502D' => 'ACCEL',
'00502E' => 'CAMBEX',
'00502F' => 'TOLLBRIDGE',
'005030' => 'FUTURE',
'005031' => 'AEROFLEX',
'005032' => 'PICAZO',
'005033' => 'MAYAN',
'005036' => 'NETCAM',
'005037' => 'KOGA',
'005038' => 'DAIN',
'005039' => 'MARINER',
'00503A' => 'DATONG',
'00503B' => 'MEDIAFIRE',
'00503C' => 'TSINGHUA',
'00503E' => 'CISCO',
'00503F' => 'ANCHOR',
'005040' => 'EMWARE',
'005041' => 'CTX',
'005042' => 'SCI',
'005043' => 'MARVELL',
'005044' => 'ASACA',
'005045' => 'RIOWORKS',
'005046' => 'MENICX',
'005047' => 'PRIVATE',
'005048' => 'INFOLIBRIA',
'005049' => 'ELLACOYA',
'00504A' => 'ELTECO',
'00504B' => 'BARCONET',
'00504C' => 'GALIL',
'00504D' => 'REPOTEC',
'00504E' => 'UMC',
'00504F' => 'OLENCOM',
'005050' => 'CISCO',
'005051' => 'IWATSU',
'005052' => 'TIARA',
'005053' => 'CISCO',
'005054' => 'CISCO',
'005055' => 'DOMS',
'005056' => 'VMWARE',
'005057' => 'BROADBAND',
'005058' => 'VEGASTREAM',
'005059' => 'SUITE',
'00505A' => 'NETWORK',
'00505B' => 'KAWASAKI',
'00505C' => 'TUNDO',
'00505E' => 'DIGITEK',
'00505F' => 'BRAND',
'005060' => 'TANDBERG',
'005062' => 'KOUWELL',
'005063' => 'OY',
'005064' => 'CAE',
'005065' => 'DENSEI-LAMBAD',
'005066' => 'ATECOM',
'005067' => 'AEROCOMM',
'005068' => 'ELECTRONIC',
'005069' => 'PIXSTREAM',
'00506A' => 'EDEVA',
'00506B' => 'SPX-ATEG',
'00506C' => 'G',
'00506D' => 'VIDEOJET',
'00506E' => 'CORDER',
'00506F' => 'G-CONNECT',
'005070' => 'CHAINTECH',
'005071' => 'AIWA',
'005072' => 'CORVIS',
'005073' => 'CISCO',
'005074' => 'ADVANCED',
'005075' => 'KESTREL',
'005076' => 'IBM',
'005077' => 'PROLIFIC',
'005078' => 'MEGATON',
'005079' => 'IEEE',
'00507A' => 'XPEED',
'00507B' => 'MERLOT',
'00507C' => 'VIDEOCON',
'00507D' => 'IFP',
'00507E' => 'NEWER',
'00507F' => 'DRAYTEK',
'005080' => 'CISCO',
'005081' => 'MURATA',
'005082' => 'FORESSON',
'005083' => 'GILBARCO',
'005084' => 'ATL',
'005086' => 'TELKOM',
'005087' => 'TERASAKI',
'005088' => 'AMANO',
'005089' => 'SAFETY',
'00508B' => 'COMPAQ',
'00508C' => 'RSI',
'00508D' => 'ABIT',
'00508E' => 'OPTIMATION',
'00508F' => 'ASITA',
'005090' => 'DCTRI',
'005091' => 'NETACCESS',
'005092' => 'RIGAKU',
'005093' => 'BOEING',
'005094' => 'PACE',
'005095' => 'PERACOM',
'005096' => 'SALIX',
'005097' => 'MMC-EMBEDDED',
'005098' => 'GLOBALOOP',
'005099' => '3COM',
'00509A' => 'TAG',
'00509B' => 'SWITCHCORE',
'00509C' => 'BETA',
'00509D' => 'THE',
'00509E' => 'LES',
'00509F' => 'HORIZON',
'0050A0' => 'DELTA',
'0050A1' => 'CARLO',
'0050A2' => 'CISCO',
'0050A3' => 'TRANSMEDIA',
'0050A4' => 'IO',
'0050A5' => 'CAPITOL',
'0050A6' => 'OPTRONICS',
'0050A7' => 'CISCO',
'0050A8' => 'OPENCON',
'0050A9' => 'MOLDAT',
'0050AA' => 'KONICA',
'0050AB' => 'NALTEC',
'0050AC' => 'MAPLE',
'0050AD' => 'COMMUNIQUE',
'0050AE' => 'IWAKI',
'0050AF' => 'INTERGON',
'0050B0' => 'TECHNOLOGY',
'0050B1' => 'GIDDINGS',
'0050B2' => 'BRODEL',
'0050B3' => 'VOICEBOARD',
'0050B4' => 'SATCHWELL',
'0050B5' => 'FICHET-BAUCHE',
'0050B6' => 'GOOD',
'0050B7' => 'BOSER',
'0050B8' => 'INOVA',
'0050B9' => 'XITRON',
'0050BA' => 'D-LINK',
'0050BB' => 'CMS',
'0050BC' => 'HAMMER',
'0050BD' => 'CISCO',
'0050BE' => 'FAST',
'0050BF' => 'MOTOTECH',
'0050C0' => 'GATAN',
'0050C1' => 'GEMFLEX',
'0050C2' => 'IEEE',
'0050C4' => 'IMD',
'0050C5' => 'ADS',
'0050C6' => 'LOOP',
'0050C8' => 'ADDONICS',
'0050C9' => 'MASPRO',
'0050CA' => 'NET',
'0050CB' => 'JETTER',
'0050CC' => 'XYRATEX',
'0050CD' => 'DIGIANSWER',
'0050CE' => 'LG',
'0050CF' => 'VANLINK',
'0050D0' => 'MINERVA',
'0050D1' => 'CISCO',
'0050D2' => 'BAE',
'0050D3' => 'DIGITAL',
'0050D4' => 'JOOHONG',
'0050D5' => 'AD',
'0050D6' => 'ATLAS',
'0050D7' => 'TELSTRAT',
'0050D8' => 'UNICORN',
'0050D9' => 'ENGETRON-ENGENHARIA',
'0050DA' => '3COM',
'0050DB' => 'CONTEMPORARY',
'0050DC' => 'TAS',
'0050DD' => 'SERRA',
'0050DE' => 'SIGNUM',
'0050DF' => 'AIRFIBER',
'0050E1' => 'NS',
'0050E2' => 'CISCO',
'0050E3' => 'TELEGATE',
'0050E4' => 'APPLE',
'0050E6' => 'HAKUSAN',
'0050E7' => 'PARADISE',
'0050E8' => 'NOMADIX',
'0050EA' => 'XEL',
'0050EB' => 'ALPHA-TOP',
'0050EC' => 'OLICOM',
'0050ED' => 'ANDA',
'0050EE' => 'TEK',
'0050EF' => 'SPE',
'0050F0' => 'CISCO',
'0050F1' => 'LIBIT',
'0050F2' => 'MICROSOFT',
'0050F3' => 'GLOBAL',
'0050F4' => 'SIGMATEK',
'0050F6' => 'PAN-INTERNATIONAL',
'0050F7' => 'VENTURE',
'0050F8' => 'ENTREGA',
'0050F9' => 'PRIVATE',
'0050FA' => 'OXTEL',
'0050FB' => 'VSK',
'0050FC' => 'EDIMAX',
'0050FD' => 'ISIONCOMM',
'0050FE' => 'PCTVNET',
'0050FF' => 'HAKKO',
'005500' => 'XEROX',
'006000' => 'XYCOM',
'006001' => 'INNOSYS',
'006002' => 'SCREEN',
'006003' => 'TERAOKA',
'006004' => 'COMPUTADORES',
'006005' => 'FEEDBACK',
'006006' => 'SOTEC',
'006007' => 'ACRES',
'006008' => '3COM',
'006009' => 'CISCO',
'00600A' => 'SORD',
'00600B' => 'LOGWARE',
'00600C' => 'APPLIED',
'00600D' => 'DIGITAL',
'00600E' => 'WAVENET',
'00600F' => 'WESTELL',
'006010' => 'NETWORK',
'006011' => 'CRYSTAL',
'006012' => 'POWER',
'006013' => 'NETSTAL',
'006014' => 'EDEC',
'006015' => 'NET2NET',
'006016' => 'CLARIION',
'006017' => 'TOKIMEC',
'006018' => 'STELLAR',
'006019' => 'BOEHRINGER',
'00601A' => 'KEITHLEY',
'00601B' => 'MESA',
'00601C' => 'TELXON',
'00601D' => 'LUCENT',
'00601E' => 'SOFTLAB',
'00601F' => 'STALLION',
'006020' => 'PIVOTAL',
'006021' => 'DSC',
'006022' => 'VICOM',
'006023' => 'PERICOM',
'006024' => 'GRADIENT',
'006025' => 'ACTIVE',
'006026' => 'VIKING',
'006027' => 'SUPERIOR',
'006028' => 'MACROVISION',
'006029' => 'CARY',
'00602A' => 'SYMICRON',
'00602B' => 'PEAK',
'00602C' => 'LINX',
'00602D' => 'ALERTON',
'00602E' => 'CYCLADES',
'00602F' => 'CISCO',
'006030' => 'VILLAGETRONIC',
'006031' => 'HRK',
'006032' => 'I-CUBE',
'006033' => 'ACUITY',
'006034' => 'ROBERT',
'006035' => 'DALLAS',
'006036' => 'AUSTRIAN',
'006037' => 'PHILIPS',
'006038' => 'NORTEL',
'006039' => 'SANCOM',
'00603A' => 'QUICK',
'00603B' => 'AMTEC',
'00603C' => 'HAGIWARA',
'00603D' => '3CX',
'00603E' => 'CISCO',
'00603F' => 'PATAPSCO',
'006040' => 'NETRO',
'006041' => 'YOKOGAWA',
'006042' => 'TKS',
'006043' => 'COMSOFT',
'006044' => 'LITTON/POLY-SCIENTIFIC',
'006045' => 'PATHLIGHT',
'006046' => 'VMETRO',
'006047' => 'CISCO',
'006048' => 'EMC',
'006049' => 'VINA',
'00604A' => 'SAIC',
'00604B' => 'BIODATA',
'00604C' => 'SAT',
'00604D' => 'MMC',
'00604E' => 'CYCLE',
'00604F' => 'SUZUKI',
'006050' => 'INTERNIX',
'006051' => 'QUALITY',
'006052' => 'REALTEK',
'006053' => 'TOYODA',
'006054' => 'CONTROLWARE',
'006055' => 'CORNELL',
'006056' => 'NETWORK',
'006057' => 'MURATA',
'006058' => 'COPPER',
'006059' => 'TECHNICAL',
'00605A' => 'CELCORE',
'00605B' => 'INTRASERVER',
'00605C' => 'CISCO',
'00605D' => 'SCANIVALVE',
'00605E' => 'LIBERTY',
'00605F' => 'NIPPON',
'006060' => 'DAWNING',
'006061' => 'WHISTLE',
'006062' => 'TELESYNC',
'006063' => 'PSION',
'006064' => 'NETCOMM',
'006065' => 'BERNECKER',
'006066' => 'LACROIX',
'006067' => 'ACER',
'006068' => 'EICON',
'006069' => 'BROCADE',
'00606A' => 'MITSUBISHI',
'00606B' => 'AICHI',
'00606C' => 'ARESCOM',
'00606D' => 'DIGITAL',
'00606E' => 'DAVICOM',
'00606F' => 'CLARION',
'006070' => 'CISCO',
'006071' => 'MIDAS',
'006072' => 'VXL',
'006073' => 'REDCREEK',
'006074' => 'QSC',
'006075' => 'PENTEK',
'006076' => 'SCHLUMBERGER',
'006077' => 'PRISA',
'006078' => 'POWER',
'006079' => 'WAVEPHORE',
'00607A' => 'DVS',
'00607B' => 'FORE',
'00607C' => 'WAVEACCESS',
'00607D' => 'SENTIENT',
'00607E' => 'GIGALABS',
'00607F' => 'AURORA',
'006080' => 'MICROTRONIX',
'006081' => 'TV/COM',
'006082' => 'NOVALINK',
'006083' => 'CISCO',
'006084' => 'DIGITAL',
'006085' => 'STORAGE',
'006086' => 'LOGIC',
'006087' => 'KANSAI',
'006088' => 'WHITE',
'006089' => 'XATA',
'00608A' => 'CITADEL',
'00608B' => 'CONFERTECH',
'00608C' => '3COM',
'00608D' => 'UNIPULSE',
'00608E' => 'HE',
'00608F' => 'TEKRAM',
'006090' => 'ABLE',
'006091' => 'FIRST',
'006092' => 'MICRO/SYS',
'006093' => 'VARIAN',
'006094' => 'AMD',
'006095' => 'ACCU-TIME',
'006096' => 'T',
'006097' => '3COM',
'006098' => 'HT',
'006099' => 'LAN',
'00609A' => 'NJK',
'00609B' => 'ASTRO-MED',
'00609C' => 'PERKINELMER',
'00609D' => 'PMI',
'00609E' => 'X3',
'00609F' => 'PHAST',
'0060A0' => 'SWITCHED',
'0060A1' => 'VPNET',
'0060A2' => 'NIHON',
'0060A3' => 'CONTINUUM',
'0060A4' => 'GRINAKER',
'0060A5' => 'PERFORMANCE',
'0060A6' => 'PARTICLE',
'0060A7' => 'MICROSENS',
'0060A8' => 'TIDOMAT',
'0060A9' => 'GESYTEC',
'0060AA' => 'INTELLIGENT',
'0060AB' => 'LARSCOM',
'0060AC' => 'RESILIENCE',
'0060AD' => 'MEGACHIPS',
'0060AE' => 'TRIO',
'0060AF' => 'PACIFIC',
'0060B0' => 'HP',
'0060B1' => 'INPUT/OUTPUT',
'0060B2' => 'PROCESS',
'0060B3' => 'Siemens I-Gate ZCom',
'0060B4' => 'GLENAYRE',
'0060B5' => 'KEBA',
'0060B6' => 'LAND',
'0060B7' => 'CHANNELMATIC',
'0060B8' => 'CORELIS',
'0060B9' => 'NITSUKO',
'0060BA' => 'SAHARA',
'0060BB' => 'CABLETRON',
'0060BC' => 'KEUNYOUNG',
'0060BD' => 'HUBBELL-PULSECOM',
'0060BE' => 'WEBTRONICS',
'0060BF' => 'MACRAIGOR',
'0060C0' => 'NERA',
'0060C1' => 'WAVESPAN',
'0060C2' => 'MPL',
'0060C3' => 'NETVISION',
'0060C4' => 'SOLITON',
'0060C5' => 'ANCOT',
'0060C6' => 'DCS',
'0060C7' => 'AMATI',
'0060C8' => 'KUKA',
'0060C9' => 'CONTROLNET',
'0060CA' => 'HARMONIC',
'0060CB' => 'HITACHI',
'0060CC' => 'EMTRAK',
'0060CD' => 'VIDEOSERVER',
'0060CE' => 'ACCLAIM',
'0060CF' => 'ALTEON',
'0060D0' => 'SNMP',
'0060D1' => 'CASCADE',
'0060D2' => 'LUCENT',
'0060D3' => 'AT&T',
'0060D4' => 'ELDAT',
'0060D5' => 'MIYACHI',
'0060D6' => 'NOVATEL',
'0060D7' => 'ECOLE',
'0060D8' => 'ELMIC',
'0060D9' => 'TRANSYS',
'0060DA' => 'JBM',
'0060DB' => 'NTP',
'0060DC' => 'TOYO',
'0060DD' => 'MYRICOM',
'0060DE' => 'KAYSER-THREDE',
'0060DF' => 'INRANGE',
'0060E0' => 'AXIOM',
'0060E1' => 'ORCKIT',
'0060E2' => 'QUEST',
'0060E3' => 'ARBIN',
'0060E4' => 'COMPUSERVE',
'0060E5' => 'FUJI',
'0060E6' => 'SHOMITI',
'0060E7' => 'RANDATA',
'0060E8' => 'HITACHI',
'0060E9' => 'ATOP',
'0060EA' => 'STREAMLOGIC',
'0060EB' => 'FOURTHTRACK',
'0060EC' => 'HERMARY',
'0060ED' => 'RICARDO',
'0060EE' => 'APOLLO',
'0060EF' => 'FLYTECH',
'0060F0' => 'JOHNSON',
'0060F1' => 'EXP',
'0060F2' => 'LASERGRAPHICS',
'0060F3' => 'NETCOM',
'0060F4' => 'ADVANCED',
'0060F5' => 'PHOBOS',
'0060F6' => 'NEXTEST',
'0060F7' => 'DATAFUSION',
'0060F8' => 'LORAN',
'0060F9' => 'DIAMOND',
'0060FA' => 'EDUCATIONAL',
'0060FB' => 'PACKETEER',
'0060FC' => 'CONSERVATION',
'0060FD' => 'NETICS',
'0060FE' => 'LYNX',
'0060FF' => 'QUVIS',
'0070B0' => 'M/A-COM',
'0070B3' => 'DATA',
'008000' => 'MULTITECH',
'008001' => 'PERIPHONICS',
'008002' => 'SATELCOM',
'008003' => 'HYTEC',
'008004' => 'ANTLOW',
'008005' => 'CACTUS',
'008006' => 'COMPUADD',
'008007' => 'DLOG',
'008008' => 'DYNATECH',
'008009' => 'JUPITER',
'00800A' => 'JAPAN',
'00800B' => 'CSK',
'00800C' => 'VIDECOM',
'00800D' => 'VOSSWINKEL',
'00800E' => 'ATLANTIX',
'00800F' => 'SMC',
'008010' => 'COMMODORE',
'008011' => 'DIGITAL',
'008012' => 'IMS',
'008013' => 'THOMAS',
'008014' => 'ESPRIT',
'008015' => 'SEIKO',
'008016' => 'WANDEL',
'008017' => 'PFU',
'008018' => 'KOBE',
'008019' => 'DAYNA',
'00801A' => 'BELL',
'00801B' => 'KODIAK',
'00801C' => 'CISCO',
'00801D' => 'INTEGRATED',
'00801E' => 'XINETRON',
'00801F' => 'KRUPP',
'008020' => 'NETWORK',
'008021' => 'NEWBRIDGE',
'008022' => 'SCAN-OPTICS',
'008023' => 'INTEGRATED',
'008024' => 'KALPANA',
'008025' => 'STOLLMANN',
'008026' => 'NETWORK',
'008027' => 'ADAPTIVE',
'008028' => 'TRADPOST',
'008029' => 'MICRODYNE',
'00802A' => 'TEST',
'00802B' => 'INTEGRATED',
'00802C' => 'THE',
'00802D' => 'XYLOGICS',
'00802E' => 'PLEXCOM',
'00802F' => 'NATIONAL',
'008030' => 'NEXUS',
'008031' => 'BASYS',
'008032' => 'ACCESS',
'008033' => 'FORMATION',
'008034' => 'SMT-GOUPIL',
'008035' => 'TECHNOLOGY',
'008036' => 'REFLEX',
'008037' => 'ERICSSON',
'008038' => 'DATA',
'008039' => 'ALCATEL',
'00803A' => 'VARITYPER',
'00803B' => 'APT',
'00803C' => 'TVS',
'00803D' => 'SURIGIKEN',
'00803E' => 'SYNERNETICS',
'00803F' => 'HYUNDAI',
'008040' => 'JOHN',
'008041' => 'VEB',
'008042' => 'FORCE',
'008043' => 'NETWORLD',
'008044' => 'SYSTECH',
'008045' => 'MATSHTA',
'008046' => 'UNIVERSITY',
'008047' => 'IN-NET',
'008048' => 'COMPEX',
'008049' => 'NISSIN',
'00804A' => 'PRO-LOG',
'00804B' => 'EAGLE',
'00804C' => 'CONTEC',
'00804D' => 'CYCLONE',
'00804E' => 'APEX',
'00804F' => 'DAIKIN',
'008050' => 'ZIATECH',
'008051' => 'ADC',
'008052' => 'NETWORK',
'008053' => 'INTELLICOM',
'008054' => 'FRONTIER',
'008055' => 'FERMILAB',
'008056' => 'SPHINX',
'008057' => 'ADSOFT',
'008058' => 'PRINTER',
'008059' => 'STANLEY',
'00805A' => 'TULIP',
'00805B' => 'CONDOR',
'00805C' => 'AGILIS',
'00805D' => 'CANSTAR',
'00805E' => 'LSI',
'00805F' => 'COMPAQ',
'008060' => 'NETWORK',
'008061' => 'LITTON',
'008062' => 'INTERFACE',
'008063' => 'RICHARD',
'008064' => 'WYSE',
'008065' => 'CYBERGRAPHIC',
'008066' => 'ARCOM',
'008067' => 'SQUARE',
'008068' => 'YAMATECH',
'008069' => 'COMPUTONE',
'00806A' => 'ERI',
'00806B' => 'SCHMID',
'00806C' => 'CEGELEC',
'00806D' => 'CENTURY',
'00806E' => 'NIPPON',
'00806F' => 'ONELAN',
'008070' => 'COMPUTADORAS',
'008071' => 'SAI',
'008072' => 'MICROPLEX',
'008073' => 'DWB',
'008074' => 'FISHER',
'008075' => 'PARSYTEC',
'008076' => 'MCNC',
'008077' => 'BROTHER',
'008078' => 'PRACTICAL',
'008079' => 'MICROBUS',
'00807A' => 'AITECH',
'00807B' => 'ARTEL',
'00807C' => 'FIBERCOM',
'00807D' => 'EQUINOX',
'00807E' => 'SOUTHERN',
'00807F' => 'DY-4',
'008080' => 'DATAMEDIA',
'008081' => 'KENDALL',
'008082' => 'PEP',
'008083' => 'AMDAHL',
'008084' => 'THE',
'008085' => 'H-THREE',
'008086' => 'COMPUTER',
'008087' => 'OKIDATA',
'008088' => 'VICTOR',
'008089' => 'TECNETICS',
'00808A' => 'SUMMIT',
'00808B' => 'DACOLL',
'00808C' => 'NETSCOUT',
'00808D' => 'WESTCOVE',
'00808E' => 'RADSTONE',
'00808F' => 'C',
'008090' => 'MICROTEK',
'008091' => 'TOKYO',
'008092' => 'JAPAN',
'008093' => 'XYRON',
'008094' => 'SATTCONTROL',
'008095' => 'BASIC',
'008096' => 'HDS',
'008097' => 'CENTRALP',
'008098' => 'TDK',
'008099' => 'KLOCKNER',
'00809A' => 'NOVUS',
'00809B' => 'JUSTSYSTEM',
'00809C' => 'LUXCOM',
'00809D' => 'DATACRAFT',
'00809E' => 'DATUS',
'00809F' => 'ALCATEL',
'0080A0' => 'EDISA',
'0080A1' => 'MICROTEST',
'0080A2' => 'CREATIVE',
'0080A3' => 'LANTRONIX',
'0080A4' => 'LIBERTY',
'0080A5' => 'SPEED',
'0080A6' => 'REPUBLIC',
'0080A7' => 'MEASUREX',
'0080A8' => 'VITACOM',
'0080A9' => 'CLEARPOINT',
'0080AA' => 'MAXPEED',
'0080AB' => 'DUKANE',
'0080AC' => 'IMLOGIX',
'0080AD' => 'TELEBIT',
'0080AE' => 'HUGHES',
'0080AF' => 'ALLUMER',
'0080B0' => 'ADVANCED',
'0080B1' => 'SOFTCOM',
'0080B2' => 'NET',
'0080B3' => 'AVAL',
'0080B4' => 'SOPHIA',
'0080B5' => 'UNITED',
'0080B6' => 'THEMIS',
'0080B7' => 'STELLAR',
'0080B8' => 'BUG',
'0080B9' => 'ARCHE',
'0080BA' => 'SPECIALIX',
'0080BB' => 'HUGHES',
'0080BC' => 'HITACHI',
'0080BD' => 'THE',
'0080BE' => 'ARIES',
'0080BF' => 'TAKAOKA',
'0080C0' => 'PENRIL',
'0080C1' => 'LANEX',
'0080C2' => 'IEEE',
'0080C3' => 'BICC',
'0080C4' => 'DOCUMENT',
'0080C5' => 'NOVELLCO',
'0080C6' => 'SOHO',
'0080C7' => 'XIRCOM',
'0080C8' => 'D-LINK',
'0080C9' => 'ALBERTA',
'0080CA' => 'NETCOM',
'0080CB' => 'FALCO',
'0080CC' => 'MICROWAVE',
'0080CD' => 'MICRONICS',
'0080CE' => 'BROADCAST',
'0080CF' => 'EMBEDDED',
'0080D0' => 'COMPUTER',
'0080D1' => 'KIMTRON',
'0080D2' => 'SHINNIHONDENKO',
'0080D3' => 'SHIVA',
'0080D4' => 'CHASE',
'0080D5' => 'CADRE',
'0080D6' => 'APPLE',
'0080D7' => 'FANTUM',
'0080D8' => 'NETWORK',
'0080D9' => 'EMK',
'0080DA' => 'BRUEL',
'0080DB' => 'GRAPHON',
'0080DC' => 'PICKER',
'0080DD' => 'GMX',
'0080DE' => 'GIPSI',
'0080DF' => 'ADC',
'0080E0' => 'XTP',
'0080E1' => 'STMICROELECTRONICS',
'0080E2' => 'T',
'0080E3' => 'CORAL',
'0080E4' => 'NORTHWEST',
'0080E5' => 'MYLEX',
'0080E6' => 'PEER',
'0080E7' => 'LYNWOOD',
'0080E8' => 'CUMULUS',
'0080E9' => 'MADGE',
'0080EA' => 'THE',
'0080EB' => 'COMPCONTROL',
'0080EC' => 'SUPERCOMPUTING',
'0080ED' => 'IQ',
'0080EE' => 'THOMSON',
'0080EF' => 'RATIONAL',
'0080F0' => 'KYUSHU',
'0080F1' => 'OPUS',
'0080F2' => 'RAYCOM',
'0080F3' => 'SUN',
'0080F4' => 'TELEMECHANIQUE',
'0080F5' => 'QUANTEL',
'0080F6' => 'SYNERGY',
'0080F7' => 'ZENITH',
'0080F8' => 'MIZAR',
'0080F9' => 'HEURIKON',
'0080FA' => 'RWT',
'0080FB' => 'BVM',
'0080FC' => 'AVATAR',
'0080FD' => 'EXSCEED',
'0080FE' => 'AZURE',
'0080FF' => 'SOC',
'009000' => 'DIAMOND',
'009001' => 'NISHIMU',
'009002' => 'ALLGON',
'009003' => 'APLIO',
'009004' => '3COM',
'009005' => 'PROTECH',
'009006' => 'HAMAMATSU',
'009007' => 'DOMEX',
'009008' => 'HAN',
'009009' => 'I',
'00900A' => 'PROTON',
'00900B' => 'LANNER',
'00900C' => 'CISCO',
'00900D' => 'OVERLAND',
'00900E' => 'HANDLINK',
'00900F' => 'KAWASAKI',
'009010' => 'SIMULATION',
'009011' => 'WAVTRACE',
'009012' => 'GLOBESPAN',
'009013' => 'SAMSAN',
'009014' => 'ROTORK',
'009015' => 'CENTIGRAM',
'009016' => 'ZAC',
'009017' => 'ZYPCOM',
'009018' => 'ITO',
'009019' => 'HERMES',
'00901A' => 'UNISPHERE',
'00901B' => 'DIGITAL',
'00901C' => 'MPS',
'00901D' => 'PEC',
'00901E' => 'SELESTA',
'00901F' => 'ADTEC',
'009020' => 'PHILIPS',
'009021' => 'CISCO',
'009022' => 'IVEX',
'009023' => 'ZILOG',
'009024' => 'PIPELINKS',
'009025' => 'VISION',
'009026' => 'ADVANCED',
'009027' => 'INTEL',
'009028' => 'NIPPON',
'009029' => 'CRYPTO',
'00902A' => 'COMMUNICATION',
'00902B' => 'CISCO',
'00902C' => 'DATA',
'00902D' => 'DATA',
'00902E' => 'NAMCO',
'00902F' => 'NETCORE',
'009030' => 'HONEYWELL-DATING',
'009031' => 'MYSTICOM',
'009032' => 'PELCOMBE',
'009033' => 'INNOVAPHONE',
'009034' => 'IMAGIC',
'009035' => 'ALPHA',
'009036' => 'ENS',
'009037' => 'ACUCOMM',
'009038' => 'FOUNTAIN',
'009039' => 'SHASTA',
'00903A' => 'NIHON',
'00903B' => 'TRIEMS',
'00903C' => 'ATLANTIC',
'00903D' => 'BIOPAC',
'00903E' => 'N',
'00903F' => 'AZTEC',
'009040' => 'CASTLE',
'009041' => 'APPLIED',
'009042' => 'ECCS',
'009043' => 'NICHIBEI',
'009044' => 'ASSURED',
'009045' => 'MARCONI',
'009046' => 'DEXDYNE',
'009047' => 'GIGA',
'009048' => 'ZEAL',
'009049' => 'ENTRIDIA',
'00904A' => 'CONCUR',
'00904B' => 'GEMTEK',
'00904C' => 'EPIGRAM',
'00904D' => 'SPEC',
'00904E' => 'DELEM',
'00904F' => 'ABB',
'009050' => 'TELESTE',
'009051' => 'ULTIMATE',
'009052' => 'SELCOM',
'009053' => 'DAEWOO',
'009054' => 'INNOVATIVE',
'009055' => 'PARKER',
'009056' => 'TELESTREAM',
'009057' => 'AANETCOM',
'009058' => 'ULTRA',
'009059' => 'TELECOM',
'00905A' => 'DEARBORN',
'00905B' => 'RAYMOND',
'00905C' => 'EDMI',
'00905D' => 'NETCOM',
'00905E' => 'RAULAND-BORG',
'00905F' => 'CISCO',
'009060' => 'SYSTEM',
'009061' => 'PACIFIC',
'009062' => 'ICP',
'009063' => 'COHERENT',
'009064' => 'THOMSON',
'009065' => 'FINISAR',
'009066' => 'TROIKA',
'009067' => 'WALKABOUT',
'009068' => 'DVT',
'009069' => 'JUNIPER',
'00906A' => 'TURNSTONE',
'00906B' => 'APPLIED',
'00906C' => 'GWT',
'00906D' => 'CISCO',
'00906E' => 'PRAXON',
'00906F' => 'CISCO',
'009070' => 'NEO',
'009071' => 'BADGER',
'009072' => 'SIMRAD',
'009073' => 'GAIO',
'009074' => 'ARGON',
'009075' => 'NEC',
'009076' => 'FMT',
'009077' => 'ADVANCED',
'009078' => 'MER',
'009079' => 'CLEARONE',
'00907A' => 'SPECTRALINK',
'00907B' => 'E-TECH',
'00907C' => 'DIGITALCAST',
'00907D' => 'LAKE',
'00907E' => 'VETRONIX',
'00907F' => 'WATCHGUARD',
'009080' => 'NOT',
'009081' => 'ALOHA',
'009082' => 'FORCE',
'009083' => 'TURBO',
'009084' => 'ATECH',
'009085' => 'GOLDEN',
'009086' => 'CISCO',
'009087' => 'ITIS',
'009088' => 'BAXALL',
'009089' => 'SOFTCOM',
'00908A' => 'BAYLY',
'00908B' => 'CELL',
'00908C' => 'ETREND',
'00908D' => 'VICKERS',
'00908E' => 'NORTEL',
'00908F' => 'AUDIOCODES',
'009090' => 'I-BUS',
'009091' => 'DIGITALSCAPE',
'009092' => 'CISCO',
'009093' => 'NANAO',
'009094' => 'OSPREY',
'009095' => 'UNIVERSAL',
'009096' => 'ASKEY',
'009097' => 'SYCAMORE',
'009098' => 'SBC',
'009099' => 'ALLIED',
'00909A' => 'ONE',
'00909B' => 'MARKPOINT',
'00909C' => 'COMBOX',
'00909D' => 'GSE',
'00909E' => 'DELPHI',
'00909F' => 'DIGI-DATA',
'0090A0' => '8X8',
'0090A1' => 'FLYING',
'0090A2' => 'CYBERTAN',
'0090A3' => 'CORECESS',
'0090A4' => 'ALTIGA',
'0090A5' => 'SPECTRA',
'0090A6' => 'CISCO',
'0090A7' => 'CLIENTEC',
'0090A8' => 'NINETILES',
'0090A9' => 'WESTERN',
'0090AA' => 'INDIGO',
'0090AB' => 'CISCO',
'0090AC' => 'OPTIVISION',
'0090AD' => 'ASPECT',
'0090AE' => 'ITALTEL',
'0090AF' => 'J',
'0090B0' => 'VADEM',
'0090B1' => 'CISCO',
'0090B2' => 'AVICI',
'0090B3' => 'AGRANAT',
'0090B4' => 'WILLOWBROOK',
'0090B5' => 'NIKON',
'0090B6' => 'FIBEX',
'0090B7' => 'DIGITAL',
'0090B8' => 'ROHDE',
'0090B9' => 'BERAN',
'0090BA' => 'VALID',
'0090BB' => 'TAINET',
'0090BC' => 'TELEMANN',
'0090BD' => 'OMNIA',
'0090BE' => 'IBC/INTEGRATED',
'0090BF' => 'CISCO',
'0090C0' => 'K',
'0090C1' => 'EDA',
'0090C2' => 'JK',
'0090C3' => 'TOPIC',
'0090C4' => 'JAVELIN',
'0090C5' => 'INTERNET',
'0090C6' => 'OPTIM',
'0090C7' => 'ICOM',
'0090C8' => 'WAVERIDER',
'0090C9' => 'PRODUCTIVITY',
'0090CA' => 'ACCORD',
'0090CB' => 'WIRELESS',
'0090CC' => 'PLANEX',
'0090CD' => 'ENT-EMPRESA',
'0090CE' => 'TETRA',
'0090CF' => 'NORTEL',
'0090D0' => 'ALCATEL',
'0090D1' => 'LEICHU',
'0090D2' => 'ARTEL',
'0090D3' => 'GIESECKE',
'0090D4' => 'BINDVIEW',
'0090D5' => 'EUPHONIX',
'0090D6' => 'CRYSTAL',
'0090D7' => 'NETBOOST',
'0090D8' => 'WHITECROSS',
'0090D9' => 'CISCO',
'0090DA' => 'DYNARC',
'0090DB' => 'NEXT',
'0090DC' => 'TECO',
'0090DD' => 'THE',
'0090DE' => 'CARDKEY',
'0090DF' => 'MITSUBISHI',
'0090E0' => 'SYSTRAN',
'0090E1' => 'TELENA',
'0090E2' => 'DISTRIBUTED',
'0090E3' => 'AVEX',
'0090E4' => 'NEC',
'0090E5' => 'TEKNEMA',
'0090E6' => 'ACER',
'0090E7' => 'HORSCH',
'0090E8' => 'MOXA',
'0090E9' => 'JANZ',
'0090EA' => 'ALPHA',
'0090EB' => 'SENTRY',
'0090EC' => 'PYRESCOM',
'0090ED' => 'CENTRAL',
'0090EE' => 'PERSONAL',
'0090EF' => 'INTEGRIX',
'0090F0' => 'HARMONIC',
'0090F1' => 'DOT',
'0090F2' => 'CISCO',
'0090F3' => 'ASPECT',
'0090F4' => 'LIGHTNING',
'0090F5' => 'CLEVO',
'0090F6' => 'ESCALATE',
'0090F7' => 'NBASE',
'0090F8' => 'MEDIATRIX',
'0090F9' => 'LEITCH',
'0090FA' => 'GIGANET',
'0090FB' => 'PORTWELL',
'0090FC' => 'NETWORK',
'0090FD' => 'COPPERCOM',
'0090FE' => 'ELECOM',
'0090FF' => 'TELLUS',
'009D8E' => 'CARDIAC',
'00A000' => 'BAY',
'00A001' => 'WATKINS-JOHNSON',
'00A002' => 'LEEDS',
'00A003' => 'STAEFA',
'00A004' => 'NETPOWER',
'00A005' => 'DANIEL',
'00A006' => 'IMAGE',
'00A007' => 'APEXX',
'00A008' => 'NETCORP',
'00A009' => 'WHITETREE',
'00A00A' => 'R',
'00A00B' => 'COMPUTEX',
'00A00C' => 'KINGMAX',
'00A00D' => 'THE',
'00A00E' => 'VISUAL',
'00A00F' => 'BROADBAND',
'00A010' => 'SYSLOGIC',
'00A011' => 'MUTOH',
'00A012' => 'B',
'00A013' => 'TELTREND',
'00A014' => 'CSIR',
'00A015' => 'WYLE',
'00A016' => 'MICROPOLIS',
'00A017' => 'J',
'00A018' => 'CREATIVE',
'00A019' => 'NEBULA',
'00A01A' => 'BINAR',
'00A01B' => 'PREMISYS',
'00A01C' => 'NASCENT',
'00A01D' => 'SIXNET',
'00A01E' => 'EST',
'00A01F' => 'TRICORD',
'00A020' => 'CITICORP/TTI',
'00A021' => 'GENERAL',
'00A022' => 'CENTRE',
'00A023' => 'APPLIED',
'00A024' => '3COM',
'00A025' => 'REDCOM',
'00A026' => 'TELDAT',
'00A027' => 'FIREPOWER',
'00A028' => 'CONNER',
'00A029' => 'COULTER',
'00A02A' => 'TRANCELL',
'00A02B' => 'TRANSITIONS',
'00A02C' => 'INTERWAVE',
'00A02D' => '1394',
'00A02E' => 'BRAND',
'00A02F' => 'PIRELLI',
'00A030' => 'CAPTOR',
'00A031' => 'HAZELTINE',
'00A032' => 'GES',
'00A033' => 'IMC',
'00A034' => 'AXEL',
'00A035' => 'CYLINK',
'00A036' => 'APPLIED',
'00A037' => 'DATASCOPE',
'00A038' => 'EMAIL',
'00A039' => 'ROSS',
'00A03A' => 'KUBOTEK',
'00A03B' => 'TOSHIN',
'00A03C' => 'EG&G',
'00A03D' => 'OPTO',
'00A03E' => 'ATM',
'00A03F' => 'COMPUTER',
'00A040' => 'APPLE',
'00A041' => 'LEYBOLD-INFICON',
'00A042' => 'SPUR',
'00A043' => 'AMERICAN',
'00A044' => 'NTT',
'00A045' => 'PHOENIX',
'00A046' => 'SCITEX',
'00A047' => 'INTEGRATED',
'00A048' => 'QUESTECH',
'00A049' => 'DIGITECH',
'00A04A' => 'NISSHIN',
'00A04B' => 'SONIC',
'00A04C' => 'INNOVATIVE',
'00A04D' => 'EDA',
'00A04E' => 'VOELKER',
'00A04F' => 'AMERITEC',
'00A050' => 'CYPRESS',
'00A051' => 'ANGIA',
'00A052' => 'STANILITE',
'00A053' => 'COMPACT',
'00A054' => 'GASSAN',
'00A055' => 'LINKTECH',
'00A056' => 'MICROPROSS',
'00A057' => 'ELSA',
'00A058' => 'GLORY',
'00A059' => 'HAMILTON',
'00A05A' => 'KOFAX',
'00A05B' => 'MARQUIP',
'00A05C' => 'INVENTORY',
'00A05D' => 'CS',
'00A05E' => 'MYRIAD',
'00A05F' => 'BTG',
'00A060' => 'ACER',
'00A061' => 'PURITAN',
'00A062' => 'AES',
'00A063' => 'JRL',
'00A064' => 'KVB/ANALECT',
'00A065' => 'NEXLAND',
'00A066' => 'ISA',
'00A067' => 'NETWORK',
'00A068' => 'BHP',
'00A069' => 'TRUETIME',
'00A06A' => 'VERILINK',
'00A06B' => 'DMS',
'00A06C' => 'SHINDENGEN',
'00A06D' => 'MANNESMANN',
'00A06E' => 'AUSTRON',
'00A06F' => 'THE',
'00A070' => 'COASTCOM',
'00A071' => 'VIDEO',
'00A072' => 'OVATION',
'00A073' => 'COM21',
'00A074' => 'PERCEPTION',
'00A075' => 'MICRON',
'00A076' => 'CARDWARE',
'00A077' => 'FUJITSU',
'00A078' => 'MARCONI',
'00A079' => 'ALPS',
'00A07A' => 'ADVANCED',
'00A07B' => 'DAWN',
'00A07C' => 'TONYANG',
'00A07D' => 'SEEQ',
'00A07E' => 'AVID',
'00A07F' => 'GSM-SYNTEL',
'00A080' => 'ANTARES',
'00A081' => 'ALCATEL',
'00A082' => 'NKT',
'00A083' => 'INTEL',
'00A084' => 'DATAPLEX',
'00A085' => 'IEEE',
'00A086' => 'AMBER',
'00A087' => 'MITEL',
'00A088' => 'ESSENTIAL',
'00A089' => 'XPOINT',
'00A08A' => 'BROOKTROUT',
'00A08B' => 'ASTON',
'00A08C' => 'MULTIMEDIA',
'00A08D' => 'JACOMO',
'00A08E' => 'NOKIA',
'00A08F' => 'DESKNET',
'00A090' => 'TIMESTEP',
'00A091' => 'APPLICOM',
'00A092' => 'INTERMATE',
'00A093' => 'B/E',
'00A094' => 'COMSAT',
'00A095' => 'ACACIA',
'00A096' => 'MITSUMI',
'00A097' => 'JC',
'00A098' => 'NETWORK',
'00A099' => 'K-NET',
'00A09A' => 'NIHON',
'00A09B' => 'QPSX',
'00A09C' => 'XYPLEX',
'00A09D' => 'JOHNATHON',
'00A09E' => 'ICTV',
'00A09F' => 'COMMVISION',
'00A0A0' => 'COMPACT',
'00A0A1' => 'EPIC',
'00A0A2' => 'DIGICOM',
'00A0A3' => 'RELIABLE',
'00A0A4' => 'MICROS',
'00A0A5' => 'TEKNOR',
'00A0A6' => 'M',
'00A0A7' => 'VORAX',
'00A0A8' => 'RENEX',
'00A0A9' => 'GN',
'00A0AA' => 'SPACELABS',
'00A0AB' => 'NETCS',
'00A0AC' => 'GILAT',
'00A0AD' => 'MARCONI',
'00A0AE' => 'NETWORK',
'00A0AF' => 'WMS',
'00A0B0' => 'I-O',
'00A0B1' => 'FIRST',
'00A0B2' => 'SHIMA',
'00A0B3' => 'ZYKRONIX',
'00A0B4' => 'TEXAS',
'00A0B5' => '3H',
'00A0B6' => 'SANRITZ',
'00A0B7' => 'CORDANT',
'00A0B8' => 'SYMBIOS',
'00A0B9' => 'EAGLE',
'00A0BA' => 'PATTON',
'00A0BB' => 'HILAN',
'00A0BC' => 'VIASAT',
'00A0BD' => 'I-TECH',
'00A0BE' => 'INTEGRATED',
'00A0BF' => 'WIRELESS',
'00A0C0' => 'DIGITAL',
'00A0C1' => 'ORTIVUS',
'00A0C2' => 'R',
'00A0C3' => 'UNICOMPUTER',
'00A0C4' => 'CRISTIE',
'00A0C5' => 'ZYXEL',
'00A0C6' => 'QUALCOMM',
'00A0C7' => 'TADIRAN',
'00A0C8' => 'ADTRAN',
'00A0C9' => 'INTEL',
'00A0CA' => 'FUJITSU',
'00A0CB' => 'ARK',
'00A0CC' => 'LITE-ON',
'00A0CD' => 'DR',
'00A0CE' => 'ASTROCOM',
'00A0CF' => 'SOTAS',
'00A0D0' => 'TEN',
'00A0D1' => 'NATIONAL',
'00A0D2' => 'ALLIED',
'00A0D3' => 'INSTEM',
'00A0D4' => 'RADIOLAN',
'00A0D5' => 'SIERRA',
'00A0D6' => 'SBE',
'00A0D7' => 'KASTEN',
'00A0D8' => 'SPECTRA',
'00A0D9' => 'CONVEX',
'00A0DA' => 'INTEGRATED',
'00A0DB' => 'FISHER',
'00A0DC' => 'O',
'00A0DD' => 'AZONIX',
'00A0DE' => 'YAMAHA',
'00A0DF' => 'STS',
'00A0E0' => 'TENNYSON',
'00A0E1' => 'WESTPORT',
'00A0E2' => 'KEISOKU',
'00A0E3' => 'XKL',
'00A0E4' => 'OPTIQUEST',
'00A0E5' => 'NHC',
'00A0E6' => 'DIALOGIC',
'00A0E7' => 'CENTRAL',
'00A0E8' => 'REUTERS',
'00A0E9' => 'ELECTRONIC',
'00A0EA' => 'ETHERCOM',
'00A0EB' => 'FASTCOMM',
'00A0EC' => 'TRANSMITTON',
'00A0ED' => 'PRI',
'00A0EE' => 'NASHOBA',
'00A0EF' => 'LUCIDATA',
'00A0F0' => 'TORONTO',
'00A0F1' => 'MTI',
'00A0F2' => 'INFOTEK',
'00A0F3' => 'STAUBLI',
'00A0F4' => 'GE',
'00A0F5' => 'RADGUARD',
'00A0F6' => 'AUTOGAS',
'00A0F7' => 'V',
'00A0F8' => 'SYMBOL',
'00A0F9' => 'BINTEC',
'00A0FA' => 'MARCONI',
'00A0FB' => 'TORAY',
'00A0FC' => 'IMAGE',
'00A0FD' => 'SCITEX',
'00A0FE' => 'BOSTON',
'00A0FF' => 'TELLABS',
'00AA00' => 'INTEL',
'00AA01' => 'INTEL',
'00AA02' => 'INTEL',
'00AA3C' => 'OLIVETTI',
'00B009' => 'GRASS',
'00B017' => 'INFOGEAR',
'00B019' => 'CASI-RUSCO',
'00B01C' => 'WESTPORT',
'00B01E' => 'RANTIC',
'00B02A' => 'ORSYS',
'00B02D' => 'VIAGATE',
'00B03B' => 'HIQ',
'00B048' => 'MARCONI',
'00B04A' => 'CISCO',
'00B052' => 'INTELLON',
'00B064' => 'CISCO',
'00B069' => 'HONEWELL',
'00B06D' => 'JONES',
'00B080' => 'MANNESMANN',
'00B086' => 'LOCSOFT',
'00B08E' => 'CISCO',
'00B091' => 'TRANSMETA',
'00B094' => 'ALARIS',
'00B09A' => 'MORROW',
'00B09D' => 'POINT',
'00B0AC' => 'SIAE-MICROELETTRONICA',
'00B0AE' => 'SYMMETRICOM',
'00B0B3' => 'XSTREAMIS',
'00B0C2' => 'CISCO',
'00B0C7' => 'TELLABS',
'00B0CE' => 'TECHNOLOGY',
'00B0D0' => 'COMPUTER',
'00B0DB' => 'NEXTCELL',
'00B0DF' => 'RELIABLE',
'00B0E7' => 'BRITISH',
'00B0EC' => 'EACEM',
'00B0EE' => 'AJILE',
'00B0F0' => 'CALY',
'00B0F5' => 'NETWORTH',
'00BB01' => 'OCTOTHORPE',
'00BBF0' => 'UNGERMANN-BASS',
'00C000' => 'LANOPTICS',
'00C001' => 'DIATEK',
'00C002' => 'SERCOMM',
'00C003' => 'GLOBALNET',
'00C004' => 'JAPAN',
'00C005' => 'LIVINGSTON',
'00C006' => 'NIPPON',
'00C007' => 'PINNACLE',
'00C008' => 'SECO',
'00C009' => 'KT',
'00C00A' => 'MICRO',
'00C00B' => 'NORCONTROL',
'00C00C' => 'ARK',
'00C00D' => 'ADVANCED',
'00C00E' => 'PSITECH',
'00C00F' => 'QNX',
'00C010' => 'HIRAKAWA',
'00C011' => 'INTERACTIVE',
'00C012' => 'NETSPAN',
'00C013' => 'NETRIX',
'00C014' => 'TELEMATICS',
'00C015' => 'NEW',
'00C016' => 'ELECTRONIC',
'00C017' => 'FLUKE',
'00C018' => 'LANART',
'00C019' => 'LEAP',
'00C01A' => 'COROMETRICS',
'00C01B' => 'SOCKET',
'00C01C' => 'INTERLINK',
'00C01D' => 'GRAND',
'00C01E' => 'LA',
'00C01F' => 'S',
'00C020' => 'ARCO',
'00C021' => 'NETEXPRESS',
'00C022' => 'LASERMASTER',
'00C023' => 'TUTANKHAMON',
'00C024' => 'EDEN',
'00C025' => 'DATAPRODUCTS',
'00C026' => 'LANS',
'00C027' => 'CIPHER',
'00C028' => 'JASCO',
'00C029' => 'KABEL',
'00C02A' => 'OHKURA',
'00C02B' => 'GERLOFF',
'00C02C' => 'CENTRUM',
'00C02D' => 'FUJI',
'00C02E' => 'NETWIZ',
'00C02F' => 'OKUMA',
'00C030' => 'INTEGRATED',
'00C031' => 'DESIGN',
'00C032' => 'I-CUBED',
'00C033' => 'TELEBIT',
'00C034' => 'DALE',
'00C035' => 'QUINTAR',
'00C036' => 'RAYTECH',
'00C037' => 'DYNATEM',
'00C038' => 'RASTER',
'00C039' => 'SILICON',
'00C03A' => 'MEN-MIKRO',
'00C03B' => 'MULTIACCESS',
'00C03C' => 'TOWER',
'00C03D' => 'WIESEMANN',
'00C03E' => 'FA',
'00C03F' => 'STORES',
'00C040' => 'ECCI',
'00C041' => 'DIGITAL',
'00C042' => 'DATALUX',
'00C043' => 'STRATACOM',
'00C044' => 'EMCOM',
'00C045' => 'ISOLATION',
'00C046' => 'KEMITRON',
'00C047' => 'UNIMICRO',
'00C048' => 'BAY',
'00C049' => 'US',
'00C04A' => 'GROUP',
'00C04B' => 'CREATIVE',
'00C04C' => 'DEPARTMENT',
'00C04D' => 'MITEC',
'00C04E' => 'COMTROL',
'00C04F' => 'DELL',
'00C050' => 'TOYO',
'00C051' => 'ADVANCED',
'00C052' => 'BURR-BROWN',
'00C053' => 'DAVOX',
'00C054' => 'NETWORK',
'00C055' => 'MODULAR',
'00C056' => 'SOMELEC',
'00C057' => 'MYCO',
'00C058' => 'DATAEXPERT',
'00C059' => 'NIPPONDENSO',
'00C05A' => 'SEMAPHORE',
'00C05B' => 'NETWORKS',
'00C05C' => 'ELONEX',
'00C05D' => 'L&N',
'00C05E' => 'VARI-LITE',
'00C05F' => 'FINE-PAL',
'00C060' => 'ID',
'00C061' => 'SOLECTEK',
'00C062' => 'IMPULSE',
'00C063' => 'MORNING',
'00C064' => 'GENERAL',
'00C065' => 'SCOPE',
'00C066' => 'DOCUPOINT',
'00C067' => 'UNITED',
'00C068' => 'PHILP',
'00C069' => 'CALIFORNIA',
'00C06A' => 'ZAHNER-ELEKTRIK',
'00C06B' => 'OSI',
'00C06C' => 'SVEC',
'00C06D' => 'BOCA',
'00C06E' => 'HAFT',
'00C06F' => 'KOMATSU',
'00C070' => 'SECTRA',
'00C071' => 'AREANEX',
'00C072' => 'KNX',
'00C073' => 'XEDIA',
'00C074' => 'TOYODA',
'00C075' => 'XANTE',
'00C076' => 'I-DATA',
'00C077' => 'DAEWOO',
'00C078' => 'COMPUTER',
'00C079' => 'FONSYS',
'00C07A' => 'PRIVA',
'00C07B' => 'ASCEND',
'00C07C' => 'HIGHTECH',
'00C07D' => 'RISC',
'00C07E' => 'KUBOTA',
'00C07F' => 'NUPON',
'00C080' => 'NETSTAR',
'00C081' => 'METRODATA',
'00C082' => 'MOORE',
'00C083' => 'TRACE',
'00C084' => 'DATA',
'00C085' => 'CANON',
'00C086' => 'THE',
'00C087' => 'UUNET',
'00C088' => 'EKF',
'00C089' => 'TELINDUS',
'00C08A' => 'LAUTERBACH',
'00C08B' => 'RISQ',
'00C08C' => 'PERFORMANCE',
'00C08D' => 'TRONIX',
'00C08E' => 'NETWORK',
'00C08F' => 'MATSUSHITA',
'00C090' => 'PRAIM',
'00C091' => 'JABIL',
'00C092' => 'MENNEN',
'00C093' => 'ALTA',
'00C094' => 'VMX',
'00C095' => 'ZNYX',
'00C096' => 'TAMURA',
'00C097' => 'ARCHIPEL',
'00C098' => 'CHUNTEX',
'00C099' => 'YOSHIKI',
'00C09A' => 'PHOTONICS',
'00C09B' => 'RELIANCE',
'00C09C' => 'TOA',
'00C09D' => 'DISTRIBUTED',
'00C09E' => 'CACHE',
'00C09F' => 'QUANTA',
'00C0A0' => 'ADVANCE',
'00C0A1' => 'TOKYO',
'00C0A2' => 'INTERMEDIUM',
'00C0A3' => 'DUAL',
'00C0A4' => 'UNIGRAF',
'00C0A5' => 'DICKENS',
'00C0A6' => 'EXICOM',
'00C0A7' => 'SEEL',
'00C0A8' => 'GVC',
'00C0A9' => 'BARRON',
'00C0AA' => 'SILICON',
'00C0AB' => 'JUPITER',
'00C0AC' => 'GAMBIT',
'00C0AD' => 'COMPUTER',
'00C0AE' => 'TOWERCOM',
'00C0AF' => 'TEKLOGIX',
'00C0B0' => 'GCC',
'00C0B1' => 'GENIUS',
'00C0B2' => 'NORAND',
'00C0B3' => 'COMSTAT',
'00C0B4' => 'MYSON',
'00C0B5' => 'CORPORATE',
'00C0B6' => 'MERIDIAN',
'00C0B7' => 'AMERICAN',
'00C0B8' => 'FRASER-S',
'00C0B9' => 'FUNK',
'00C0BA' => 'NETVANTAGE',
'00C0BB' => 'FORVAL',
'00C0BC' => 'TELECOM',
'00C0BD' => 'INEX',
'00C0BE' => 'ALCATEL',
'00C0BF' => 'TECHNOLOGY',
'00C0C0' => 'SHORE',
'00C0C1' => 'QUAD/GRAPHICS',
'00C0C2' => 'INFINITE',
'00C0C3' => 'ACUSON',
'00C0C4' => 'COMPUTER',
'00C0C5' => 'SID',
'00C0C6' => 'PERSONAL',
'00C0C7' => 'SPARKTRUM',
'00C0C8' => 'MICRO',
'00C0C9' => 'BAILEY',
'00C0CA' => 'ALFA',
'00C0CB' => 'CONTROL',
'00C0CC' => 'TELESCIENCES',
'00C0CD' => 'COMELTA',
'00C0CE' => 'CEI',
'00C0CF' => 'IMATRAN',
'00C0D0' => 'RATOC',
'00C0D1' => 'COMTREE',
'00C0D2' => 'SYNTELLECT',
'00C0D3' => 'OLYMPUS',
'00C0D4' => 'AXON',
'00C0D5' => 'QUANCOM',
'00C0D6' => 'J1',
'00C0D7' => 'TAIWAN',
'00C0D8' => 'UNIVERSAL',
'00C0D9' => 'QUINTE',
'00C0DA' => 'NICE',
'00C0DB' => 'IPC',
'00C0DC' => 'EOS',
'00C0DD' => 'QLOGIC',
'00C0DE' => 'ZCOMM',
'00C0DF' => 'KYE',
'00C0E0' => 'DSC',
'00C0E1' => 'SONIC',
'00C0E2' => 'CALCOMP',
'00C0E3' => 'OSITECH',
'00C0E4' => 'LANDIS',
'00C0E5' => 'GESPAC',
'00C0E6' => 'TXPORT',
'00C0E7' => 'FIBERDATA',
'00C0E8' => 'PLEXCOM',
'00C0E9' => 'OAK',
'00C0EA' => 'ARRAY',
'00C0EB' => 'SEH',
'00C0EC' => 'DAUPHIN',
'00C0ED' => 'US',
'00C0EE' => 'KYOCERA',
'00C0EF' => 'ABIT',
'00C0F0' => 'KINGSTON',
'00C0F1' => 'SHINKO',
'00C0F2' => 'TRANSITION',
'00C0F3' => 'NETWORK',
'00C0F4' => 'INTERLINK',
'00C0F5' => 'METACOMP',
'00C0F6' => 'CELAN',
'00C0F7' => 'ENGAGE',
'00C0F8' => 'ABOUT',
'00C0F9' => 'HARRIS',
'00C0FA' => 'CANARY',
'00C0FB' => 'ADVANCED',
'00C0FC' => 'ASDG',
'00C0FD' => 'PROSUM',
'00C0FE' => 'APTEC',
'00C0FF' => 'BOX',
'00CBBD' => 'CAMBRIDGE',
'00CF1C' => 'COMMUNICATION',
'00D000' => 'FERRAN',
'00D001' => 'VST',
'00D002' => 'DITECH',
'00D003' => 'COMDA',
'00D004' => 'PENTACOM',
'00D005' => 'ZHS',
'00D006' => 'CISCO',
'00D007' => 'MIC',
'00D008' => 'MACTELL',
'00D009' => 'HSING',
'00D00A' => 'LANACCESS',
'00D00B' => 'RHK',
'00D00C' => 'SNIJDER',
'00D00D' => 'MICROMERITICS',
'00D00E' => 'PLURIS',
'00D00F' => 'SPEECH',
'00D010' => 'CONVERGENT',
'00D011' => 'PRISM',
'00D012' => 'GATEWORKS',
'00D013' => 'PRIMEX',
'00D014' => 'ROOT',
'00D015' => 'UNIVEX',
'00D016' => 'SCM',
'00D017' => 'SYNTECH',
'00D018' => 'QWES',
'00D019' => 'DAINIPPON',
'00D01A' => 'URMET',
'00D01B' => 'MIMAKI',
'00D01C' => 'SBS',
'00D01D' => 'FURUNO',
'00D01E' => 'PINGTEL',
'00D01F' => 'CTAM',
'00D020' => 'AIM',
'00D021' => 'REGENT',
'00D022' => 'INCREDIBLE',
'00D023' => 'INFORTREND',
'00D024' => 'COGNEX',
'00D025' => 'XROSSTECH',
'00D026' => 'HIRSCHMANN',
'00D027' => 'APPLIED',
'00D028' => 'OMNEON',
'00D029' => 'WAKEFERN',
'00D02A' => 'FLEXION',
'00D02B' => 'JETCELL',
'00D02C' => 'CAMPBELL',
'00D02D' => 'ADEMCO',
'00D02E' => 'COMMUNICATION',
'00D02F' => 'VLSI',
'00D030' => 'SAFETRAN',
'00D031' => 'INDUSTRIAL',
'00D032' => 'YANO',
'00D033' => 'DALIAN',
'00D034' => 'ORMEC',
'00D035' => 'BEHAVIOR',
'00D036' => 'TECHNOLOGY',
'00D037' => 'PHILIPS-DVS-LO',
'00D038' => 'FIVEMERE',
'00D039' => 'UTILICOM',
'00D03A' => 'ZONEWORX',
'00D03B' => 'VISION',
'00D03C' => 'VIEO',
'00D03D' => 'PRIVATE',
'00D03E' => 'ROCKETCHIPS',
'00D03F' => 'AMERICAN',
'00D040' => 'SYSMATE',
'00D041' => 'AMIGO',
'00D042' => 'MAHLO',
'00D043' => 'ZONAL',
'00D044' => 'ALIDIAN',
'00D045' => 'KVASER',
'00D046' => 'DOLBY',
'00D047' => 'XN',
'00D048' => 'ECTON',
'00D049' => 'IMPRESSTEK',
'00D04A' => 'PRESENCE',
'00D04B' => 'LA',
'00D04C' => 'EUROTEL',
'00D04D' => 'DIV',
'00D04E' => 'LOGIBAG',
'00D04F' => 'BITRONICS',
'00D050' => 'ISKRATEL',
'00D051' => 'O2',
'00D052' => 'ASCEND',
'00D053' => 'CONNECTED',
'00D054' => 'SAS',
'00D055' => 'KATHREIN-WERKE',
'00D056' => 'SOMAT',
'00D057' => 'ULTRAK',
'00D058' => 'CISCO',
'00D059' => 'AMBIT',
'00D05A' => 'SYMBIONICS',
'00D05B' => 'ACROLOOP',
'00D05C' => 'TECHNOTREND',
'00D05D' => 'INTELLIWORXX',
'00D05E' => 'STRATABEAM',
'00D05F' => 'VALCOM',
'00D060' => 'PANASONIC',
'00D061' => 'TREMON',
'00D062' => 'DIGIGRAM',
'00D063' => 'CISCO',
'00D064' => 'MULTITEL',
'00D065' => 'TOKO',
'00D066' => 'WINTRISS',
'00D067' => 'CAMPIO',
'00D068' => 'IWILL',
'00D069' => 'TECHNOLOGIC',
'00D06A' => 'LINKUP',
'00D06B' => 'SR',
'00D06C' => 'SHAREWAVE',
'00D06D' => 'ACRISON',
'00D06E' => 'TRENDVIEW',
'00D06F' => 'KMC',
'00D070' => 'LONG',
'00D071' => 'ECHELON',
'00D072' => 'BROADLOGIC',
'00D073' => 'ACN',
'00D074' => 'TAQUA',
'00D075' => 'ALARIS',
'00D076' => 'MERRILL',
'00D077' => 'LUCENT',
'00D078' => 'ELTEX',
'00D079' => 'CISCO',
'00D07A' => 'AMAQUEST',
'00D07B' => 'COMCAM',
'00D07C' => 'KOYO',
'00D07D' => 'COSINE',
'00D07E' => 'KEYCORP',
'00D07F' => 'STRATEGY',
'00D080' => 'EXABYTE',
'00D081' => 'REAL',
'00D082' => 'IOWAVE',
'00D083' => 'INVERTEX',
'00D084' => 'NEXCOMM',
'00D085' => 'OTIS',
'00D086' => 'FOVEON',
'00D087' => 'MICROFIRST',
'00D088' => 'MAINSAIL',
'00D089' => 'DYNACOLOR',
'00D08A' => 'PHOTRON',
'00D08B' => 'ADVA',
'00D08C' => 'GENOA',
'00D08D' => 'PHOENIX',
'00D08E' => 'NVISION',
'00D08F' => 'ARDENT',
'00D090' => 'CISCO',
'00D091' => 'SMARTSAN',
'00D092' => 'GLENAYRE',
'00D093' => 'TQ',
'00D094' => 'TIMELINE',
'00D095' => 'XYLAN',
'00D096' => '3COM',
'00D097' => 'CISCO',
'00D098' => 'PHOTON',
'00D099' => 'ELCARD',
'00D09A' => 'FILANET',
'00D09B' => 'SPECTEL',
'00D09C' => 'KAPADIA',
'00D09D' => 'VERIS',
'00D09E' => '2WIRE',
'00D09F' => 'NOVTEK',
'00D0A0' => 'MIPS',
'00D0A1' => 'OSKAR',
'00D0A2' => 'INTEGRATED',
'00D0A3' => 'VOCAL',
'00D0A4' => 'ALANTRO',
'00D0A5' => 'AMERICAN',
'00D0A6' => 'LANBIRD',
'00D0A7' => 'TOKYO',
'00D0A8' => 'NETWORK',
'00D0A9' => 'SHINANO',
'00D0AA' => 'CHASE',
'00D0AB' => 'DELTAKABEL',
'00D0AC' => 'GRAYSON',
'00D0AD' => 'TL',
'00D0AE' => 'ORESIS',
'00D0AF' => 'CUTLER-HAMMER',
'00D0B0' => 'BITSWITCH',
'00D0B1' => 'OMEGA',
'00D0B2' => 'XIOTECH',
'00D0B3' => 'DRS',
'00D0B4' => 'KATSUJIMA',
'00D0B5' => 'DOTCOM',
'00D0B6' => 'CRESCENT',
'00D0B7' => 'INTEL',
'00D0B8' => 'IOMEGA',
'00D0B9' => 'MICROTEK',
'00D0BA' => 'CISCO',
'00D0BB' => 'CISCO',
'00D0BC' => 'CISCO',
'00D0BD' => 'SICAN',
'00D0BE' => 'EMUTEC',
'00D0BF' => 'PIVOTAL',
'00D0C0' => 'CISCO',
'00D0C1' => 'HARMONIC',
'00D0C2' => 'BALTHAZAR',
'00D0C3' => 'VIVID',
'00D0C4' => 'TERATECH',
'00D0C5' => 'COMPUTATIONAL',
'00D0C6' => 'THOMAS',
'00D0C7' => 'PATHWAY',
'00D0C8' => 'I/O',
'00D0C9' => 'ADVANTECH',
'00D0CA' => 'INTRINSYC',
'00D0CB' => 'DASAN',
'00D0CC' => 'TECHNOLOGIES',
'00D0CD' => 'ATAN',
'00D0CE' => 'ASYST',
'00D0CF' => 'MORETON',
'00D0D0' => 'ZHONGXING',
'00D0D1' => 'SIROCCO',
'00D0D2' => 'EPILOG',
'00D0D3' => 'CISCO',
'00D0D4' => 'V-BITS',
'00D0D5' => 'GRUNDIG',
'00D0D6' => 'AETHRA',
'00D0D7' => 'B2C2',
'00D0D8' => '3COM',
'00D0D9' => 'DEDICATED',
'00D0DA' => 'TAICOM',
'00D0DB' => 'MCQUAY',
'00D0DC' => 'MODULAR',
'00D0DD' => 'SUNRISE',
'00D0DE' => 'PHILIPS',
'00D0DF' => 'KUZUMI',
'00D0E0' => 'DOOIN',
'00D0E1' => 'AVIONITEK',
'00D0E2' => 'MRT',
'00D0E3' => 'ELE-CHEM',
'00D0E4' => 'CISCO',
'00D0E5' => 'SOLIDUM',
'00D0E6' => 'IBOND',
'00D0E7' => 'VCON',
'00D0E8' => 'MAC',
'00D0E9' => 'ADVANTAGE',
'00D0EA' => 'NEXTONE',
'00D0EB' => 'LIGHTERA',
'00D0EC' => 'NAKAYO',
'00D0ED' => 'XIOX',
'00D0EE' => 'DICTAPHONE',
'00D0EF' => 'IGT',
'00D0F0' => 'CONVISION',
'00D0F1' => 'SEGA',
'00D0F2' => 'MONTEREY',
'00D0F3' => 'SOLARI',
'00D0F4' => 'CARINTHIAN',
'00D0F5' => 'ORANGE',
'00D0F6' => 'ALCATEL',
'00D0F7' => 'NEXT',
'00D0F8' => 'FUJIAN',
'00D0F9' => 'ACUTE',
'00D0FA' => 'RACAL',
'00D0FB' => 'TEK',
'00D0FC' => 'GRANITE',
'00D0FD' => 'OPTIMA',
'00D0FE' => 'ASTRAL',
'00D0FF' => 'CISCO',
'00DD00' => 'UNGERMANN-BASS',
'00DD01' => 'UNGERMANN-BASS',
'00DD02' => 'UNGERMANN-BASS',
'00DD03' => 'UNGERMANN-BASS',
'00DD04' => 'UNGERMANN-BASS',
'00DD05' => 'UNGERMANN-BASS',
'00DD06' => 'UNGERMANN-BASS',
'00DD07' => 'UNGERMANN-BASS',
'00DD08' => 'UNGERMANN-BASS',
'00DD09' => 'UNGERMANN-BASS',
'00DD0A' => 'UNGERMANN-BASS',
'00DD0B' => 'UNGERMANN-BASS',
'00DD0C' => 'UNGERMANN-BASS',
'00DD0D' => 'UNGERMANN-BASS',
'00DD0E' => 'UNGERMANN-BASS',
'00DD0F' => 'UNGERMANN-BASS',
'00E000' => 'FUJITSU',
'00E001' => 'STRAND',
'00E002' => 'CROSSROADS',
'00E003' => 'NOKIA',
'00E004' => 'PMC-SIERRA',
'00E005' => 'TECHNICAL',
'00E006' => 'SILICON',
'00E007' => 'NETWORK',
'00E008' => 'AMAZING',
'00E009' => 'MARATHON',
'00E00A' => 'DIBA',
'00E00B' => 'ROOFTOP',
'00E00C' => 'MOTOROLA',
'00E00D' => 'RADIANT',
'00E00E' => 'AVALON',
'00E00F' => 'SHANGHAI',
'00E010' => 'HESS',
'00E011' => 'UNIDEN',
'00E012' => 'PLUTO',
'00E013' => 'EASTERN',
'00E014' => 'CISCO',
'00E015' => 'HEIWA',
'00E016' => 'RAPID-CITY',
'00E017' => 'EXXACT',
'00E018' => 'ASUSTEK',
'00E019' => 'ING',
'00E01A' => 'COMTEC',
'00E01B' => 'SPHERE',
'00E01C' => 'MOBILITY',
'00E01D' => 'WEBTV',
'00E01E' => 'CISCO',
'00E01F' => 'AVIDIA',
'00E020' => 'TECNOMEN',
'00E021' => 'FREEGATE',
'00E022' => 'MEDIALIGHT',
'00E023' => 'TELRAD',
'00E024' => 'GADZOOX',
'00E025' => 'DIT',
'00E026' => 'EASTMAN',
'00E027' => 'DUX',
'00E028' => 'APTIX',
'00E029' => 'SMC',
'00E02A' => 'TANDBERG',
'00E02B' => 'EXTREME',
'00E02C' => 'AST',
'00E02D' => 'INNOMEDIALOGIC',
'00E02E' => 'SPC',
'00E02F' => 'MCNS',
'00E030' => 'MELITA',
'00E031' => 'HAGIWARA',
'00E032' => 'MISYS',
'00E033' => 'E',
'00E034' => 'CISCO',
'00E035' => 'LOUGHBOROUGH',
'00E036' => 'PIONEER',
'00E037' => 'CENTURY',
'00E038' => 'PROXIMA',
'00E039' => 'PARADYNE',
'00E03A' => 'CABLETRON',
'00E03B' => 'PROMINET',
'00E03C' => 'ADVANSYS',
'00E03D' => 'FOCON',
'00E03E' => 'ALFATECH',
'00E03F' => 'JATON',
'00E040' => 'DESKSTATION',
'00E041' => 'CSPI',
'00E042' => 'PACOM',
'00E043' => 'VITALCOM',
'00E044' => 'LSICS',
'00E045' => 'TOUCHWAVE',
'00E046' => 'BENTLY',
'00E047' => 'INFOCUS',
'00E048' => 'SDL',
'00E049' => 'MICROWI',
'00E04A' => 'ENHANCED',
'00E04B' => 'JUMP',
'00E04C' => 'REALTEK',
'00E04D' => 'INTERNET',
'00E04E' => 'SANYO',
'00E04F' => 'CISCO',
'00E050' => 'EXECUTONE',
'00E051' => 'TALX',
'00E052' => 'FOUNDRY',
'00E053' => 'CELLPORT',
'00E054' => 'KODAI',
'00E055' => 'INGENIERIA',
'00E056' => 'HOLONTECH',
'00E057' => 'HAN',
'00E058' => 'PHASE',
'00E059' => 'CONTROLLED',
'00E05A' => 'GALEA',
'00E05B' => 'WEST',
'00E05C' => 'MATSUSHITA',
'00E05D' => 'UNITEC',
'00E05E' => 'JAPAN',
'00E05F' => 'E-NET',
'00E060' => 'SHERWOOD',
'00E061' => 'EDGEPOINT',
'00E062' => 'HOST',
'00E063' => 'CABLETRON',
'00E064' => 'SAMSUNG',
'00E065' => 'OPTICAL',
'00E066' => 'PROMAX',
'00E067' => 'EAC',
'00E068' => 'MERRIMAC',
'00E069' => 'JAYCOR',
'00E06A' => 'KAPSCH',
'00E06B' => 'W&G',
'00E06C' => 'BALTIMORE',
'00E06D' => 'COMPUWARE',
'00E06E' => 'FAR',
'00E06F' => 'TERAYON',
'00E070' => 'DH',
'00E071' => 'EPIS',
'00E072' => 'LYNK',
'00E073' => 'NATIONAL',
'00E074' => 'TIERNAN',
'00E075' => 'ATLAS',
'00E076' => 'DEVELOPMENT',
'00E077' => 'WEBGEAR',
'00E078' => 'BERKELEY',
'00E079' => 'A',
'00E07A' => 'MIKRODIDAKT',
'00E07B' => 'BAY',
'00E07C' => 'METTLER-TOLEDO',
'00E07D' => 'ENCORE',
'00E07E' => 'WALT',
'00E07F' => 'LOGISTISTEM',
'00E080' => 'CONTROL',
'00E081' => 'TYAN',
'00E082' => 'ANERMA',
'00E083' => 'JATO',
'00E084' => 'COMPULITE',
'00E085' => 'GLOBAL',
'00E086' => 'CYBEX',
'00E087' => 'LECROY',
'00E088' => 'LTX',
'00E089' => 'ION',
'00E08A' => 'GEC',
'00E08B' => 'QLOGIC',
'00E08C' => 'NEOPARADIGM',
'00E08D' => 'PRESSURE',
'00E08E' => 'UTSTARCOM',
'00E08F' => 'CISCO',
'00E090' => 'BECKMAN',
'00E091' => 'LG',
'00E092' => 'ADMTEK',
'00E093' => 'ACKFIN',
'00E094' => 'OSAI',
'00E095' => 'ADVANCED-VISION',
'00E096' => 'SHIMADZU',
'00E097' => 'CARRIER',
'00E098' => 'TREND',
'00E099' => 'SAMSON',
'00E09A' => 'POSITRON',
'00E09B' => 'ENGAGE',
'00E09C' => 'MII',
'00E09D' => 'SARNOFF',
'00E09E' => 'QUANTUM',
'00E09F' => 'PIXEL',
'00E0A0' => 'WILTRON',
'00E0A1' => 'HIMA',
'00E0A2' => 'MICROSLATE',
'00E0A3' => 'CISCO',
'00E0A4' => 'ESAOTE',
'00E0A5' => 'COMCORE',
'00E0A6' => 'TELOGY',
'00E0A7' => 'IPC',
'00E0A8' => 'SAT',
'00E0A9' => 'FUNAI',
'00E0AA' => 'ELECTROSONIC',
'00E0AB' => 'DIMAT',
'00E0AC' => 'MIDSCO',
'00E0AD' => 'EES',
'00E0AE' => 'XAQTI',
'00E0AF' => 'GENERAL',
'00E0B0' => 'CISCO',
'00E0B1' => 'PACKET',
'00E0B2' => 'TELMAX',
'00E0B3' => 'ETHERWAN',
'00E0B4' => 'TECHNO',
'00E0B5' => 'ARDENT',
'00E0B6' => 'ENTRADA',
'00E0B7' => 'PI',
'00E0B8' => 'AMD',
'00E0B9' => 'BYAS',
'00E0BA' => 'BERGHOF',
'00E0BB' => 'NBX',
'00E0BC' => 'SYMON',
'00E0BD' => 'INTERFACE',
'00E0BE' => 'GENROCO',
'00E0BF' => 'TORRENT',
'00E0C0' => 'SEIWA',
'00E0C1' => 'MEMOREX',
'00E0C2' => 'NECSY',
'00E0C3' => 'SAKAI',
'00E0C4' => 'HORNER',
'00E0C5' => 'BCOM',
'00E0C6' => 'LINK2IT',
'00E0C7' => 'EUROTECH',
'00E0C8' => 'VIRTUAL',
'00E0C9' => 'AUTOMATEDLOGIC',
'00E0CA' => 'BEST',
'00E0CB' => 'RESON',
'00E0CC' => 'HERO',
'00E0CD' => 'SENSIS',
'00E0CE' => 'ARN',
'00E0CF' => 'INTEGRATED',
'00E0D0' => 'NETSPEED',
'00E0D1' => 'TELSIS',
'00E0D2' => 'VERSANET',
'00E0D3' => 'DATENTECHNIK',
'00E0D4' => 'EXCELLENT',
'00E0D5' => 'ARCXEL',
'00E0D6' => 'COMPUTER',
'00E0D7' => 'SUNSHINE',
'00E0D8' => 'LANBIT',
'00E0D9' => 'TAZMO',
'00E0DA' => 'ASSURED',
'00E0DB' => 'VIAVIDEO',
'00E0DC' => 'NEXWARE',
'00E0DD' => 'ZENITH',
'00E0DE' => 'DATAX',
'00E0DF' => 'KE',
'00E0E0' => 'SI',
'00E0E1' => 'G2',
'00E0E2' => 'INNOVA',
'00E0E3' => 'SK-ELEKTRONIK',
'00E0E4' => 'FANUC',
'00E0E5' => 'CINCO',
'00E0E6' => 'INCAA',
'00E0E7' => 'RAYTHEON',
'00E0E8' => 'GRETACODER',
'00E0E9' => 'DATA',
'00E0EA' => 'INNOVAT',
'00E0EB' => 'DIGICOM',
'00E0EC' => 'CELESTICA',
'00E0ED' => 'NEW',
'00E0EE' => 'MAREL',
'00E0EF' => 'DIONEX',
'00E0F0' => 'ABLER',
'00E0F1' => 'THAT',
'00E0F2' => 'ARLOTTO',
'00E0F3' => 'WEBSPRINT',
'00E0F4' => 'INSIDE',
'00E0F5' => 'TELES',
'00E0F6' => 'DECISION',
'00E0F7' => 'CISCO',
'00E0F8' => 'DIANA',
'00E0F9' => 'CISCO',
'00E0FA' => 'TRL',
'00E0FB' => 'LEIGHTRONIX',
'00E0FC' => 'HUAWEI',
'00E0FD' => 'A-TREND',
'00E0FE' => 'CISCO',
'00E0FF' => 'SECURITY',
'00E6D3' => 'NIXDORF',
'020406' => 'BBN',
'020701' => 'INTERLAN',
'021C7C' => 'PERQ',
'026060' => '3COM',
'026086' => 'SATELCOM',
'02608C' => '3COM',
'027001' => 'RACAL-DATACOM',
'0270B0' => 'M/A-COM',
'0270B3' => 'DATA',
'029D8E' => 'CARDIAC',
'02A0C9' => 'INTEL',
'02AA3C' => 'OLIVETTI',
'02BB01' => 'OCTOTHORPE',
'02C08C' => '3COM',
'02CF1C' => 'COMMUNICATION',
'02CF1F' => 'CMC',
'02E03B' => 'PROMINET',
'02E6D3' => 'BTI',
'040AE0' => 'XMIT',
'048845' => 'BAY',
'04E0C4' => 'TRIUMPH-ADLER',
'080001' => 'COMPUTER',
'080002' => '3COM',
'080003' => 'ACC',
'080004' => 'CROMEMCO',
'080005' => 'SYMBOLICS',
'080006' => 'SIEMENS',
'080007' => 'APPLE',
'080008' => 'BBN',
'080009' => 'HP',
'08000A' => 'NESTAR',
'08000B' => 'UNISYS',
'08000C' => 'MIKLYN',
'08000D' => 'ICL',
'08000E' => 'NCR',
'08000F' => 'SMC',
'080010' => 'AT&T',
'080011' => 'TEKTRNIX',
'080012' => 'BELL',
'080013' => 'EXXON',
'080014' => 'EXCELAN',
'080015' => 'STC',
'080016' => 'BARRISTER',
'080017' => 'NATIONAL',
'080018' => 'PIRELLI',
'080019' => 'GENERAL',
'08001A' => 'DATAGENL',
'08001B' => 'DATAGENL',
'08001C' => 'KDD-KOKUSAI',
'08001D' => 'ABLE',
'08001E' => 'APOLLO',
'08001F' => 'SHARP',
'080020' => 'SUN',
'080021' => '3M',
'080022' => 'NBI',
'080023' => 'MATSUSHITA',
'080024' => '10NET',
'080025' => 'CDC',
'080026' => 'NORSK',
'080027' => 'PCS',
'080028' => 'TI',
'080029' => 'MEGATEK',
'08002A' => 'MOSAIC',
'08002B' => 'DEC',
'08002C' => 'BRITTON',
'08002D' => 'LAN-TEC',
'08002E' => 'METAPHOR',
'08002F' => 'PRIME',
'080030' => 'CERN',
'080031' => 'LITTLE',
'080032' => 'TIGAN',
'080033' => 'BAUSCH',
'080034' => 'FILENET',
'080035' => 'MICROFIVE',
'080036' => 'INTERGRAPH',
'080037' => 'FUJI',
'080038' => 'BULL',
'080039' => 'SPIDER',
'08003A' => 'ORCATECH',
'08003B' => 'TORUS',
'08003C' => 'SCHLUMBERGER',
'08003D' => 'CADNETIX',
'08003E' => 'MOTOROLA',
'08003F' => 'FRED',
'080040' => 'FERRANTI',
'080041' => 'DCA',
'080042' => 'JAPAN',
'080043' => 'PIXEL',
'080044' => 'DSI',
'080046' => 'SONY',
'080047' => 'SEQUENT',
'080048' => 'EUROTHERM',
'080049' => 'UNIVATION',
'08004A' => 'BANYAN',
'08004B' => 'PLANNING',
'08004C' => 'ENCORE',
'08004D' => 'CORVUS',
'08004E' => 'BICC',
'08004F' => 'CYGNET',
'080050' => 'DAISY',
'080051' => 'EXPERDATA',
'080052' => 'INSYSTEC',
'080053' => 'MIDDLE',
'080055' => 'STANFORD',
'080056' => 'STANFORD',
'080057' => 'EVANS',
'080059' => 'A/S',
'08005A' => 'IBM',
'08005B' => 'VTA',
'08005C' => 'FOUR',
'08005D' => 'GOULD',
'08005E' => 'COUNTERPOINT',
'08005F' => 'SABER',
'080060' => 'INDUSTRIAL',
'080061' => 'JAROGATE',
'080062' => 'GENERAL',
'080063' => 'PLESSEY',
'080064' => 'AUTOPHON',
'080065' => 'GENRAD',
'080066' => 'AGFA',
'080067' => 'COMDESIGN',
'080068' => 'RIDGE',
'080069' => 'SGI',
'08006A' => 'ATTST',
'08006B' => 'ACCEL',
'08006C' => 'SUNTEK',
'08006D' => 'WHITECHAPEL',
'08006E' => 'EXCELAN',
'08006F' => 'PHILIPS',
'080070' => 'MITSUBISHI',
'080071' => 'MATRA',
'080072' => 'XEROX',
'080073' => 'TECMAR',
'080074' => 'CASIO',
'080075' => 'DDE',
'080076' => 'PC',
'080077' => 'TSL',
'080078' => 'ACCELL',
'080079' => 'SGI',
'08007A' => 'INDATA',
'08007B' => 'SANYO',
'08007C' => 'VITALINK',
'08007E' => 'AMALGAMATED',
'08007F' => 'CARNEGIE-MELLON',
'080080' => 'XIOS',
'080081' => 'CROSFIELD',
'080082' => 'VERITAS',
'080083' => 'SEIKO',
'080084' => 'TOMEN',
'080085' => 'ELXSI',
'080086' => 'IMAGEN/QMS',
'080087' => 'XYPLEX',
'080088' => 'MCDATA',
'080089' => 'KINETIX',
'08008A' => 'PERFORMANCE',
'08008B' => 'PYRAMID',
'08008C' => 'NETWORK',
'08008D' => 'XYVISION',
'08008E' => 'TANDEM',
'08008F' => 'CHIPCOM',
'080090' => 'RETIX',
'081443' => 'UNIBRAIN',
'08BBCC' => 'AK-NORD',
'09006A' => 'AT&T',
'100000' => 'PRIVATE',
'10005A' => 'IBM',
'100090' => 'HP',
'1000D4' => 'DEC',
'1000E0' => 'APPLE',
'1000E8' => 'NATIONAL',
'1100AA' => 'IEEE',
'2E2E2E' => 'LAA',
'3C0000' => '3COM',
'400003' => 'NET',
'444553' => 'MICRSOFT',
'444649' => 'DFI',
'475443' => 'GTC',
'484453' => 'HDS',
'484C00' => 'NETWORK',
'4854E8' => 'WINBOND',
'4C424C' => 'INFORMATION',
'525400' => 'REALTEK',
'52544C' => 'NOVELL',
'5254AB' => 'REALTEK',
'565857' => 'ACULAB',
'800010' => 'AT&T',
'80AD00' => 'CNET',
'A06A00' => 'VERILINK',
'AA0000' => 'DEC',
'AA0001' => 'DEC',
'AA0002' => 'DEC',
'AA0003' => 'DEC',
'AA0004' => 'DEC',
'ACDE48' => 'IEEE',
'C00000' => 'WESTERN',
'E20C0F' => 'KINGSTON',
'EC1000' => 'ENANCE',
'EC1000' => 'ENANCE');
return ($manufactor{$input});
};

