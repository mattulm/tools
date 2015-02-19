#!/usr/bin/perl

# script that tests any blocking filters, based on email extensions
# by Michael Hendrickx <michael@scanit.be>

use strict;
use IO::Socket;

# if you need to change anything, do it here

my $mailserver = 	"mail.company.com";
my $smtp_port  = 	25;
my $sender     =        "test\@company.com";
my $recipient  = 	"administrator@company.com";

# a list of unwanted files (extensions only)

my @ext = qw(001 002 00A 386 3GR AA_ ACE ACM ADE ADP ADT APA APP ARC
             ARJ ASA ASD ASP AXA BAS BAT BIN BOA BZA CAB CBT CCA CDR
             CDX CGI CHM CLA CMD CNV COA COM CPA CPL CRT CSC CSS DAB
             DAT DEV DIF DLA DOT DQY DRV EEA EML EXA FDF FMT FOA FPH
             FPW GFA GIM GIX GMS GNA GWA GZA HDI HHT HLP HTA ICE ICS 
             IMA INF INI INS IQY ISN ISP ITS JSA LGP LIB LNK LZH M3U 
             MB0 MB1 MB2 MBA MBR MDA MHT MOD MPD MPT MRC MSA MSG MSI 
             MSM MSO MSP MST NAP NWS OBA OBD OBT OCA OCX OLA OLE OTM
             OVA PCD PCI PHP PIF PLG POT PPZ PRC PWZ QLB QPW QTC REG
             RMF RQY RTF SCR SCT SHA SHS SIS SKV SLK SMM SWF SYS TAR
             TAZ TBZ TDO TGZ TLB TSP UNP URL VBA VBS VWP VXD WBK WIZ 
             WPA WPC WPD WRI WRL WRZ WSA WSI XML XSL XTP XXA ZLA ZOM 
             ZZZ {AA );

# don't change anything below this line, or the script might do
# undesirable things. thanks.

my $mail;	# general buffer holding all data
my $comm_buffer;

make_mail($recipient, $sender);
#print $mail;
send_mail();

sub attach_file($){
	my $extension = shift;
	$mail .= 
	"\r\n".
	"--------------ABCDBLAHBLAHF00B4R\r\n". 
	"Content-Type: application/octet-stream;\r\n".
	"        name=\"test.".$extension."\"\r\n". 
	"Content-Transfer-Encoding: 7bit\r\n".
	"Content-Description: test.".$extension."\r\n".
	"Content-Disposition: attachment;\r\n". 
	"        filename=\"test.".$extension."\"\r\n\r\n".
	"this is a security test\r\n\r\n\r\n".
	#"--------------ABCDBLAHBLAHF00B4R--\r\n";
        print " + attached: test.$extension\n";
}

sub send_mail(){
	my $socket = IO::Socket::INET->new(PeerAddr=>$mailserver,
					   PeerPort=>$smtp_port,
					   Proto=>"tcp") || die "Connection refused";

	print "Sending mail...\n";
	recv $socket, $comm_buffer, 1024, 0;
	if($comm_buffer !~ "220"){ die "Not an smtp server"; }
	send $socket, "HELO mailserver\r\n", 0;
        $comm_buffer = "";        
	recv $socket, $comm_buffer, 1024, 0;
	if($comm_buffer !~ "250"){ die "HELO"; }
	send $socket, "MAIL FROM: $sender\r\n", 0;
        $comm_buffer = "";
	recv $socket, $comm_buffer, 1024, 0;
	if($comm_buffer !~ "250"){ die "Error in communication"; }
	send $socket, "RCPT TO: $recipient\r\n", 0;
        $comm_buffer = "";	
        recv $socket, $comm_buffer, 1024, 0;
	if($comm_buffer !~ "250"){ die "Error in communication"; }
	send $socket, "DATA\r\n", 0;
        $comm_buffer = "";
	recv $socket, $comm_buffer, 1024, 0;
	if($comm_buffer !~ "354"){ die "Error in communication"; }
	send $socket, $mail, 0;
        $comm_buffer = "";        
	recv $socket, $comm_buffer, 1024, 0;
	if($comm_buffer !~ "250"){ die "Error in communication"; }
	send $socket, "QUIT\r\n", 0;
        $comm_buffer = "";        
	recv $socket, $comm_buffer, 1024, 0;
	if($comm_buffer !~ "221"){ die "Error in communication"; }
        print "mail is sent\n";
}

sub make_mail($$){
	my $recipient = shift;
	my $sender = shift;
        my $i;

	$mail = 
	"From: \"Security test\" <$sender>\r\n".
	"To: \"$recipient\" <$recipient>\r\n".
	"Subject: Security test - attachments\r\n".
        "Mime-Version: 1.0\r\n".
	"Content-Type: multipart/mixed;\r\n".
	"        boundary=\"------------ABCDBLAHBLAHF00B4R\"\r\n".
	"\r\n".
	"This is a multi-part message in MIME format.\r\n".
	"--------------ABCDBLAHBLAHF00B4R\r\n".
	"Content-Type: text/plain;\r\n".
	"Content-Transfer-Encoding: quoted-printable\r\n\r\n".
        "This is a computer generated message, do not reply.\r\n".
	"Please check what attachments came through\r\n\r\n    --($sender)\r\n\r\n";
        
        for($i=0;length($ext[$i])>0;$i++){ attach_file($ext[$i]); }
       	$mail .= "--------------ABCDBLAHBLAHF00B4R--\r\n.\r\n";
}
