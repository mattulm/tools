#!/usr/bin/perl 

#
# LiLith: http forms scanner/injector
# by <michael@code.ae>   
#
#                      "She has come from the shadows of the dreamworld"
#                                                     -inkubus sukkubus
#
# Not  the usual http scanner , this will look for variable and 'try' to
# exploit it, or at least report it. Works much as a spider, but reports
# and exploits any <form>'s of <input> on websites.
#
# Copyright (c) 2003-2005 Michael Hendrickx <michael@code.ae>
#
# Thank you to all people who believe in me.
#
# Changes: - got rid of many many false positives (thats good)
#          - when SQL error is found, it now goes onto next var
#          - improved (i hope) scanning engine
#          - (anti) coldfusion support
#          - better cookie handling and cookie tampering
#          - omitted perl HTML::Form limitation
#	         - better verbose output
#          - extensive logging
#          - detects directory indexing
#          - recursive dynamic URL dissection
#          - cleaned up this pasta code
#
# TODO: Gtk user interface (if wanted, please let me know)
#
# "She has come from the shadows of the dreamworld"
#                                -inkubus sukkubus
#
# This tool was written to improve security, please do not abuse it.  If
# you require more information or latest version, please read the README
# file that  came with  this  release  or point your favorite browser to 
# http://michael.code.ae/.
#
# Thank you,
#   Michael
#
#
# This program is free software;you can redistribute it and/or modify it
# under the terms of the GNU  General Public License as published by the 
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.
#
# Disclaimer: This software comes as is,without any expressed or implied
# warranty. Use it at your own risk, the author can't be hold liable for
# any damage that might be done	to your or any other system as an effect
# of using this software.				    
#
# For more information, please see the GNU General Public License.
#
# You should have received a copy of the GNU GeneralPublic License along
# with this program; if not, write to the Free Software Foundation Inc., 
# 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.


use strict;
use Class::ISA;
use LWP::UserAgent;
use URI::URL;
use HTML::Form;
use HTML::LinkExtor;
use HTTP::Cookies;
use Getopt::Std;
use Encode;

my (@links, @visited_links, @dynvisurls, @agents, @illegal, @dirs, $page);
my (%L, %options);

$L{logfile} = "";	# name of logfile
$L{host} = "";		# target host
$L{proxy} = "";		# optional proxy
$L{agent} = "";		# user agent
$L{request} = "";	# host.dir
$L{dir} = "";		# starting directory
$L{v} = 0;		# verbose level
$L{serverinfo} = 0;	# server OS flag
$L{timeout} = 60;	# http timeout, seconds
$L{cred_in} = "";	# basic auth
$L{cred_pw} = "";	# basic passwd
$L{prox_in} = "";	# proxy auth
$L{prox_pw} = "";	# proxy passwd
$L{flag_poison} = 1;	# by default, inject poison
$L{flag_all} = 0;	# display all requests / release
$L{flag_all_poison} = 0;# try all poison, even when error is found
$L{flag_index} = 1;     # look for indexable (browsable) directories
$L{flag_strip} = 1;	# give stripped ocutput
$L{pause} = 0;		# pause between requests
$L{cookies} = 1;	# use cookies
$L{jar} = "";		# the cookie jar
$L{l_url} = "http://michael.code.ae/";
$L{time_now} = 0;	# timestamps
$L{dots} = 0;		# dots :)
$L{num_found} = 0;

my %ver = (         # just to keep track of changes
	    maj=>0,         # major
	    min=>6,         # minor
	    rev=>"a"        # revision
	  );  

$L{agent} = "LiLith v".$ver{maj}.".".$ver{min}.$ver{rev};  # -a arg

@agents = (
	    "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.5) Gecko/20031027",
	    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
	    "Lynx/2.8.4rel.1 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.7d",
	    "curl/7.12.1 (i686-pc-linux-gnu) libcurl 7.12.0 (OpenSSL 0.9.7d) zlib/1.2.1.1"
	  );

@illegal = ("'", "\"", "\|", "\%", "\(", "\$",";", ",", "&", " ", "[", "*", "?", 
	"", "/../../test", "0", "123", 
	
	# normal values, which a form might need to be required
	"john", 		# name / password / city / country
	"j0hn007",      	# password / geeky name 
	"john\@doe.org", 	# e-mail
	"4000000000000002",	# credit card number
	"12/06",		# expiry date
	"12/2006",		# longer form
	);

# --- main() ---------------------------------------

    print "LiLith v".$ver{maj}.".".$ver{min}.$ver{rev}.
	  " : http forms scanner/injector\nby michael\@code.ae (".$L{l_url}.")\n\n";

    usage() if $#ARGV < 0;
    getopts('ASIcivsh:p:u:d:a:T:f:g',\%options);
    chkopts(\%options);

    $L{host} = $ARGV[$#ARGV];
    
    if($L{host} eq ""){ print "Error: host argument missing.\n"; usage(); }

    sanitize();
    display_info();

    # if logfile is specified
    if($L{logfile} ne ""){
	$L{time_now} = gmtime;    
        log_to_file("Starting Lilith v".$ver{maj}.".".$ver{min}.".".$ver{rev}." (".$L{l_url}.") at ".$L{time_now}."\n");
    }
    
    empty_cookie_jar();
    if($L{serverinfo} eq 0){ get_server_version(); }

    # start spidering 
    spider($L{request});
    #done spidering
    
    my $nvl = @visited_links;

    # tempy
    if($L{cookies} and $L{jar}){ print $L{jar}->as_string; }
    # cookie tampering as well

    # indexable directories
    if($L{flag_index} eq 1){
	if($L{v} eq 1){
    	    print " [i] Looking for indexable (browsable) directories:\n";
	    log_to_file("Looking for indexable (browsable) directories:");
	}

	# chop all filenames from @visited_links, keep the directories, lose the dup's	
	foreach my $tmp_link (@visited_links){ add_indexdir($tmp_link); }
	my $ndirs = @dirs;
	if($L{v} eq 1){ print "  +-> checking ".$ndirs." directories.\n"; }
	log_to_file("checking ".$ndirs." directories");
	
	foreach my $tmp_dir (@dirs) {indexable($tmp_dir);}
    }
    
# lilith is done  

    print "\nLiLith v".$ver{maj}.".".$ver{min}.$ver{rev}." completed.\n";# at ".$time_now."\n";
    print $nvl." hyperlink";
    if($nvl eq 1){ print " was"; } else { print "s were"; } 
    print " followed, ".$L{num_found}." error";
    print "s" if $L{num_found} gt 1;
    print " found.\n";

    if($L{logfile} ne ""){
        log_to_file("Visited links (".$nvl."):");
        log_to_file(join("\n  ", @visited_links));
    }

exit;

# --------------------------------------------------
# called functions of the program.  

# usage() : prints how to use it and exits
sub usage {
    print "usage: $0 [options] <host>\n";
    print "with following options:\n";
    print "  -d <dir>         : <dir> (or file) where to start [default: /]\n";
    print "  -a <agent>       : agent to use (-a 0 for list) [\"".$L{agent}."\"]\n";
    print "  -u <user:pass>   : basic authentication credentials\n";
    print "  -p <proxy>       : proxy server (proxy:port)\n";
    print "  -U <user:pass>   : proxy authentication credentials\n";
    print "  -T <delay>       : wait <delay> seconds between requests [".$L{pause}."s]\n";
    print "  -f <file>        : if defined, extensive logging is done to <file>\n";
    print "  -c               : ignore cookies presented by <host>\n";
    print "  -g               : try more poison, even when error is found\n";
# TODO:
#   print "  -C               : do not perform cookie value tampering\n";
    print "  -s               : do not attempt to guess server version\n";
    print "  -S               : do not strip host and directory from output\n";
    print "  -I               : don't try to get directory listings\n";
    print "  -i               : don't inject any poison\n";
    print "  -A               : print all return codes (lots of data)\n";
    print "  -v               : verbosity\n";
    print "\n";
    exit 1;
}


# chkopts() : check options (getopt) and parses
sub chkopts {
    my $opt = shift; 
    if(defined $opt->{a}){ 
        if($opt->{a} eq "0"){
            print "Available agents:\n";
            for(my $i=0;$i<@agents;$i++){ print " + ".($i+1).": ".$agents[$i]."\n"; }
            print " + default: ".$L{agent}."\n\n"; exit(0);
        }
        # get the element-1 from the @agents list
        if($opt->{a}=~/[1-9]{1}/){ 
            if($agents[($opt->{a})-1] ne ""){ $L{agent} = $agents[($opt->{a})-1]; }
        }
        if($opt->{a}=~/[a-z]/){ 
            if($agents[($opt->{a})-1] ne ""){ $L{agent} = $opt->{a}; }
        }
	
    }        
    if(defined $opt->{p}){ $L{proxy} = $opt->{p}; }
    if(defined $opt->{v}){ $L{v}++; }
    if(defined $opt->{u}){($L{cred_un}, $L{cred_pw}) = split /:/, $opt->{u}; }
    if(defined $opt->{U}){($L{prox_un}, $L{prox_pw}) = split /:/, $opt->{U}; }
    if(defined $opt->{d}){ $L{dir} = $opt->{d}; }
    if(defined $opt->{s}){ $L{serverinfo} = 1; }
    if(defined $opt->{i}){ $L{flag_poison} = 0; }
    if(defined $opt->{g}){ $L{flag_all_poison} = 1; }
    if(defined $opt->{S}){ $L{flag_strip} = 0; }
    if(defined $opt->{I}){ $L{flag_index} = 0; }
    if(defined $opt->{A}){ $L{flag_all} = 1; }    
    if(defined $opt->{T}){ $L{pause} = $opt->{T}; }
    if(defined $opt->{f}){ $L{logfile} = $opt->{f}; }
    if(defined $opt->{c}){ $L{cookies} = 0; }
}

# sanitize() :sanity checks for proxy, target, ...
sub sanitize {
    if($L{host} !~ /http\:\/\//){ $L{host} = "http://".$L{host}; }
    if($L{host} =~ /http\:\/\/.*\/.+/){
        $L{dir} = $L{host};
        $L{dir} =~ s/http\:\/\/.*\/(.*)/\/$1/g;
        $L{host} =~ s/$L{dir}//g;
    }
    if($L{proxy}){ if($L{proxy} !~ /http\:\/\//){ $L{proxy} = "http://".$L{proxy}; }}
    if($L{prox_un} && !$L{proxy}){ print " [e] How can you set proxy credentials without\n".
				   "     specifying a proxy?\n"; exit; }
    if(substr($L{dir},0,1) ne "/"){ $L{dir} = "/".$L{dir}; }
    $L{request} = $L{host}.$L{dir};
}


# get_server_version() : try to determine what server we're dealing with
sub get_server_version(){
    
    my ($res, @probes, $final, %cnt, $max);
    $max = 0;
    
    my $req = HTTP::Request->new(GET =>$L{request});
    $res = lilith_req($req);

    if($res->as_string =~ /500 Can\'t connect to .* \(connect: Connection refused\)/){
	print "\n + Error: Connection refused\n\n";
	exit;
    }

    push @probes, $res->headers->server;
    sleep $L{pause};

    # head request
    $req = HTTP::Request->new(HEAD =>$L{request});
    $res = lilith_req($req);
    
    push @probes, $res->headers->server;
    sleep $L{pause};
    
    # get non existing file
    $req = HTTP::Request->new(GET =>$L{request}."/banner$$.jpg");
    $res = lilith_req($req);
    push @probes, $res->headers->server;
    
    foreach my $a (@probes){ $cnt{$a}++; }
    foreach my $b(keys %cnt){
        if($cnt{$b}>$max){ $max = $cnt{$b}; $final = $b; }
    }
    
    print " + server:        ";
    if($final){
	print $final."\n";
	log_to_file(" + server: ".$final);
    } else {
	print "could not be determined\n";
	log_to_file(" + server could not be determined");
    }
    print "\n";
}

# display_info() : print some info information prior to the scan    
sub display_info {
    $L{time_now} = localtime;    
    $L{host}      && print " + target:        ".$L{host}."\n";
    $L{proxy}     && print " + proxy:         ".$L{proxy}."\n";
    $L{cred_un}   && print " + cred auth:     ".$L{cred_un}.":".$L{cred_pw}."\n";
    $L{dir}       && print " + directory:     ".$L{dir}."\n";
    $L{pause}     && print " + delay:         ".$L{pause}." seconds\n";
    $L{logfile}   && print " + logfile:       ".$L{logfile}."\n";
                     print " + started:       ".$L{time_now}."\n";		     
}

# misc_error(): see if the response contains a misc error. (file not found, some SQL errors)
sub misc_error {
    my $response   = shift;		# the page that is given back -html code-
    my $poison 	   = shift;		# the character that triggered this
    my $inputname = shift;		# the script that caused this chaos

    if($response->content =~ /.*Error\: java.sql.SQLException\: Unable to connect to any hosts due to exception\: java.net.ConnectException\: Connection refused\: connect.*/){
	# if($response->content =~ /.*ORA-[0-9].*, line.*/){ $temp = "Oracle"; }
        print "  +--[!] Misc error: SQL server connection refused?: ".strip($response->base)." (".$inputname." = \"".$poison."\")\n";
	log_to_file("Misc error SQL server connection refused: ".$response->base." (".$inputname." = \"".$poison."\")");
	return 1;
    }

}


# path_disclosure($response, $scriptname): see if the $response from $scriptname contains real paths
sub path_disclosure {
    my $response   = shift;		# the page that is given back -html code-
    my $poison 	   = shift;		# the character that triggered this
    my $inputname = shift;		# the script that caused this chaos
    my $temp;				# temporary copy
    $temp = $response->content;
    
    # Fatal error: Cannot re-assign $this in /home/sites/.../x.php on line 123
    if($temp =~ s/.*Fatal error: .* in (.*) on line.*/$1/g){
	# if just scriptname is given, relative to webroot
	if($temp ne $response->base){ print "  +--[!] path disclosure: ".strip($response->base)." = ".$temp.")\n\n"; } 
	else { print "  +--[!] Misc error: ".strip($response->base)."; (".$inputname."=".$poison.")\n\n"; }	
    } # s/Fatal error../g

    $temp = $response->content;
    # Warning: in_array(): Wrong datatype for second argument in /usr/../htdocs/includes/inc.php on line 123
    if($temp =~ s/.*Warning:.* in (.*) on line.*/$1/g){
	# if just scriptname is given, relative to webroot
	if($temp ne $response->base){ print "  +--[!] path disclosure: ".strip($response->base)." = ".$temp.")\n"; } 
	else { print "  +--[!] Misc error: ".strip($response->base)."; (".$inputname."=".$poison.")\n\n"; }	
    } # s/Warning: ../g

    $temp = $response->content;    
    # The Error Occurred in <b>C:\Inetpub\wwwroot\test\news.cfc: line 70</b><br>
    if($temp =~ s/.*The Error Occurred in <b>(.*): line.*<\/b><br>.*/$1/g){
	# if just scriptname is given, relative to webroot
	if($temp ne $response->base){ print "  +--[!] path disclosure: ".strip($response->base)." = ".$temp.")\n"; } 
	else { print "  +--[!] Misc error (ColdFusion): ".strip($response->base)."; (".$inputname."=".$poison.")\n\n"; }	
    } # s/The Error Occ../g
   
    $temp = $response->content;    
    # The error occurred while.. Template: D:\inetpub\wwwroot\test\test.cfm
    if($temp =~ s/.*The error occurred while processing.*Template: (.*) <br>.*/$1/g){
	# if just scriptname is given, relative to webroot
	if($temp ne $response->base){ print "  +--[!] path disclosure: ".strip(response->base)." = ".$temp.")\n"; } 
	else { print "  +--[!] Misc error (ColdFusion): ".strip($response->base)."; (".$inputname."=".$poison.")\n\n"; }	
    } # s/The Error Occ../g

    $temp = $response->content;    
    # The error occurred while processing an element with a general identifier of (CFQUERY), 
    # in the template file e:\inetpub\wwwroot\test.cfm.
    if($temp =~ s/.*The error occurred while processing.*in the template file (.*)\.<\/p><br>.*/$1/g){
	# if just scriptname is given, relative to webroot
	if($temp ne $response->base){ print "  +--[!] path disclosure: ".strip($response->base)." = ".$temp.")\n"; } 
	else { print "  +--[!] Misc error (ColdFusion): ".strip($response->base)."; (".$inputname."=".$poison.")\n\n"; }	
    }
}

# sql_injection(): detects sql errors in $response
sub sql_injection {
    my $response   = shift;		# the page that is given back -html code- (HTTP::Response)
    my $poison 	   = shift;		# the character that triggered this
    my $inputname = shift;		# the script that caused this chaos
    my $temp;				# temporary copy

    $temp = $response->content;

    if( $temp  =~ /.*Microsoft OLE DB Provider for .*/ or 
        $temp  =~ /not a valid MySQL/ or
	$temp =~ /.*java.sql.SQLException\: Syntax error or access violation\,  message from server\:.*/
    ){
        print "  +--[!] SQL injection: ".strip($response->base)." (".$inputname." = \"".$poison."\")\n";
	log_to_file("SQL Injection: ".$response->base." (".$inputname." = \"".$poison."\")");
	return 1;
    }
    return 0;
}

# add_indexdir(): add potential indexable directory to @dirs
sub add_indexdir {
    my $arg = shift;
    my @tmp = split /\//, $arg;
    my $tmp = @tmp;
    pop @tmp unless($L{host} =~ /$tmp[$tmp-1]/);
    my $dir = join('/', @tmp)."/";
    return unless($dir =~ /$L{host}/);
    foreach my $vdir (@dirs){ return if($vdir eq $dir); }  
    push @dirs, $dir;
}

# indexable(): forgot a default document? Is $_ a browsable directory?
sub indexable {
    my $url = shift; 
    my $response = lilith_req(HTTP::Request->new(GET=>$url));
    return if(!defined $response);
    if($L{v} > 0){ print "  +--[d] ".$response->code.": ".strip($response->base); }

    # Apache
    if($response->content =~ /<H1>Index of \/.*<\/H1>/){
	# extra checking (<a.*>last modified</a>, ...)
	print "\n  +--[!] Conf error: browsable directory: ".strip($response->base)."\n\n";
	return;
    }
    
    # Tomcat
    if($response->content =~ /<title>Directory Listing For \/.*<\/title>/ and
       $response->content =~ /<body><h1>Directory Listing For \/.*<\/h1>/)
    {
	print "\n  +--[!] Conf error: browsable directory: ".strip($response->base)."\n\n";
	return;    
    }
    
    my $host = $L{host};
    my $dir = $url;
    $host =~ s/http\:\/\///g;
    $dir =~ s/$host//g;
    
    # iis
    if($response->content =~ /<body><H1>$host - $dir/){
	print "\n  +--[!] Conf error: browsable directory: ".strip($response->base)."\n\n";
	return;    
    }

    # if not returned yet, it's not vuln
    if($L{v} > 0){ print " ..failed\n"; }
}

#lilith_req(): makes the given HTTP::Request, returns HTTP::Response
sub lilith_req{
    my $request = shift;    
    
    # so we won't spider the web
    return unless $request->uri =~ /$L{host}/;
    
    # go back to the homepage?
    return unless $request->uri =~ /$L{dir}/;

    # draw_dots();

    # give all replies
    # if($L{v} eq 1){
    if($L{flag_all} eq 1){
        print " [r] ".($request->method)." ".strip($request->uri)."\n";            
    }    

    my $ua = LWP::UserAgent->new(timeout=>$L{timeout},agent=>$L{agent}); 
    if($L{proxy}){ $ua->proxy('http', $L{proxy}); } 
    if($L{cookies}){ $ua->cookie_jar($L{jar}); } 
    if($L{proxy} and $L{prox_un}){ $request->proxy_authorization_basic($L{prox_un}, $L{prox_pw}); }
    if($L{cred_un}){ $request->auhtorization($L{cred_un}, $L{cred_pw}); }
    my $response = $ua->request($request);
    if($response->code eq "302"){
	my $new = $response->headers->header('Location');
	$new =~ s/#.*//g;
	my $tmp = $new; #backup
	
	$new =~ s/\?.*//g;

        foreach my $vlink (@visited_links){ if($vlink eq $new){ $new = ""; } }  
        if($new ne ""){ foreach my $alink (@links){ if($alink eq $new){ $new = ""; }}}
        if($new ne ""){ push @links, $new; } else { return; }
	if($L{v}>0){ print " [i] ".strip($tmp)."\n"; }
    	if($new ne "" and $tmp =~ /\?/){ dynurl($tmp); }
    }
    return $response;    
}

# strip(): 
sub strip {
    my $s = shift; 
    return $s unless $L{flag_strip} eq 1;
    $s =~ s/$L{host}//g;
    ($s =~ s/$L{dir}//g) unless $L{dir} eq '/'; 
    return ($s eq "" ? "/" : $s);
}

# empty_cookie_jar() : makes an empty cookie jar
sub empty_cookie_jar {
    return if $L{cookies};
    use HTTP::Cookies;
    $L{jar} = HTTP::Cookies->new({});
}

   
#log_to_file(): logs $msg to $L{logfile}
sub log_to_file {
    my $msg = shift;
    if($L{logfile} eq ""){ return; }
    open(FILE, "+>>", $L{logfile}) || die " [e] Error: cannot open ".$L{logfile}."\n";
    print FILE $msg."\n";
    close(FILE);
}

sub draw_dots {
    my $range = 72; # 80px screen
    if($L{dots} eq 0){
	print " [.] .";
    }
    elsif($L{dots} eq $range){
	print ".\n";
	$L{dots} = 0;
    }
    else
    {
	print ".";
    }
    $L{dots}++;
}

# look_for_error() : checks if request made any error
sub look_for_error {
    my $response = shift;	# HTML page that's returned
    my $poison = shift;		# poison that was injected
    my $inputname = shift;	# name of script/cgi/...
    my $request = shift;	# (optional) HTTP::Request object
    
    $request = "" unless defined $request;
    return if !($response->code);

    # if multiple fields are filled in, the $poison and $inputname are empty
    #if($poison eq "" and $inputname eq ""){
#	print "DEBUG: ".$request->content."\n";
#    	print " [e] ".strip($response->base)." gave HTTP:".$response->code." with \"".$poison.
#    	      "\" in ".$inputname."\n";   

    	# SQL injection?
#    	return 1 if(sql_injection($response, $poison, $inputname) eq 1);

    	# full path disclosure 
#    	return 1 if(path_disclosure($response, $poison, $inputname) eq 1);
    
    	# misc errors
#    	return 1 if(misc_error($response, $poison, $inputname) eq 1);
                 
#    }

    if($L{v} eq 0){
	if($response->code ne 302 and # moved
	   $response->code ne 403 and # forbidden
	   $response->code ne 404 and # file not found
	   $response->code ne 405 and # method not allowed
	   $response->code ne 200)
	   {
	    # dots
	 #  print "\n"; $L{dots} = 0;
	   
    	    print " [e] ".strip($response->base)." gave HTTP:".$response->code." with \"".$poison.
    		  "\" in ".$inputname."\n";                    
        } # $response->code
    } # verbose

    # give all replies
    # if($L{v} eq 1){
    if($L{flag_all} eq 1){
        print " [R] ".strip($response->base)." gave HTTP:".$response->code." with \"".$poison.
        "\" in ".$inputname."\n";            
    }

    # log complete request & reply to file    
    if($L{logfile} ne ""){
        log_to_file("HTTP ".$response->code.": (".$response->base.") ".$inputname." set to ".$poison.":");
        log_to_file("----------------------------------------------------------------------");
        my $time_now = localtime;
        log_to_file($time_now);
        log_to_file("HTTP Request: ".$request->as_string);
        log_to_file("\n----------------------------------------------------------------------");
        log_to_file("HTTP Reply: ".$response->content);
        log_to_file("\n----------------------------------------------------------------------\n");
    }

   
    # DEBUG print "\n\nHTTP Request: ".$request->as_string."\n";
 
    # SQL injection?
    #return 1 if(sql_injection($response, $poison, $inputname) eq 1);
    if(sql_injection($response, $poison, $inputname) eq 1){
    	# DEBUG print "DEBUG: ";
	if($poison eq "" and $inputname eq ""){
	    # we have multiple fields
	    print join("\n  +-", split('&', $response->content));
    	} else { 
	    # DEBUG print "RETURNED\n";
	    return 1; 
        } # single poison
    }

    # full path disclosure 
    return 1 if(path_disclosure($response, $poison, $inputname) eq 1);
    
    # misc errors
    return 1 if(misc_error($response, $poison, $inputname) eq 1);

    # this function has way too many false positives.
    # if($response->code ne 200 and ($response->content =~ /error/ or $response->content =~ /Error/)){
    #   printf "  +--[!] Misc error: ".$response->base." (".$inputname.")\n\n";
    #	return;
    #}    
    
    return 0;

}

# dynurl() : if $_ is a dynamic url- dissect and poisonate
sub dynurl {
    my $tmpurl = shift;
    my (@tmpuv, @tmpvc, %url_vars, $va);
    my ($reqobj, $inj_resp); # our request
                
    # get variables and values in the url
    @tmpuv = split /\?/, $tmpurl;
    @tmpvc = split /\&/, $tmpuv[1]; # 0 is the url     
    
    # a?var1=val1&var2=val2: dissect every variable and its value
    foreach $va (@tmpvc){ my($a,$b) = split(/=/,$va); $url_vars{$a} = $b; }

    my $nurl_vars = %url_vars;
    # if verbosity, print the variables
    if($L{v}>0){
        print "     +-[i] found $nurl_vars input"; 
        if($nurl_vars ne 1){ print "s"; }            
        if($nurl_vars eq 0){ print ".\n"; return } else { print ":\n"; }
        foreach my $var (keys %url_vars){ 
            print "     +--[i] ".$var." (\"".$url_vars{$var}."\")\n"; 
        }
        print "\n";                           
    }
    
    # if we don't want to insert poison, don't be naughty
    return if($L{flag_poison} eq 0);
    
    # check if we had this one already
    foreach my $vlink (@dynvisurls){ if($vlink eq $tmpuv[0]){ return; }} 

    my @vars = values %url_vars;
    my @tvars = keys %url_vars;
    my $np = @illegal;
    my $found = 0; # 0 not found, 1 = found

    # try 'poison' in each field, leave the rest blank
    for(my $o=0; $o<@vars; $o++){ 
	foreach my $p (@illegal){
	    return if $found eq 1;
	    my $str = $tmpuv[0]."?";
    	    $str .= $tvars[$o]."=".$p."&"; 
    	    $reqobj = HTTP::Request->new(GET=>$str);
    	    $inj_resp = lilith_req($reqobj);
	    $found = look_for_error($inj_resp, $p, $tvars[$o], $reqobj) && !$L{flag_all_poison};
            $L{num_found}++ if $found eq 1;		
    	    sleep $L{pause};						
	}
    }
    
    # callback for dynamic urls.  recursive
    sub cb_dyn {
	return if ($found eq 1);
	my $var = shift;
	if ($var >= @vars){ return; }
	
	cb_dyn($var+1);

	if($vars[$var] eq $np-1){ $vars[$var] = 0; return; }				    
	$vars[$var]++;					    

	my $str = $tmpuv[0]."?";
	for(my $o=0; $o<@vars; $o++){ $str .= $tvars[$o]."=".$illegal[$vars[$o]]."&"; }
	chop $str;
	
        $reqobj = HTTP::Request->new(GET=>$str);
    	$inj_resp = lilith_req($reqobj);

	$found = look_for_error($inj_resp, $illegal[$vars[0]], $tvars[0], $reqobj) && !$L{flag_all_poison};		
        $L{num_found}++ if $found gt 0;		

        sleep $L{pause};					
	cb_dyn($var);
    }
								    
    cb_dyn(0);    
    
    push @dynvisurls, $tmpuv[0];
}


# getforms() : get the <form> tags, dissects and injects some data
sub getforms{
    my $buffer = shift;				# buffer: html code - big chunk
    my @forms = HTML::Form->parse($buffer);    	# @array of all <form> from $buffer
    my $nforms = @forms; 			# number of <form>'s

    if($L{v}>0){ 
	print "  +-[i] found ".$nforms." form"; 
        if($nforms ne 1){ print "s"; }
        if($nforms eq 0){ print ".\n"; return } else { print ":\n"; }
    }
    
    for(my $i=0;$i<$nforms;$i++){    
        sleep $L{pause};
        if($L{v}>0){ print "  +--[i] $i : ".$forms[$i]->method." - ".strip($forms[$i]->action)."\n"; }
        if($forms[$i]->action =~ /\?/){ return dynurl($forms[$i]->action); }
        
        # see the different inputs
        my @inputs = $forms[$i]->inputs;
        my $ninputs = @inputs;
        
        if($L{v}>0){ # if verbosity, print all inputs
            print "     +-[i] found $ninputs input"; 
            if($ninputs ne 1){ print "s"; }            
            if($ninputs eq 0){ print ".\n"; return } else { print ":\n"; }
            for(my $j=0;$j<$ninputs;$j++){  
		print "     +--[i] ".($inputs[$j]->type)."\t: ".
		      $inputs[$j]->name." (\"".$inputs[$j]->value."\")\n"; 
	    }
            print "\n";                           
        }        
        # if there is a submit button, inject poison
        if($L{flag_poison} eq 1){
            my $clickcont = $forms[$i]->click;
            if(length $clickcont->content){  # it is submittable
		my ($found, $found2);
		$found2 = 0;
                for(my $j=0;$j<$ninputs;$j++){ # per each control seperatly
		    $found = 0;
		    $clickcont = "";
            	    foreach my $poison (@illegal){
			if($found eq 0 and length $inputs[$j]->name gt 0){
                    	    sleep $L{pause};
			    my $request = $forms[$i]->click;
			    my $str = $inputs[$j]->name."=".$poison;
			    $request->header("Content-Length", (length $str));
			    $request->content($str);			    
			    my $response = lilith_req($request);
			    next if(!$response);
			    $found2 += $found = look_for_error($response, 
				            	    $poison, 
						    $inputs[$j]->name ne "" ? $inputs[$j]->name : "<no name>", 
						    $request) && !$L{flag_all_poison};			
                            $L{num_found}++ if $found gt 0;
                    	    } # if found
                    	} # $poison
                } # for(j<$ninputs)
		return if ($found2 gt 0 and !$L{flag_all_poison});
		
    		my @inputs = $forms[$i]->inputs;	# perl acts a little bit funny
		my @ivals = @inputs; # input values - the table we'll change
		my $nivals = @ivals; # number of input values
		my $nillegal = @illegal;

		my $count = 0;

		for(my $u = 0; $u < $nivals; $u++){ $ivals[$u] = 0; }
		my $f = $found;
		my @fms = @forms;

		# recursive function for POST
	        sub cb_frm {
		    my $pos = shift;
			
		    $found = $f; # heh?  $found seems to become 1 if we enter this function
		    $f = $found; # for some obscure reason.
		    @forms = @fms; # total perl weirdness
		    ++$count;	
		    if($ivals[$pos] ne ""){
                        for(my $ill = 0; $ill < $nillegal; $ill++){
                            if($ivals[$pos] eq $illegal[$ill+1]){
			        $ivals[$pos] = $illegal[$ill];
				# make request
				my $str = "";
		                for(my $o=0; $o<$nivals; $o++)
                        	{ 
                            	    $str .= $inputs[$o]->name."=".$ivals[$o]."&"; 
                        	}
                                chop $str;		
				print "DEBUG: ".$str."\n";

	                        my $request = $forms[$i]->click;
       		                $request->header("Content-Length", length $str);
                        	$request->content($str);
				my $response = lilith_req($request);
				$found = look_for_error($response, "", "", $request) && !$L{flag_all_poison};
				$f = $found; # for some obscure reason.
                		$L{num_found}++ if $found eq 1;
    				sleep $L{pause};		
				return if $found ne 0;			

			        # break; - we will just make $ill = nillegal, so the for() will stop
				$ill = $nillegal;
			    } 
                        } 
			for(my $y = 0; $y < $nivals; $y++){
			    if($ivals[$y] == $illegal[$nillegal-1]){
			        $ivals[$y] = $illegal[0];
			    }
			    else
			    {
		    	    print "DEBUG: cb_frm(".$y.")\n";
			    cb_frm($y);
			    # break; - there's no break - we'll just up $y
			    $y = $nivals;
			    } 
			}                            
                    }
		    else
		    {
			$ivals[$pos] = $illegal[0];
			my $str = "";
                        for(my $o=0; $o<$nivals; $o++)
                        { 
                            $str .= $inputs[$o]->name."=".$ivals[$o]."&"; 
                        }
                        chop $str;
                        print "DEBUG: ".$str."\n";
                        my $request = $forms[$i]->click;
                        $request->header("Content-Length", length $str);
                        $request->content($str);
			my $response = lilith_req($request);
			$found = look_for_error($response, "", "", $request) && !$L{flag_all_poison};
			$f = $found; # for some obscure reason.
                	$L{num_found}++ if $found eq 1;
			return if $found ne 0;
    			sleep $L{pause};					
                    }
		}
		
		my $possible = $nillegal ^ $nivals;	
		print "DEBUG: total possibilities: ".$possible."\n";			
	        while($count < $possible)
                {
		    print "DEBUG: cb_frm(0)\n";
                    cb_frm(0); 
                }
            } # $form->content (submit possible)
        } # $flag_poison        
    } # for @forms 
}

# cb :  links callback (HTML::LinkExtor) | check for duplicates
sub cb {
    my ($tag, %attr) = @_;
    my $ok = 0;
    if($tag ne "a" and $tag ne "frame"){ return; }
    
    # make absolute to eliminate /data/a.html != www.a.com/data/a.html    
    %attr = map { $_ = url($_, $page->base)->abs; } %attr;    
    foreach my $link (values %attr){        
        # leave out anchors (blah.html#top, blah.html#item2...)
        $link =~ s/#.*//g;
        foreach my $vlink (@visited_links){ if($vlink eq $link){ $link = ""; } }  
        if($link ne ""){ foreach my $alink (@links){ if($alink eq $link){ $link = ""; }}}
        if($link ne ""){ push @links, $link; }
    }        
}
    
# spider() : analyses the website, getting out links, getforms(),.. 
sub spider {
    my $request = shift;
    
    # here, the ua is needed, since we have a callback
    my $spider_ua = LWP::UserAgent->new(timeout=>$L{timeout},agent=>$L{agent});

    my $req_obj = HTTP::Request->new(GET=>$request);
    if($L{proxy}){ $spider_ua->proxy('http', $L{proxy}); }
    if($L{cookies}){ $spider_ua->cookie_jar($L{jar}); }        
    if($request =~ /\?/){ dynurl($request); }    
    $page = lilith_req($req_obj);
    shift @links;
    push @visited_links, $request;
    
    if(not defined $page){ return print " + Error getting $request\n"; }
    
    if($page->code == 401){
	# authentication needed
	if($L{cred_un} eq ""){
	    my $realm = $page->header("www-authenticate");
	    $realm =~ s/Basic//g;
	    $realm =~ s/realm=//g;
	    print " [e] Authentication needed: (realm: $realm)\n";
	    print "     Please set proper credentials\n";
	    return;
	} else { # creds filled in, but (probably) wrong ones
	    print " [e] Authentication failed (wrong username/password)\n";
	    return;
	}
    }
    
    if($page->code == 407){
	print " [e] Proxy authentication needed. Set proper credentials\n";
	return;
    }
                
    if($page->content eq ""){ 
        # some sites give false positives here
        unless($page->is_success){
            print " [e] error getting ".$request.": ".$page->status_line."\n";
            return; 
        }
    }
    
    # spider the page for forms
    if($L{v}>0){ print "\n [i] ".strip($request)."\n"; }
    
    getforms($page);
    
    # extract links and recursive call    
    my $parser = HTML::LinkExtor->new(\&cb);    
    sleep $L{pause};
    @links = map { $_ = url($_, $page->base)->abs; } @links;    
    @visited_links = map { $_ = url($_, $page->base)->abs; } @visited_links;    
    my $linres = $spider_ua->request(HTTP::Request->new(GET=>$request), sub {$parser->parse($_[0])});
    if($links[0]){ spider($links[0]); }
}

# </lilith>
