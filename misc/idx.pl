 #! c:\perl\bin\perl.exe  
 #---------------------------------------------------------------------  
 # idx.pl   
 # Parse .idx files with the Java cache to TLN format  
 #   
 #   
 # Version: 0.2 (BETA)   
 # Examples:   
 # 1335156604|JAVA|WORKSTATIONNAME|USERNAME|http://malicious_site.com.br/js/jar//fap4.jar?r=1051139  
 # 1347043129|JAVA|WORKSTATIONNAME|USERNAME|http://www.malicious_site.pro/P4fLBitJ-PxK2/yUA83mE  
 # 1347043127|JAVA|WORKSTATIONNAME|USERNAME|http://www.malicious_site.pro/SfLBitJ-PxK2/yUA83mE  
 #---------------------------------------------------------------------  
#perl2exe_include "Regexp/Common/URI.pm"
#perl2exe_include "Regexp/Common/URI/fax.pm"
#perl2exe_include "Regexp/Common/URI/file.pm"
#perl2exe_include "Regexp/Common/URI/ftp.pm"
#perl2exe_include "Regexp/Common/URI/gopher.pm"
#perl2exe_include "Regexp/Common/URI/http.pm"
#perl2exe_include "Regexp/Common/URI/pop.pm"
#perl2exe_include "Regexp/Common/URI/prospero.pm"
#perl2exe_include "Regexp/Common/URI/news.pm"
#perl2exe_include "Regexp/Common/URI/tel.pm"
#perl2exe_include "Regexp/Common/URI/telnet.pm"
#perl2exe_include "Regexp/Common/URI/tv.pm"
#perl2exe_include "Regexp/Common/URI/wais.pm"
 use DBI;  
 use strict;  
 use Getopt::Long;  
 use File::Find;  
 use Regexp::Common qw /URI/;  
 use Time::Local; 

 my %config = ();  
 Getopt::Long::Configure("prefix_pattern=(-|\/)");  
 GetOptions(\%config, qw(path|p=s system|s=s user|u=s help|?|h));  
 if ($config{help} || ! %config) {  
     _syntax();  
     exit 1;  
 }  
 die "You must enter a path.\n" unless ($config{path});  
 #die "File not found.\n" unless (-e $config{path} && -f $config{path});  
 my $path =$config{path};  
 my @files;  
 my $data;
 my $data = $_;  
 my $lines;
 my $arraysize = 0;
 my %months = ('Jan'=>'01','Feb'=>'02','Mar'=>'03','Apr'=>'04','May'=>'05','Jun'=>'06','Jul'=>'07','Aug'=>'08','Sep'=>'09','Oct'=>'10','Nov'=>'11','Dec'=>'12');  
 my $start_dir = $path;  
 find(  
   sub { push @files, $File::Find::name unless -d; },  
   $start_dir  
 );  
 for my $file (@files) {  
   my ($ext) = $file =~ /(\.[^.]+)$/;  
   if ($ext eq ".idx") {  
             $file =~ s/\\/\//g;  
			
			
            
			open( FILE, "< $file" ) or die "Can't open $file : $!";  
            
			
			while(<FILE>){  
				 $data .= $_;	 
			}
			
			
			my @timestamps = $data =~ m/[0-3][0-9] [a-zA-Z][a-z][a-z] [0-9][0-9][0-9][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9]/g;   
            my @url = $data =~ m/($RE{URI}{HTTP}{-scheme => qr(https?)})/g; 
            if($timestamps[1]){
				$timestamps[1] = getEpoch($timestamps[1]);  
				print $timestamps[1]."|JAVA|".$config{system}."|".$config{user}."|".$url[0]."\n";  
				$data = '';
            }
			
			close(FILE);
			
    }  
 }  
 sub getEpoch {  
     my $time = substr ( $_[0],index($_[0], ' ', 10)+1,length($_[0])-1);  
     my $date = substr ( $_[0],0,index($_[0], ' ', 10));  
     my ($hr,$min,$sec) = split(/:/,$time,3);  
     my ($dd,$mm,$yyyy) = split(/ /,$date,3);  
     $mm = $months{$mm};  
     $mm =~ s/^0//; 
     my $epoch = timegm($sec,$min,$hr, $dd,($mm)-1,$yyyy);  
     return $epoch;  
 }  
 sub _syntax {  
 print<< "EOT";  
 idx.pl  
 [option]  
 Parse Java cache IDX files (  
  -p path..................path to java cache  
  -s Systemname............add systemname to appropriate field in tln file  
  -u user..................add user (or SID) to appropriate field in tln file  
  -h ......................Help (print this information)  
 Ex: C:\\> idx.pl -p C:\\Documents and Settings\\userprofile\\Application Data\\Sun\\Java\\Deployment\\cache\\\ -s %COMPUTERNAME% -u %USERNAME% > events.txt  
 **All times printed as GMT/UTC  
 copyright 2012 Sploit  
EOT
}   