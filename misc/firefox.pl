 #! c:\perl\bin\perl.exe  
 #---------------------------------------------------------------------  
 # firefox.pl  
 # Parse the firefox places.sqlite database to TLN format  
 #  
 # Ref: http://davidkoepi.wordpress.com/2010/11/27/firefoxforensics/  
 #  
 # Version: 0.2 (BETA)  
 #---------------------------------------------------------------------  
#perl2exe_include "DBD/SQLite.pm"
 use DBI;  
 use strict;  
 use Getopt::Long;  
 my %config = ();  
 Getopt::Long::Configure("prefix_pattern=(-|\/)");  
 GetOptions(\%config, qw(path|p=s system|s=s user|u=s downloads|d auto|a=s help|?|h));  
 if ($config{help} || ! %config) {  
     _syntax();  
     exit 1;  
 }  
 
 #my $path = ""; 
 #my $downloads=$config{downloads};
 my $path;
 my $content;
 my $filename;
 my @lines;
 my @unique;
 
 
 if (defined( $config{auto})){
	die "You must enter a path to tsk-bodyfile.\n" unless ($config{auto});  
	#die "File not found.\n" unless (-e $config{path} && -p $config{path});  
	
    open(FILE, "< $config{auto}" ) or die "Can't open $config{auto} : $!";  
	@lines = <FILE>;
	$content = join('', @lines);
	
	my @database = $content =~ /C:.*places.sqlite/g;
	my @unique = do { my %seen; grep { !$seen{$_}++ } @database };
 
	foreach(@unique)
	{
		$path = reverse $_;
		$path  = substr ($path, index($path, '/'), length($path)-1);
		$path = reverse $path;
		$path =~ s/\//\\/g;
		
		if (defined( $config{downloads})){
		$filename = $path."downloads.sqlite";
		
			if (-e $filename) {
				getDownloads($path);
			} 
			
		}
		print $path."\n";
		getHistory($path);
	}
 }
 else
 {
	
	die "You must enter a path.\n" unless ($config{path});  
	#die "File not found.\n" unless (-e $config{path} && -p $config{path});  
	$path = $config{path}; 
	#print $path;
	if (defined( $config{downloads})){
		getDownloads($config{path});
	}
	getHistory($config{path});
 }
 
 
 
 sub getHistory {
	
	my $db = DBI->connect("dbi:SQLite:dbname=$_[0]\\places.sqlite","","") || die( "Unable to connect to database\n" );  
	my $all = $db->selectall_arrayref("SELECT url,moz_places.last_visit_date/1000000 from moz_places order by moz_places.last_visit_date desc;");  
	foreach my $row (@$all) {  
		my ($url,$date) = @$row;  
		print $date."|FIREFOX|".$config{system}."|".$url."\n";  
	}
	$db->disconnect;  
 }
 
 sub getDownloads { 
	
	
	my $db = DBI->connect("dbi:SQLite:dbname=$_[0]\\downloads.sqlite","","") || die( "Unable to connect to database\n" );  
	my $all = $db->selectall_arrayref("SELECT name,source,moz_downloads.startTime/1000000, moz_downloads.currBytes, moz_downloads.maxBytes FROM moz_downloads;");  
	foreach my $row (@$all) {  
		my ($exe,$source,$date,$currBytes,$maxBytes) = @$row;  
		print $date."|FIREFOX|".$config{system}."|".$config{user}."|dl:".$exe." src:".$source." cB:".$currBytes." mB:".$maxBytes."\n";  
	}
	$db->disconnect;  
  }
 
 
 sub _syntax {  
 print<< "EOT";  
 firefox.pl  
 [option]  
 Parse Firefox History (places.sqlite) & downloads (Win2000, XP, 2003, Win7)  
  -p path..................path to places.sqllite file to parse 
  -d downloads.............parse downloads.sqlite file in same directory
  -s systemname............add systemname to appropriate field in tln file  
  -u user..................add username to appropriate field in tln file
  -a auto..................automatically find places.sqlite within tsk output
  -h Help..................Help (print this information)  
 Ex: C:\\> firefox.pl -d -f C:\\firefox\ -s %COMPUTERNAME% -u %USERNAME% > events.txt  
 Ex: C:\\> firefox.pl -d -a C:\\tsk-bodyfile.txt -s %COMPUTERNAME%
 **All times printed as GMT/UTC  
 copyright 2012 Sploit  
EOT
}  