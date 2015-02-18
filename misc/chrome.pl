 #! c:\perl\bin\perl.exe  
 #---------------------------------------------------------------------  
 # chrome.pl  
 # Parse the History sqlite database to TLN format  
 #  
 # Ref: http://www.forensicswiki.org/wiki/Google_Chrome  
 # Ref: http://computer-forensics.sans.org/blog/2010/01/21/google-chrome-forensics/  
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
	
	my @database = $content =~ /C:.*\/History/g;
	my @unique = do { my %seen; grep { !$seen{$_}++ } @database };
 
	foreach(@unique)
	{
		if (-f $_) {
		
			$path = reverse $_;
			$path  = substr ($path, index($path, '/'), length($path)-1);
			$path = reverse $path;
			$path =~ s/\//\\/g;
		
			if (defined( $config{downloads})){
				$filename = $path."History";
		
				if (-e $filename) {
					getDownloads($path);
				} 
			
			}
			
			getHistory($path);
		}
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
	
	
	my $db = DBI->connect("dbi:SQLite:dbname=$_[0]\\History","","") || die( "Unable to connect to database\n" );  
	my $all = $db->selectall_arrayref("SELECT ((visits.visit_time/1000000)-11644473600), urls.url, urls.title FROM urls, visits WHERE urls.id = visits.url;");  
	foreach my $row (@$all) {  
		my ($date,$url,$title) = @$row;  
		print $date."|CHROME|".$config{system}."|".$url."\n";  
	}  
	$db->disconnect;  
}
 
 sub getDownloads { 
	
	
	my $db = DBI->connect("dbi:SQLite:dbname=$_[0]\\History","","") || die( "Unable to connect to database\n" );  
	my $all = $db->selectall_arrayref("SELECT full_path,url,start_time, received_bytes, total_bytes FROM downloads;");  
	foreach my $row (@$all) {  
		my ($exe,$source,$date,$currBytes,$maxBytes) = @$row;  
		print $date."|CHROME|".$config{system}."|".$config{user}."|dl:".$exe." src:".$source." cB:".$currBytes." mB:".$maxBytes."\n";  
	}
	$db->disconnect;  
  }
 
 sub _syntax {  
 print<< "EOT";  
 chrome.pl  
 [option]  
 Parse Chrome History & downloads (Win2000, XP, 2003, Win7)  
  -p path..................path to History file to parse  
  -d downloads.............parse downloads.sqlite file in same directory
  -s Systemname............add systemname to appropriate field in tln file  
  -u user..................add username to appropriate field in tln file
  -a auto..................automatically find places.sqlite within tsk output
  -h Help..................Help (print this information)  
 Ex: C:\\> chrome.pl -d -p C:\\Users\\%username%\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\ -s %COMPUTERNAME% -u %USERNAME%> events.txt 
 Ex: C:\\> chrome.pl -d -a C:\\tsk-bodyfile.txt -s %COMPUTERNAME%
 **All times printed as GMT/UTC    
EOT
 }   