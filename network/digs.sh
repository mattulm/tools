#!/bin/bash
#
# Dig for the different types of flags we might want frmo a domain
#
#
# Make sure there is something there.
if [ "$1" = "" ]; then
    	echo "You need to supply a domain name!";
	exit;
fi

#
# OK, let's run the scans.

#
# Let's go with host first and do some stuff.
echo "Run the host command against our domain" 
echo "Run the host command against our domain" >> /home/$1.digs.list;
host $1 >> /home/$1.digs.list;
echo " " >> /home/$1.digs.list; sleep 4;
echo "Might as well try a domain transfer"
host -T AXFR $i >> /home/$1.digs.list;
echo " " >> /home/$1.digs.list;
echo " " >> /home/$1.digs.list;

#
# Let's do some digging.
for type in A AAAA CNAME CERT DLV DNSKEY IPSECKEY MX NS NSEC PTR SIG SOA SRV TXT; do
	echo "I am going to look for the following records: $type";
	echo "I am going to look for the following records: $type" >> /home/$1.digs.list;
	dig -t $type $1 | grep -A3 -i "answer section" | egrep -vi "(QUERY TIME|SERVER)" >> /home/$1.digs.list;
	echo " "; sleep 1; echo " " >> /home/$1.digs.list; 
	dig +nocmd +multiline +noall +answer any $1 >> /home/$1.digs.list;
	echo " "; sleep 1; echo " " >> /home/$1.digs.list;
	echo " "; sleep 1; echo " " >> /home/$1.digs.list;
done


#
# Print the output to the screen for analysis
echo "Let's look at our file now......"
cat /home/$1.digs.list;

#
# EOF
