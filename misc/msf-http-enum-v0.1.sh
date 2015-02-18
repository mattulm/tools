#!/bin/bash

##use this script if you have files with http/s hosts

#    Copyright (C) [2009] [ m1k3@m1k3.at ]
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.


####INFOS:
#-i ... generate a file with IPs of HTTP hosts
# if you are using nmap with the option -v
# grep Discovered nmap-scan.txt | grep \ 80\/ | cut -d\  -f6 | sort -u > IPs-80.txt
#-s ... generate a file with IPs of HTTPs hosts
# if you are using nmap with the option -v
# grep Discovered nmap-scan.txt | grep \ 443\/ | cut -d\  -f6 | sort -u > IPs-443.txt
#-f ... generate a file with lines like the following:
#	https://111.111.111.111:1234
#	http://111.111.111.113:80
#	https://111.111.111.112:443
#	http://111.111.111.114:8080
# you can use all together ...


logfile=msf-httpenum-01.log
nlogfile=nikto-01.log
MSFCLI="/pentest/exploits/framework3/msfcli" 
MPATH="/"
NIKTO=1
NIKTOOPTS="-C all"
timeout=10	#nikto-timeout

if [ "$1" = "" ]; then
	echo "usage: ./$0 -i <IP-File> -s <IP-File-HTTPS> -f <IP-Port-File> -p <PATH> -o <outputdirectory>"
	exit
else
	while [ "$1" != "" ]; do
		case $1 in
			-i | --httpfile )	shift
						IP=$1
						;;
			-s | --httpsfile )	shift
						IPs=$1
						;;
			-f | --ipportfile )	shift
						IPp=$1
						;;
			-p | --path )		shift
						MPATH=$1
						;;
			-o | --outputdir )	shift
						dir=$1
		esac
		shift
	done
fi

if [ $dir ]; then
	mkdir $dir
	logfile=$dir/$logfile
	nlogfile=$dir/$nlogfile
fi

if [ -r $IP ]; then
	while read line
	do
		echo "===================================================================" | tee -a $logfile
		echo "auditing device: $line, HTTP" | tee -a $logfile
		echo "" | tee -a $logfile

		echo "auditing webserver version" | tee -a $logfile
		$MSFCLI auxiliary/scanner/http/version RHOSTS=$line THREADS=10 E | tee -a $logfile
		echo "" | tee -a $logfile
		echo "auditing webserver options" | tee -a $logfile
		$MSFCLI auxiliary/scanner/http/options RHOSTS=$line THREADS=10 E | tee -a $logfile
		echo "" | tee -a $logfile
		echo "auditing if webserver is writable" | tee -a $logfile
		$MSFCLI auxiliary/scanner/http/writable RHOSTS=$line THREADS=10 E | tee -a $logfile
		echo "" | tee -a $logfile

		echo "auditing directories" | tee -a $logfile
		$MSFCLI auxiliary/scanner/http/wmap_dir_scanner RHOSTS=$line PATH=$MPATH THREADS=10 E | tee -a $logfile

		for X in txt html asp htm aspx cfg
		do
			echo "auditing for $X files" | tee -a $logfile
			$MSFCLI auxiliary/scanner/http/wmap_files_dir RHOSTS=$line PATH=$MPATH THREADS=10 EXT=.$X E | tee -a $logfile
		done
		if [ $NIKTO -eq 1 ]; then
			echo "auditing the webserver with nikto" | tee -a $logfile
			nikto -host $line $NIKTOOPTS -timeout $timeout -port 80 | tee -a $nlogfile
		fi

		echo "finished auditing device: $line, HTTP" | tee -a $logfile
		echo "===================================================================" | tee -a $logfile
	done < $IP
fi

if [ -r $IPs ]; then
	while read line
	do
		echo "===================================================================" | tee -a $logfile
		echo "auditing device: $line, HTTPS" | tee -a $logfile
		echo "" | tee -a $logfile

		echo "auditing webserver version" | tee -a $logfile
		$MSFCLI auxiliary/scanner/http/version RHOSTS=$line THREADS=10 RPORT=443 SSL=true E | tee -a $logfile
		echo "" | tee -a $logfile
		echo "auditing webserver options" | tee -a $logfile
		$MSFCLI auxiliary/scanner/http/options RHOSTS=$line THREADS=10 RPORT=443 SSL=true E | tee -a $logfile
		echo "" | tee -a $logfile
		echo "auditing if webserver is writable" | tee -a $logfile
		$MSFCLI auxiliary/scanner/http/writable RHOSTS=$line THREADS=10 RPORT=443 SSL=true E | tee -a $logfile
		echo "" | tee -a $logfile
		echo "looking for ssl details" | tee -a $logfile
		$MSFCLI auxiliary/scanner/http/wmap_ssl RHOSTS=$line THREADS=10 RPORT=443 SSL=true E | tee -a $logfile
		echo "" | tee -a $logfile

		echo "auditing directories" | tee -a $logfile
		$MSFCLI auxiliary/scanner/http/wmap_dir_scanner RHOSTS=$line PATH=$MPATH THREADS=10 RPORT=443 SSL=true E | tee -a $logfile

		for X in txt html asp htm aspx cfg
		do
			echo "auditing $X files" | tee -a $logfile
			$MSFCLI auxiliary/scanner/http/wmap_files_dir RHOSTS=$line PATH=$MPATH THREADS=10 RPORT=443 SSL=true EXT=.$X E | tee -a $logfile
		done

		if [ $NIKTO -eq 1 ]; then
			echo "auditing the webserver with nikto" | tee -a $logfile
			nikto -host $line $NIKTOOPTS -timeout $timeout -ssl -port 443 | tee -a $nlogfile
		fi

		echo "finished auditing device: $line, HTTPS" | tee -a $logfile
		echo "===================================================================" | tee -a $logfile
	done < $IPs
fi

if [ -r $IPp ]; then
	while read line
	do
		PROT=`echo $line | cut -d\: -f1`
		if [ $PROT == https ]; then
			SSLx=true
		else
			SSLx=false
		fi
		PORT=`echo $line | cut -d\: -f3`
		IP=`echo $line | cut -d\: -f2 | cut -d\/ -f3`

		echo "IP: $IP"
		echo "Port: $PORT"
		echo "Protocol: $PROT"
		echo "SSL=$SSLx"

		echo "===================================================================" | tee -a $logfile
		echo "auditing device: $IP, $PROT" | tee -a $logfile
		echo "" | tee -a $logfile

		echo "auditing webserver version for $IP on Port $PORT" | tee -a $logfile
		$MSFCLI auxiliary/scanner/http/version RHOSTS=$IP THREADS=10 RPORT=$PORT SSL=$SSLx E | tee -a $logfile
		echo "" | tee -a $logfile
		echo "auditing webserver options" | tee -a $logfile
		$MSFCLI auxiliary/scanner/http/options RHOSTS=$IP THREADS=10 RPORT=$PORT SSL=$SSLx E | tee -a $logfile
		echo "" | tee -a $logfile
		echo "auditing if webserver is writable" | tee -a $logfile
		$MSFCLI auxiliary/scanner/http/writable RHOSTS=$IP THREADS=10 RPORT=$PORT SSL=$SSLx E | tee -a $logfile
		echo "" | tee -a $logfile
		if [ $PROT == https ]; then
			echo "looking for ssl details" | tee -a $logfile
			$MSFCLI auxiliary/scanner/http/wmap_ssl RHOSTS=$IP THREADS=10 RPORT=$PORT SSL=$SSLx E | tee -a $logfile
			echo "" | tee -a $logfile
		fi

		echo "auditing directories" | tee -a $logfile
		$MSFCLI auxiliary/scanner/http/wmap_dir_scanner RHOSTS=$IP PATH=$MPATH THREADS=10 RPORT=$PORT SSL=$SSLx E | tee -a $logfile

		for X in txt html asp htm aspx cfg
		do
			echo "auditing $X files" | tee -a $logfile
			$MSFCLI auxiliary/scanner/http/wmap_files_dir RHOSTS=$IP PATH=$MPATH THREADS=10 RPORT=$PORT SSL=$SSLx EXT=.$X E | tee -a $logfile
		done

		if [ $NIKTO -eq 1 ]; then
			echo "auditing the webserver with nikto" | tee -a $logfile
			if [ $PROT == https ]; then
				nikto -host $IP $NIKTOOPTS -timeout $timeout -ssl -port $PORT | tee -a $nlogfile
			else
				nikto -host $IP $NIKTOOPTS -timeout $timeout -port $PORT | tee -a $nlogfile
			fi
		fi

		echo "finished auditing device: $IP, $PROT" | tee -a $logfile
		echo "===================================================================" | tee -a $logfile
	done < $IPp
fi


echo "===================================================================" | tee -a $logfile
echo "generating output file $dir/msf-found.txt" | tee -a $logfile
grep "\[\*\]\ Found" $logfile > $dir/msf-found.txt
cat $dir/msf-found.txt | sort -u
echo "audit finished" | tee -a $logfile
echo "===================================================================" | tee -a $logfile

exit 0

