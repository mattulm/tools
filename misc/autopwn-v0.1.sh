#!/bin/bash

release="v0.1"

#basic options
	NMAP=0
	NESSUS=0
	OPENVAS=0

#other Nmap Options
	TIMING=3	#0-5 ... higher means faster
	MOPTIONS="-v -sS -PN -n -T$TIMING"	#nmap options
	
#more Tools
	XPLOIT=1	#automated exploiting via metasploit 
			#- 0 means just CHECK if there are any exploits available
			#- 1 means automated exploiting - DANGEROUS
	
	TCPDUMP=1	#create a tcpdump of the whole audit
	IFCONFIG=1	#save networking details

#Metasploit Path
	SPLOITBIN="/pentest/exploits/framework3/msfconsole"	#Metasploit Path

#Nessus User Account:
	NESSUSUSER=root
	NESSUSPASS=""	#check this
	NESSUSBIN="/opt/nessus/bin/nessus"
	NESSUSDBIN="/opt/nessus/sbin/nessusd"

#OpenVAS User Account:
	OPENVASUSER=root
	OPENVASPASS=""	#check this
	OPENVASBIN="OpenVAS-Client"

function usage {
	echo ""
	echo "automated exploiting script:"
       	echo "version: $release"
	echo ""
	echo "usage information:"
	echo "usage: $0 -f IP-File -O <OUTPUT Directory> -p [-v -o]"
	echo ""
	echo "-p ... Nmap Portscan"
	echo "-v ... Nessus Vulnerabilityscan"
	echo "-o ... OpenVAS Vulnerabilityscan"
	echo ""
	echo "usage: $0 -V | -h"
	echo ""
	exit 0
}

function release {
	echo ""
	echo "automated audit script:"
       	echo "version: $release"
	echo ""
	exit 0
}

function license {
	clear
	echo "
		Copyright (C) [2009]  [Michael Messner - m1k3@m1k3.at]

		This program is free software: you can redistribute it and/or modify
		it under the terms of the GNU General Public License as published by
		the Free Software Foundation, either version 3 of the License, or
		(at your option) any later version.

		This program is distributed in the hope that it will be useful,
		but WITHOUT ANY WARRANTY; without even the implied warranty of
		MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
		GNU General Public License for more details.

		You should have received a copy of the GNU General Public License
		along with this program.  If not, see <http://www.gnu.org/licenses/>.
	"
	exit 0
}

if [ "$1" = "" ]; then
	usage
else
	while [ "$1" != "" ]; do
		case $1 in
		   -V | --version )	release
		   			exit
					;;
		   -l | --lic )		license
					exit
			     		;;		
		   -h | --help )	usage
		   			exit
					;;
		   -f | --file )	shift
		   			IP=$1
					;;
		   -O | --outdir )	shift
		   			WORKDIR=$1
		   			;;
		   -p | --portscan )	NMAP=1
		   			;;
		   -v | --nessus )	NESSUS=1
		   			;;
		   -o | --openvas )	OPENVAS=1
		   			;;
		   * )			usage
		   			exit 1
		esac
		shift
	done
fi

if [ ! $WORKDIR ]; then
	WORKDIR="audit"		#if there is no working directory defined then we take audit as working directory
fi

if [ "$UID" -ne "0" ]; then
	echo "You are not root -> Exit!"
	exit 1
fi

if [ -d ./$WORKDIR ]; then
	echo "there is another Working Directory ... creating a backup ..."
	mv ./$WORKDIR ./$WORKDIR-`date +%k-%M-%S-%F`
fi

echo "creating working directory ..."
mkdir ./$WORKDIR
if [ $? -ne 0 ]; then
	echo "Das Arbeitsverzeichnis konnte nicht erstellt werden -> Exit!"
	exit 1
fi

#check if the IP-Parameter is a valid file
if [ -f $IP ]; then
	NIP="-iL $IP"
else
	echo "I need a file with IP addresses for the pentest ..."
	exit 1
fi

if [ $XPLOIT -gt 0 ]; then
	NSPLOIT="-oX ./$WORKDIR/nmap"

	if [ ! -x $SPLOITBIN ]; then
		echo "Metasploit Konsolenbinary wurde nicht gefunden"
		XPLOIT=0
	fi
fi

echo "=====================================================" | tee ./$WORKDIR/logfile.txt
echo "# verwendete Scriptversion:" $release | tee -a ./$WORKDIR/logfile.txt
echo "#" | tee -a ./$WORKDIR/logfile.txt

if [ $NMAP -eq 1 ]; then
	echo "# folgendes Nmap Binary wird verwendet:" `which nmap` | tee -a ./$WORKDIR/logfile.txt
	echo "# folgende Nmap Version wird verwendet:" `nmap -V | grep version | cut -d\  -f3` | tee -a ./$WORKDIR/logfile.txt
fi

echo "# Arbeitsverzeichnis:" `pwd`/$WORKDIR | tee -a ./$WORKDIR/logfile.txt
echo "#" | tee -a ./$WORKDIR/logfile.txt
echo "# Folgende Ziele werden analysiert:" | tee -a ./$WORKDIR/logfile.txt
echo "#" | tee -a ./$WORKDIR/logfile.txt
while read line;
do
        echo "# System IP: $line"
done < $IP
echo "#" | tee -a ./$WORKDIR/logfile.txt
echo "# Folgende Checks werden nun durchgefuehrt:" | tee -a ./$WORKDIR/logfile.txt
echo "#" | tee -a ./$WORKDIR/logfile.txt

if [ $TCPDUMP -eq 1 ]; then
	echo "# creating a full TCPdump of the complete audit" | tee -a ./$WORKDIR/logfile.txt
fi
echo "# Nmap Main Scan Options: $MOPTIONS" | tee -a ./$WORKDIR/logfile.txt
if [ $NESSUS -eq 1 ]; then
	echo "# Nessus Vulnerability Scan would be executed" | tee -a ./$WORKDIR/logfile.txt
	echo "# Nessusversion:" `/opt/nessus/sbin/nessusd -v | grep nessus | cut -d\  -f3` | tee -a ./$WORKDIR/logfile.txt
	echo "#" | tee -a ./$WORKDIR/logfile.txt
fi

if [ $OPENVAS -eq 1 ]; then
	echo "# OpenVAS Vulnerability Scan would be executed" | tee -a ./$WORKDIR/logfile.txt
	echo "# OpenVAS Version:" `openvasd -v | grep OpenVAS | cut -d\  -f3` | tee -a ./$WORKDIR/logfile.txt
	echo "#" | tee -a ./$WORKDIR/logfile.txt
fi

if ([ $XPLOIT -eq 1 ] || [ $XPLOIT -eq 3 ] || [ $XPLOIT -eq 5 ]); then
	echo "# Looking for matching Exploits in the Metasploit Framework" | tee -a ./$WORKDIR/logfile.txt
elif ([ $XPLOIT -eq 2 ] || [ $XPLOIT -eq 4 ] || [ $XPLOIT -eq 6 ]); then
	echo "# Automated Exploiting via Metasploit" | tee -a ./$WORKDIR/logfile.txt
fi

echo "=====================================================" | tee -a ./$WORKDIR/logfile.txt

echo ""

if [ $TCPDUMP -eq 1 ]; then
	echo ""
	echo "====================================================="
	echo "starting tcpdump"
	tcpdump -vv -n -w ./$WORKDIR/tcpdump.log &
fi

if [ $IFCONFIG -eq 1 ]; then
	echo "" | tee -a ./$WORKDIR/network-config.txt
	echo "=====================================================" | tee -a ./$WORKDIR/network-config.txt
	echo "Interface Information:" | tee ./$WORKDIR/network-config.txt
	echo "" | tee ./$WORKDIR/network-config.txt

	ifconfig -a | tee -a ./$WORKDIR/network-config.txt

	echo "" | tee -a ./$WORKDIR/network-config.txt
	echo "Route Information:" | tee -a ./$WORKDIR/network-config.txt
	route | tee -a ./$WORKDIR/network-config.txt
	echo "=====================================================" | tee -a ./$WORKDIR/network-config.txt
	echo "" | tee -a ./$WORKDIR/network-config.txt
fi

if [ $NMAP -eq 1 ]; then

	mkdir ./$WORKDIR/nmap

	echo "" | tee -a ./$WORKDIR/nmap/nmap-portscan.txt
	echo "=====================================================" | tee -a ./$WORKDIR/nmap/nmap-portscan.txt
	echo "performing Nmap-Scan" | tee -a ./$WORKDIR/nmap/nmap-portscan.txt
	echo "" | tee -a ./$WORKDIR/nmap/nmap-portscan.txt
	
	nmap $MOPTIONS $NSPLOIT/nmap-portscan.xml $NIP | tee -a ./$WORKDIR/nmap/nmap-portscan.txt

	echo "Finished Nmap-Scan" | tee -a ./$WORKDIR/nmap/nmap-portscan.txt
	echo "=====================================================" | tee -a ./$WORKDIR/nmap/nmap-portscan.txt
	echo "" | tee -a ./$WORKDIR/nmap/nmap-portscan.txt
fi

##Nessus
if [ $NESSUS -eq 1 ]; then
	mkdir ./$WORKDIR/nessus

	echo "" | tee ./$WORKDIR/nessus/nessus.log
	echo "=====================================================" | tee ./$WORKDIR/nessus/nessus.log
	echo "performing Nessus Vulnerability Scan" | tee ./$WORKDIR/nessus/nessus.log
	
	netstat -anp | grep 1241
	if [ $? -ne 0 ]; then
		echo "Nessus not running?"
		read -p "please start nessus and press a key ..."
	fi

	$NESSUSBIN -q -x -V -T nbe localhost 1241 $NESSUSUSER $NESSUSPASS $IP ./$WORKDIR/nessus/audit.nbe | tee -a ./$WORKDIR/nessus/nessus.log

	if [ -f ./$WORKDIR/nessus/audit.nbe ]; then
		echo "" | tee -a ./$WORKDIR/nessus/nessus.log
		echo "converting nessus output files ..." | tee -a ./$WORKDIR/nessus/nessus.log

		$NESSUSBIN -i ./$WORKDIR/nessus/audit.nbe -o ./$WORKDIR/nessus/audit.html | tee -a ./$WORKDIR/nessus/nessus.log
		echo "..." | tee -a ./$WORKDIR/nessus/nessus.log

		$NESSUSBIN -i ./$WORKDIR/nessus/audit.nbe -o ./$WORKDIR/nessus/audit.nessus | tee -a ./$WORKDIR/nessus/nessus.log
		echo "..." | tee -a ./$WORKDIR/nessus/nessus.log

		$NESSUSBIN -i ./$WORKDIR/nessus/audit.nbe -o ./$WORKDIR/nessus/audit.txt | tee -a ./$WORKDIR/nessus/nessus.log
		echo "finished the converting process ..." | tee -a ./$WORKDIR/nessus/nessus.log
	else
		echo ""
		echo "WARNING"
		echo "no audit.nbe file available ... strange!"
		echo "I'm not sure if the scan was successful"
		echo ""
	fi

	if [ -f /opt/nessus/etc/nessus/nessusd.conf ]; then
		echo "saving nessusd configuration ..." | tee -a ./$WORKDIR/nessus/nessus.log
		cp /opt/nessus/etc/nessus/nessusd.conf ./$WORKDIR/nessus/nessusd.conf
	fi

	echo "Finished Nessus Scan" | tee -a ./$WORKDIR/nessus/nessus.log
	echo "=====================================================" | tee -a ./$WORKDIR/nessus/nessus.log
	echo "" | tee ./$WORKDIR/nessus/nessus.log
fi

if [ $OPENVAS -eq 1 ]; then

	mkdir ./$WORKDIR/openvas

	echo "" | tee -a ./$WORKDIR/openvas/openvas.log
	echo "=====================================================" | tee -a ./$WORKDIR/openvas/openvas.log
	echo "performing OpenVAS Vulnerability Scan" | tee -a ./$WORKDIR/openvas/openvas.log

	netstat -anp | grep 9390
	if [ $? -ne 0 ]; then
		echo "OpenVAS not running?"
		read -p "please start openvasd and press a key ..."
	fi

	$OPENVASBIN -x -V -T nbe -q localhost 9390 $OPENVASUSER $OPENVASPASS $IP ./$WORKDIR/openvas/audit.nbe | tee -a ./$WORKDIR/openvas/openvas.log
	
	if [ -f ./$WORKDIR/openvas/audit.nbe ]; then
		echo "" | tee -a ./$WORKDIR/openvas/openvas.log
		echo "converting openvas output files ..." | tee -a ./$WORKDIR/openvas/openvas.log
		$OPENVASBIN -i ./$WORKDIR/openvas/audit.nbe -o ./$WORKDIR/openvas/audit.html | tee -a ./$WORKDIR/openvas/openvas.log
		echo "..." | tee -a ./$WORKDIR/openvas/openvas.log

		$OPENVASBIN -i ./$WORKDIR/openvas/audit.nbe -o ./$WORKDIR/openvas/audit.xml | tee -a ./$WORKDIR/openvas/openvas.log
		echo "..." | tee -a ./$WORKDIR/openvas/openvas.log

		$OPENVASBIN -i ./$WORKDIR/openvas/audit.nbe -o ./$WORKDIR/openvas/audit.txt | tee -a ./$WORKDIR/openvas/openvas.log
		echo "..." | tee -a ./$WORKDIR/openvas/openvas.log

		$OPENVASBIN -i ./$WORKDIR/openvas/audit.nbe -o ./$WORKDIR/openvas/audit.tex | tee -a ./$WORKDIR/openvas/openvas.log
		echo "finished the converting process ..." | tee -a ./$WORKDIR/openvas/openvas.log
	else
		echo ""
		echo "WARNING"
		echo "no audit.nbe file available ... strange!"
		echo "I'm not sure if the scan was successful"
		echo ""
	fi

	if [ -f /usr/local/etc/openvas/openvasd.conf ]; then
		echo "saving openvasd configuration" | tee -a ./$WORKDIR/openvas/openvas.log
		cp /usr/local/etc/openvas/openvasd.conf ./$WORKDIR/openvas/openvasd.conf.`date +%k-%M-%S-%F`
	fi

	echo "Finished OpenVAS Scan" | tee -a ./$WORKDIR/openvas/openvas.log
	echo "Finished OpenVAS Scan" >> ./$WORKDIR/logfile.txt
	echo "=====================================================" | tee -a ./$WORKDIR/openvas/openvas.log
	echo "" | tee -a ./$WORKDIR/openvas/openvas.log
fi

##METASPLOIT
if [ $NMAP -eq "1" -o $NESSUS -eq "1" -o $OPENVAS -eq "1" ]; then
	mkdir ./$WORKDIR/metasploit
	while [ -f ./$WORKDIR/nmap/nmap-portscan.xml -o -f ./$WORKDIR/nessus/audit.nbe -o -f ./$WORKDIR/openvas/audit.nbe ]; do

		if [ -f ./$WORKDIR/nmap/nmap-portscan.xml ]; then
			DIR="nmap"
			FILE="nmap-portscan.xml"
			echo ""
			echo "Starting metasploit via Nmap input file"
			echo ""
		elif [ -f ./$WORKDIR/nessus/audit.nbe ]; then
			DIR="nessus"
			FILE="audit.nbe"
			echo ""
			echo "Starting metasploit via Nessus input file"
			echo ""
		elif [ -f ./$WORKDIR/openvas/audit.nbe ]; then
			DIR="openvas"
			FILE="audit.nbe"
			echo ""
			echo "Starting metasploit via OpenVAS input file"
			echo ""
		fi

		echo "" | tee -a ./$WORKDIR/metasploit/logfile.txt
		echo "=====================================================" | tee -a ./$WORKDIR/metasploit/logfile.txt
		echo "creating Metasploit Configuration:" | tee -a ./$WORKDIR/metasploit/logfile.txt
		echo "" | tee -a ./$WORKDIR/metasploit/logfile.txt
#		echo "load db_sqlite3" > ./$WORKDIR/metasploit/metasploit.cfg	#use it for older releases of metasploit
		echo "db_destroy pentest" >> ./$WORKDIR/metasploit/metasploit.cfg
		echo "db_create pentest" >> ./$WORKDIR/metasploit/metasploit.cfg

		if [ $NMAP -eq "1" ]; then
			echo "db_import_nmap_xml ./$WORKDIR/$DIR/$FILE" >> ./$WORKDIR/metasploit/metasploit.cfg
		else
			echo "db_import_nessus_nbe ./$WORKDIR/$DIR/$FILE" >> ./$WORKDIR/metasploit/metasploit.cfg
		fi	

		echo "db_hosts" >> ./$WORKDIR/metasploit/metasploit.cfg
		echo "db_services" >> ./$WORKDIR/metasploit/metasploit.cfg

		if [ $NMAP -eq "1" ]; then
			echo "db_autopwn -t -p" >> ./$WORKDIR/metasploit/metasploit.cfg
		else
			echo "db_autopwn -t -x" >> ./$WORKDIR/metasploit/metasploit.cfg
		fi

		if [ $XPLOIT -gt "0" ]; then
			if [ $NMAP -eq "1" ]; then
				echo "db_autopwn -t -p -e" >> ./$WORKDIR/metasploit/metasploit.cfg
			else
				echo "db_autopwn -t -x -e" >> ./$WORKDIR/metasploit/metasploit.cfg
			fi
		fi
		echo "jobs" >> ./$WORKDIR/metasploit/metasploit.cfg
		echo "banner" >> ./$WORKDIR/metasploit/metasploit.cfg
		echo "" >> ./$WORKDIR/metasploit/metasploit.cfg
	
		echo "executing Metasploit" | tee -a ./$WORKDIR/metasploit/logfile.txt
		$SPLOITBIN -r ./$WORKDIR/metasploit/metasploit.cfg | tee ./$WORKDIR/metasploit/metasploit.log
		echo "Finished METASPLOIT" | tee -a ./$WORKDIR/metasploit/logfile.txt
		echo "=====================================================" | tee -a ./$WORKDIR/metasploit/logfile.txt
		echo "" | tee -a ./$WORKDIR/metasploit/logfile.txt
		mv ./pentest ./$WORKDIR/metasploit/
		mv ./$WORKDIR/metasploit/metasploit.cfg ./$WORKDIR/metasploit/metasploit-$DIR.cfg

		if [ $DIR == "nmap" ]; then
			mv ./$WORKDIR/nmap/nmap-portscan.xml ./$WORKDIR/nmap/nmap-portscan_.xml
			NMAP="0"
		elif [ $DIR == "nessus" ]; then
			mv ./$WORKDIR/nessus/audit.nbe ./$WORKDIR/nessus/audit_.nbe
		elif [ $DIR == "openvas" ]; then
			mv ./$WORKDIR/openvas/audit.nbe ./$WORKDIR/openvas/audit_.nbe
		fi
	done
fi

if [ $TCPDUMP -eq 1 ]; then
	echo "" | tee -a ./$WORKDIR/tcpdump.txt
	echo "terminating tcpdump" | tee -a ./$WORKDIR/tcpdump.txt
	killall tcpdump 
fi 

echo "" | tee -a ./$WORKDIR/logfile.txt
echo "=====================================================" | tee -a ./$WORKDIR/logfile.txt
echo "finished auditing of the following devices:" | tee -a ./$WORKDIR/logfile.txt

while read line; do
        echo "# System IP:" $line
done < $IP

echo "=====================================================" | tee -a ./$WORKDIR/logfile.txt
echo "" | tee -a ./$WORKDIR/logfile.txt

exit 0
