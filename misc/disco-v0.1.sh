#!/bin/bash

##use this script if you have a file with IP adresses

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
#    along with this program.  If not, see http://www.gnu.org/licenses/.

logfile=logging.txt
PTR=0
NMAP=0
COM=0           ##use Nmap portscan on common used ports for discovery
PORTS="21,22,23,25,50,53,80,139,264,443,445,8000,8080,10000"    ##Ports for Scan on common used ports
FAST=0          ##use Nmap fast scan for discovery
WORKDIR=.


function usage {
        clear
        echo ""
        echo "usage: $0 -i IP-FILE -o OUTPUTDIRECTORY -n -p -f -c"
        echo "-n ... Nmap discovery scan"
        echo "-p ... Host-PTR discovery scan"
        echo "-f ... use Nmap Fast Scan for finding online hosts (auto enable the nmap option)"
        echo "-c ... use Nmap Scan on common ports for finding online hosts (auto enable the nmap option)"
        echo ""
}

if [ "$1" = "" ]; then
        usage
        exit
else
        while [ "$1" != "" ]; do
                case $1 in
                        -i | --ipfile )         shift
                                                IP=$1
                                                shift
                                                ;;
                        -o | --outputdir )      shift
                                                WORKDIR=$1
                                                shift
                                                ;;
                        -n | --nmap )           shift
                                                NMAP=1
                                                ;;
                        -p | --ptr )            shift
                                                PTR=1
                                                ;;
                        -c | --com )            shift
                                                COM=1
                                                NMAP=1
                                                ;;
                        -f | --fast )           shift
                                                FAST=1
                                                NMAP=1
                                                ;;
                        * )                     usage
                                                exit 1
                esac
        done
fi

if [ ! "$UID" -eq 0 ]; then
        echo "You are not root -> Exit!"
        exit 1
fi

if [ $WORKDIR ]; then
        mkdir $WORKDIR 2>/dev/null
        logfile=$WORKDIR/$logfile
else
        logfile=./$logfile
        WORKDIR=.
fi

if [ $NMAP -eq 1 ]; then
        echo "" | tee -a $logfile
        echo "======================================================================" | tee -a $logfile
        echo "Nmap discovery scan started" | tee -a $logfile

        echo ""
        echo ""
        echo "======================================================================"
        echo "Nmap discovery scan via ICMP-Echo Scan" | tee -a $logfile
        echo "======================================================================"
        echo ""
        nmap -d -n -sP -PE -iL $IP | tee -a $WORKDIR/nmap-icmp-echo.txt

        echo ""
        echo ""
        echo "======================================================================"
        echo "Nmap discovery scan via ICMP-Netmask Scan" | tee -a $logfile
        echo "======================================================================"
        echo ""
        nmap -d -n -sP -PM -iL $IP | tee -a $WORKDIR/nmap-icmp-netmask.txt

        echo ""
        echo ""
        echo "======================================================================"
        echo "Nmap discovery scan via ICMP-Timestamp Scan" | tee -a $logfile
        echo "======================================================================"
        echo ""
        nmap -d -n -sP -PP -iL $IP | tee -a $WORKDIR/nmap-icmp-timestamp.txt

        if [ $COM -eq 1 ]; then
                echo ""
                echo ""
                echo "======================================================================"
                echo "Nmap discovery scan via Portscan on some common used ports" | tee -a $logfile
                echo "======================================================================"
                echo ""
                nmap -v -n -sS -p$PORTS -PN -iL $IP | tee -a $WORKDIR/nmap-commonports.txt
        fi

        if [ $FAST -eq 1 ]; then
                echo ""
                echo ""
                echo "======================================================================"
                echo "Nmap discovery scan via Fastscan" | tee -a $logfile
                echo "======================================================================"
                echo ""
                nmap -v -n -F -PN -iL $IP | tee -a $WORKDIR/nmap-fastscan.txt
        fi

        echo "Nmap discovery scan finished" | tee -a $logfile
        echo "======================================================================" | tee -a $logfile
        echo "" | tee -a $logfile

fi

if [ $PTR = 1 ]; then
        echo "======================================================================" | tee -a $logfile
        echo "PTR discovery scan started" | tee -a $logfile

        while read line
        do
                host $line | tee -a $WORKDIR/ptr-check.txt
                sleep 1
        done < $IP

        echo "PTR discovery scan finished" | tee -a $logfile
        echo "======================================================================" | tee -a $logfile
        echo "" | tee -a $logfile
fi

clear
echo "======================================================================" | tee -a $logfile
echo "generating results ..." | tee -a $logfile

if [ $NMAP = 1 ]; then
        echo "" | tee -a $logfile
        echo "found the following hosts online via ICMP scans" | tee -a $logfile
        grep "^Host" $WORKDIR/nmap-icmp-*.txt | grep up | cut -d\:  -f2 | cut -d\  -f2 | sort -u | tee $WORKDIR/result-nmap-icmp-hosts.txt
        echo "" | tee -a $logfile

        echo "found the following hosts online via portscans" | tee -a $logfile

        if [ $COM -eq 1 ]; then
                grep "^Discovered" $WORKDIR/nmap-commonports.txt | cut -d\  -f6 | sort -u | tee $WORKDIR/result-nmap-commonports-hosts.txt
        fi

        if [ $FAST -eq 1 ]; then
                grep "^Discovered" $WORKDIR/nmap-fastscan.txt | cut -d\  -f6 | sort -u | tee $WORKDIR/result-nmap-fastscan-hosts.txt
        fi

        echo "" | tee -a $logfile
        echo "all results from nmap" | tee -a $logfile
        cat $WORKDIR/result-nmap*.txt | sort -u | tee $WORKDIR/result-nmap-hosts.txt
fi

if [ $PTR = 1 ]; then
        echo "" | tee -a $logfile
        echo "all PTR results" | tee -a $logfile
        grep "name pointer" $WORKDIR/ptr-check.txt | cut -d\  -f1,5 | sort -u | tee $WORKDIR/result-ptr-hosts.txt
fi

echo "" | tee -a $logfile
echo "finished discovery process" | tee -a $logfile
echo "======================================================================" | tee -a $logfile

exit 0
