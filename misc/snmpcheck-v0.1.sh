#!/bin/bash

SNMPCHECK=/pentest/enumeration/snmpenum/snmpcheck-1.7.pl

if [ "$1" = "" ]; then
        echo "usage: ./$0 <IP-File> <Logfile>"
        exit
else
        hostfile="$1"
        logfile="$2"
fi


while read line;
do
        $SNMPCHECK -w -T 60 -t $line | tee -a $logfile
done < $hostfile
~
