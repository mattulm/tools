#!/bin/bash

SAMDUMP=/usr/bin/samrdump.py

if [ "$1" = "" ]; then
        echo "usage: ./$0 <IP-File> <Logfile>"
        exit
else
        hostfile="$1"
        logfile="$2"
fi


while read line;
do
        echo "samrdump for IP: $line"
        $SAMDUMP $line 445/SMB | tee -a $logfile
        $SAMDUMP $line 139/SMB | tee -a $logfile
done < $hostfile
~
