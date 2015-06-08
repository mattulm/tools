#!/bin/bash

if [ "$1" == "" ]
then
	echo "Usage: ./pingsweep.sh [network]"
	echo "Example: .pingsweep.sh 192.168.1"
else
	for i in {220..254}; do
   		ping -c 1 192.168.122.$i | grep "bytes from" | cut -f1 -d":" | cut -f4 -d" "
	done
fi
