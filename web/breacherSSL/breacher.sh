#!/usr/bin/env bash
 
if [ $# -ne 1 ]; then 
	echo Usage: $0 HOST PORT=443
	exit
fi
HOST=$1
if [ $# -ne 2 ]; then 
	PORT=443
else
	PORT=$2
fi 



java -jar breacher.jar $HOST $PORT
