#!/bin/bash

# Netcat web methods checker

#
# Create a loop to go through the HTTP verbs
for verb in HEAD CONNECT GET OPTIONS POST PUT TRACE DELETE; do

	# Tell people what we are doing. 
	echo "Going to try the following method now: $verb"
	
	# do what we are doing.
	printf "$verb / HTTP/1.1\nHost: edelmanpr.nl\n\n" | nc edelmanpr.nl 80

	# so as to not slam the server right away
	sleep 5; echo " "; echo " ";
	sleip 5; echo " "; echo " ";
	sleep 5; echo " "; echo " ";

done
