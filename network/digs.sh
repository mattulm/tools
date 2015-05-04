#!/bin/bash

# Dig for the different types of flags we might want frmo a domain

for type in MX A CNAME NS SIG; do
	echo "I am going to look for the following records: $type";
	echo "I am going to look for the following records: $type" >> /home/edelmanpr.nl.digs.list;
	dig -t $type edelmanpr.nl >> /home/edelmanpr.nl.digs.list;
	echo " "; sleep 1; echo " " >> /home/edelmanpr.nl.digs.list;
	echo " "; sleep 1; echo " " >> /home/edelmanpr.nl.digs.list;
done
