#!/bin/bash

# Netcat web methods checker

for webmethod in CONNECT GET OPTIONS POST PUT TRACE; do
	printf "$webmethod / HTTP/1.1\nHost: domain.com\n\n" | nc domain.com 80
done