#!/bin/bash
#
#
#
# Quick script to grab all of the XSS attacks posted on Reddit
lynx -dump -listonly http://www.reddit.com/r/xss/ | grep http | grep -v reddit >> /home/redditXSSscrape.txt


