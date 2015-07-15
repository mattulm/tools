#!/bin/sh

# Demonstration of environment variables set by Hotspotter when executing a
# specified command.  Use your imagination to put this information to good use.
echo "Station MAC address is $HS_STAMAC"
echo "BSSID is $HS_BSSID"
echo "DSTMAC is $HS_DSTMAC"
echo "ESSID is $HS_ESSID"
