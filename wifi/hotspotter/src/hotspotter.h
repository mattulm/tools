/*
 * $Id: $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * Hotspotter is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

//#define DEBUG 0
#define MAXLINES 30000
#define M_HDR_LEN 24

// prototypes
int handle_ssid(u_char *ssid, u_char *last_ssid);
int handle_ap(u_char *ssid, struct iwreq iwr, int socketfd, int automatic,
    u_char *interface);
int lookup_hotspot(u_char *essid);
int become_ap(u_char *ssid, int socketfd, u_char *interface);
void cleanup_failure();
void close_pcap();
