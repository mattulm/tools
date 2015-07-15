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

/*
 * lamont_dump from nmap's utils.cc.  Thanks Fyodor.
 */

/* Prototypes */
void lamont_hdump(unsigned char *bp, unsigned int length);
void printmac(unsigned char *mac);
void mac_to_string(unsigned char *mac, char *string, int len);
