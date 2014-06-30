/* 
 * $smu-mark$ 
 * $name: if_promisc.c$ 
 * $author: Salvatore Sanfilippo 'antirez'$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Thu Aug 12 23:11:25 MET DST 1999$ 
 * $rev: 1$ 
 */ 

#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include "rascan.h"
#include "globals.h"

int if_promisc_on(int s)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	if ( ioctl(s, SIOCGIFFLAGS, &ifr) == -1) {
		perror("[open_sockpacket] ioctl(SIOCGIFFLAGS)");
		return -1;
	}

	if (!(ifr.ifr_flags & IFF_PROMISC)) {
		ifr.ifr_flags |= IFF_PROMISC;
		if ( ioctl(s, SIOCSIFFLAGS, &ifr) == -1) {
			perror("[open_sockpacket] ioctl(SIOCSIFFLAGS)");
			return -1;
		}
	}
	return 0;
}

int if_promisc_off(int s)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	if ( ioctl(s, SIOCGIFFLAGS, &ifr) == -1) {
		perror("[open_sockpacket] ioctl(SIOCGIFFLAGS)");
		return -1;
	}

	if (ifr.ifr_flags & IFF_PROMISC) {
		ifr.ifr_flags ^= IFF_PROMISC;
		if ( ioctl(s, SIOCSIFFLAGS, &ifr) == -1) {
			perror("[open_sockpacket] ioctl(SIOCSIFFLAGS)");
			return -1;
		}
	}
	return 0;
}
