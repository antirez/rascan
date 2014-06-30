/* 
 * $smu-mark$ 
 * $name: resolve.c$ 
 * $author: Salvatore Sanfilippo 'antirez'$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Thu Aug 12 21:52:42 MET DST 1999$ 
 * $rev: 7$ 
 */ 

#include <sys/types.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void resolve (struct sockaddr * addr, char *hostname)
{
	struct  sockaddr_in *address;
	struct  hostent     *host;

	address = (struct sockaddr_in *)addr;

	bzero((char *)address, sizeof(struct sockaddr_in));
	address->sin_family = AF_INET;
	address->sin_addr.s_addr = inet_addr(hostname);

	if ( (int)address->sin_addr.s_addr == -1) {
		host = gethostbyname(hostname);
		if (host) {
			bcopy( host->h_addr,
			(char *)&address->sin_addr,host->h_length);
		} else {
			perror("[resolve] Could not resolve address");
			exit(1);
		}
	}
}
