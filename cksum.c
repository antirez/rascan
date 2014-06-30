/* 
 * $smu-mark$ 
 * $name: cksum.c$ 
 * $author: Salvatore Sanfilippo 'antirez'$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Thu Aug 12 21:52:40 MET DST 1999$ 
 * $rev: 7$ 
 */ 

#include "rascan.h" /* only for arch semi-indipendent data types */

/*
 * from R. Stevens's Network Programming
 */
__u16 cksum(__u16 *buf, int nbytes)
{
	__u32 sum;
	__u16 oddbyte;

	sum = 0;
	while (nbytes > 1) {
		sum += *buf++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		oddbyte = 0;
		*((__u16 *) &oddbyte) = *(__u8 *) buf;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (__u16) ~sum;
}
