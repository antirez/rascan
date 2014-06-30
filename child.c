#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include "rascan.h"
#include "globals.h"

int synsender(char *device)
{
	char	packet[IP_PACKETSIZE], runchar[] = "|/-\\";
	int	port;
	struct iphdr *ip = (struct iphdr*)(packet + IP_OFFSETIP);
	struct tcphdr *tcp = (struct tcphdr*) (packet + IP_OFFSETTCP);
	struct tcp_pseudohdr pseudoheader;
	unsigned char endbyte;
	char	*shared;

	port	= scanstart;
	hpit	= scanend;
	endbyte = Cnet_first;
	hhit	= Cnet_last;

	sleep(1);

	/* get raw socket */
	w_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (w_sock == -1)
	{
		perror("can't get raw socket");
		exit(1);
	}

        /* attach shared memory */
	shared = shm_attach();
	if (shared == NULL)
	{
		printf("[listener] can't attack shared memory segment\n");
		rascan_exit(-1);
	}

	/* clean up packet memory */
	memset(packet, 0, IP_PACKETSIZE);
	if (opt_Cnet) memset(shared, 0, 256);
	else if (opt_target) memset(shared, 0, scanend-scanstart+1);

	/* build IP header */
	bcopy((char*)&local.sin_addr, &ip->saddr,sizeof(ip->saddr));
	bcopy((char*)&remote.sin_addr,&ip->daddr,sizeof(ip->daddr));
	ip->version = 4;
	ip->ihl     = sizeof(struct iphdr)/4;
	ip->tos     = 0;
	ip->tot_len = htons(IP_PACKETSIZE);
	ip->id      = htons(getpid() & 255);
	ip->frag_off = 0;
	ip->ttl     = 40+(rand() % 200);
	ip->protocol = 6;
	ip->check   = 0; /* computed by kernel */

	/* build TCP header */
	tcp->th_dport = htons(port);
	tcp->th_sport = htons(sport);
	tcp->th_seq   = htonl(rand());
	tcp->th_ack   = htonl(0);
	tcp->th_off   = sizeof(struct tcphdr)/4;
	if      (scanmethod == SYNSCAN) tcp->th_flags = TH_SYN;
	else if (scanmethod == FINSCAN) tcp->th_flags = TH_FIN;
	else if (scanmethod == OSPROBE)	tcp->th_flags = TH_SYN|TH_FIN;
	tcp->th_win   = htons(32648);

	/* build pseudo header */
	bzero(&pseudoheader, 12+sizeof(struct tcphdr));
	pseudoheader.saddr.s_addr=local.sin_addr.s_addr;
	pseudoheader.daddr.s_addr=remote.sin_addr.s_addr;
	pseudoheader.protocol = 6;
	pseudoheader.lenght = htons(sizeof(struct tcphdr));
	bcopy((char*) tcp, (char*) &pseudoheader.tcpheader,
		sizeof(struct tcphdr));
	tcp->th_sum = cksum((u_short *) &pseudoheader,
		12+sizeof(struct tcphdr));

/* REMOVEME
	while ( (fp = fopen(PCfilename, "r")) == NULL )
	{
		int c = 0;

		printf("can't open %s, retry", PCfilename);
		if (c++ == 10)
		{
			perror("[synsender] fopen()");
			exit(1);
		}
		sleep(1);
	}
*/

	/* REMOVEME
	if (opt_target)
	{
		received_tab = (int*) malloc(
			(scanend - scanstart + 1) * sizeof(int) );
		bzero((void*)received_tab,
			(scanend - scanstart + 1) * sizeof(int) );
	}
	else if(opt_Cnet)
	{
		received_tab = (int*) malloc( 256 * sizeof(int) );
		bzero( (void*)received_tab, 256 * sizeof(int) );
	}

	if (received_tab == NULL)
	{
		perror("[synsender] malloc()");
		exit(1);
	}
	*/

	while (1)
	{
		static runcharid = 0;
		int	result, c;

		/*
		 * -t stuff (start)
		 */
		if (opt_target)
		{
			c = 0; /* replies received counter */
			while ( wasreceived(port, shared) )
			{
				port++; c++;
				if (port > scanend) 
					port = scanstart;
				if ( c == (scanend - scanstart + 1) )
					all_received();
			}

			tcp->th_dport = htons(port);
			tcp->th_sum = 0;
			bcopy((char*) tcp, (char*) &pseudoheader.tcpheader,
				sizeof(struct tcphdr));
			tcp->th_sum = cksum((u_short *) &pseudoheader,
				12+sizeof(struct tcphdr));
			port++;
		}

		/*
		 * -C stuff (start)
		 */
		if (opt_Cnet)
		{
			char		*tmp;
//			unsigned char	a, b, c, d;

			c = 0; /* replies received counter */
			while ( wasreceived(endbyte, shared) )
			{
				endbyte++; c++;
				if (endbyte > Cnet_last) 
					endbyte = Cnet_first;
				if ( c == (Cnet_last-Cnet_first+1) )
					all_received();
			}

			/* inc. daddr */
			tmp = malloc(sizeof(ip->daddr));
			bcopy((char*)&remote.sin_addr, tmp, sizeof(ip->daddr));
			*((char*)(tmp + 3)) = endbyte;
			bcopy((char*)tmp, &ip->daddr, sizeof(ip->daddr));
			tcp->th_sum = 0;
			bcopy((char*)tmp, (char*)&pseudoheader.daddr,
				sizeof(ip->daddr));
			bcopy((char*) tcp, (char*) &pseudoheader.tcpheader,
				sizeof(struct tcphdr));
			tcp->th_sum = cksum((u_short *) &pseudoheader,
				12+sizeof(struct tcphdr));
/*
			a = *((char*)(tmp));
			b = *((char*)(tmp + 1));
			c = *((char*)(tmp + 2));
			d = *((char*)(tmp + 3));
			printf("%u - %u - %u - %u\n", a, b, c, d);
*/

			free(tmp);
			endbyte++;
		}
		/*
		 * -C stuff (end)
		 */

		if (opt_moreverbose && opt_target)
			if (scanmethod == SYNSCAN)
				printf("sending SYN to port %d\n", port - 1);
			else if (scanmethod == FINSCAN)
				printf("sending FIN to port %d\n", port - 1);

		if (opt_moreverbose && opt_Cnet)
			if (scanmethod == SYNSCAN)
				printf("sending SYN to host .%d\n", endbyte-1);
			else if (scanmethod == FINSCAN)
				printf("sending FIN to host .%d\n", endbyte-1);

		result = sendto(w_sock, packet, IP_PACKETSIZE, 0,
			(struct sockaddr *)&remote, sizeof(remote));
		if (result != IP_PACKETSIZE)
		{
			perror("sending packet");
			exit(0);
		}
		printf("%c\b", runchar[runcharid++&3]);
		fflush(stdout);

		if ( (port > hpit || port == 0 ) && opt_target )
		{
			char command;

			sleep(1);
			if (scanmethod == SYNSCAN)
				printf("\nreturn resend "
					"SYN to timeouted port, Ctrl+c do "
					"report, 'l' list port in timeout\n");
			if (scanmethod == FINSCAN)
				printf("\nreturn resend FIN to "
					"timeouted port, ctrl+c do report\n");

			while(1)
			{
				command = getchar();
				if (command == 'l')
				{
					int y;

					(void) getchar(); /* skip enter */
/*
					REMOVEME
					received_sync(received_tab);
*/
					for (y = scanstart; y <= scanend; y++)
					{
						if (!wasreceived(y, shared))
							printf("TIMEOUT %d\n", y);
					}
				}
				else
					break;
			}

			/* resync received table with parent */
/*
			REMOVEME
			received_sync(received_tab);
*/
			port = scanstart;

			/* set hpit to highest port in timeout */
			hpit = scanend; /* can be omitted? */
			while( wasreceived(hpit, shared) )
				hpit--;
		}

		if ( (endbyte > hhit) && opt_Cnet )
		{
			sleep(2);
			printf("\n(hit a key for resending syns to timeouted "
				"hosts, ctrl+c for report)\n");

			getchar();

			/* resync received table with parent */
/*
			REMOVEME
			received_sync(received_tab);
*/
			endbyte = Cnet_first;

			/* set hhit to highest host in timeout */
			hhit = Cnet_last; /* can be omitted? */
			while ( wasreceived(hhit, shared) )
				hhit--;
		}
                usleep(send_utime);
	}
	return 0;
}
