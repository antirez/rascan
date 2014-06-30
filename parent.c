#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <signal.h>
#include "rascan.h"
#include "globals.h"

#define SYN_ON (tcp->th_flags & TH_SYN)
#define ACK_ON (tcp->th_flags & TH_ACK)
#define FIN_ON (tcp->th_flags & TH_FIN)
#define RST_ON (tcp->th_flags & TH_RST)
#define URG_ON (tcp->th_flags & TH_URG)
#define PUSH_ON (tcp->th_flags & TH_PUSH)
#define NOTIFY_SYNACK_SYNFINSCAN \
	printf("SYN|ACK from %5d\t%.20s\n", port, (service)? \
	service->s_name: "unknown"); \
	fflush(stdout);
#define NOTIFY_SYNACK_OSPROBE \
	printf("SYN|ACK (Solaris, 95/98/NT, " \
	"FreeBSD, other...) from %5d\t%.20s\n", \
	port, (service)? service->s_name: \
	"unknown"); fflush(stdout);
#define NOTIFY_RSTACK_SYNSCAN \
	printf("RST|ACK from %d\n", port); fflush(stdout);
#define NOTIFY_RSTACK_FINSCAN \
	printf( "RST|ACK from %d, the port seems to be close\n", port); \
	fflush(stdout);
#define NOTIFY_SYNACKFIN_OSPROBE \
	printf("SYN|ACK|FIN (Linux?) from %5d\t%.20s\n", \
	port, (service)? service->s_name: "unknown"); fflush(stdout);
#define NOTIFY_ACK_OSPROBE \
	printf("ACK ( BSDi | HPUX ?) from %5d\t%.20s\n", \
	port, (service)? service->s_name: "unknown"); fflush(stdout);
#define C_NOTIFY_SYNACK_SYNFINSCAN \
	printf("-> SYN|ACK from %s\n", src_addr); fflush(stdout);
#define C_NOTIFY_SYNACK_OSPROBE \
	printf("-> SYN|ACK (Solaris, 95/98/NT, FreeBSD, other...) from %s\n", \
	src_addr); fflush(stdout);
#define C_NOTIFY_RSTACK_SYNSCAN \
	printf("-> RST|ACK from %s\n", src_addr); fflush(stdout);
#define C_NOTIFY_RSTACK_FINSCAN \
	printf("RST|ACK from %s... it seems to has port %d open\n", \
	src_addr, port); fflush(stdout);
#define C_NOTIFY_SYNACKFIN_OSPROBE \
	printf("-> SYN|ACK|FIN (Linux) from %s\n", src_addr); fflush(stdout);
#define C_NOTIFY_ACK_OSPROBE \
	printf("-> ACK ( *BSD* | HPUX ? ) from %s\n", src_addr); fflush(stdout);

int listener(char *device)
{
	char	packet[LINK_PACKETSIZE]; 
	struct	iphdr	*ip	= (struct iphdr*)  (packet + LINK_OFFSETIP);
	struct	tcphdr	*tcp	= (struct tcphdr*) (packet + LINK_OFFSETTCP);
	struct	servent *service;
	char	*shared;

	signal(SIGTERM, rascan_exit);
	signal(SIGINT, rascan_exit);
	signal(SIGSEGV, rascan_exit);	
	signal(SIGILL, rascan_exit);
	signal(SIGBUS, rascan_exit);
	signal(SIGFPE, rascan_exit);
	//signal(SIGCHLD, childabort);

	/* attach shared memory */
	shared = shm_attach();
	if (shared == NULL)
	{
		printf("[listener] can't attack shared memory segment\n");
		rascan_exit(-1);
	}

	/* allocate memory for ports-state table */
	if (opt_target)
	{
		port_state = malloc(scanend-scanstart+1);
		if (!port_state)
		{
			perror("[listener] port_state = malloc()");
			rascan_exit(-1);
		}
	}
	else if (opt_Cnet)
	{
		host_state = malloc(256);
		if (!host_state)
		{
			perror("[listener] host_state = malloc()");
			rascan_exit(-1);
		}
	}

	/* clear memory (shared memory cleaned by child) */
	memset((void*)packet, 0, LINK_PACKETSIZE);
	if (opt_target) bzero((void*)port_state, scanend-scanstart+1);
	else if (opt_Cnet) bzero((void*)host_state, 256);

	/* open PF_PACKET/SOCK_RAW (2.2.x) or AF_INET/SOCK_PACKET (2.0.x) */
	r_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (r_sock == -1)
		r_sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_IP));
	if (r_sock == -1) {
		perror("can't get PF_PACKET SOCK_RAW nor AF_INET SOCK_PACKET");
		rascan_exit(-1);
	}

	/* if opt_source set interface in promisc. mode */
	if (opt_source)
		if_promisc_on(r_sock);


	/* open FIXME: unsafely a temp file */
/* REMOVEME
	if ( (fp = fopen(PCfilename, "w+")) == NULL )
	{
		perror("[listener] fopen()");
		rascan_exit(-1);
	}
*/

	/* parent mail loop */
	while(1)
	{
		char		src_addr[1024],
				dst_addr[1024],
				servicename[1024],
				*portstateindex = NULL,
				*hoststateindex = NULL,
				*tmp;
		unsigned char	endbyte;
		struct	in_addr src,
				dst;
		int		port,
				size;

		/* wait for packets */
		if ( recv(r_sock, &packet, LINK_PACKETSIZE, 0) == -1)
		{
			perror("[listener] recv()");
			rascan_exit(-1);
		}

		/* extracts last byte from source address */
		tmp = malloc(sizeof(ip->saddr));
		bcopy(&(ip->saddr), tmp,  sizeof(ip->saddr));
		endbyte = *(tmp+3);

		bcopy(&(ip->saddr), &src, sizeof(struct in_addr));
		bcopy(&(ip->daddr), &dst, sizeof(struct in_addr));
		strncpy(src_addr, inet_ntoa(src), 1024);
		strncpy(dst_addr, inet_ntoa(dst), 1024);
		service = getservbyport(tcp->th_sport, "tcp");
		strncpy(servicename, (service)? service->s_name:
			"unknown", 1024);
		port	= ntohs(tcp->th_sport);
		size	= ntohs(ip->tot_len);
		if (opt_target)
			portstateindex = port_state+port-scanstart;
		else if (opt_Cnet)
			hoststateindex = host_state+endbyte;

		if ( opt_debug &&
		     !memcmp (&ip->saddr, &remote.sin_addr, sizeof(ip->saddr))&&
		     ntohs(tcp->th_dport) == sport
		   )
		{
			printf("%s.%s [%d] ", src_addr, servicename, port);
			if (SYN_ON) printf("SYN ");
			if (FIN_ON) printf("FIN ");
			if (RST_ON) printf("RST ");
			if (ACK_ON) printf("ACK ");
			if (PUSH_ON) printf("PUSH ");
			if (URG_ON) printf("URG ");
			printf("\n");
			fflush(stdout);
		}

		if (
		opt_target && ip->protocol == 6 &&
		!memcmp(&ip->saddr, &remote.sin_addr, sizeof(ip->saddr)) &&
		(SYN_ON || ACK_ON || RST_ON) &&
		ntohs(tcp->th_dport) == sport &&
		*(portstateindex) == 0
		)
		{
			/* REMOVEME
			fprintf(fp, "%d\n", port);
			fflush(fp);
			*/

			*(shared+port-scanstart) = 1;

			if (SYN_ON && ACK_ON && !FIN_ON)
			{
				*(portstateindex) = 'S';
				if ( !opt_quiet && (scanmethod == SYNSCAN ||
					scanmethod == FINSCAN))
				{
					NOTIFY_SYNACK_SYNFINSCAN
				}
				if ( scanmethod == OSPROBE )
				{
					NOTIFY_SYNACK_OSPROBE
				}
			}
			else if (RST_ON && ACK_ON)
			{
				*(portstateindex) = 'R';
				if (opt_verbose && scanmethod == SYNSCAN)
				{
					NOTIFY_RSTACK_SYNSCAN
				}
				if (scanmethod == FINSCAN && !opt_quiet)
				{
					NOTIFY_RSTACK_FINSCAN
				}
			}
			else if (SYN_ON && ACK_ON && FIN_ON)
			{
				*(portstateindex) = 'L';
				if ( (!opt_quiet) && (scanmethod == OSPROBE) )
				{
					NOTIFY_SYNACKFIN_OSPROBE
				}
			}
			else if (!SYN_ON && ACK_ON && !FIN_ON)
			{
				*(portstateindex) = 'B';
				if ( (!opt_quiet)
				&&   (scanmethod == OSPROBE) )
				{
					NOTIFY_ACK_OSPROBE
				}
			}
		}
		else if (
		opt_Cnet && (ip->protocol == 6) &&
//		(!memcmp(&ip->saddr, &remote.sin_addr, sizeof(ip->saddr)
//			- sizeof(char) ) ) &&
		(SYN_ON || ACK_ON || RST_ON) &&
		ntohs(tcp->th_dport) == sport &&
		*(hoststateindex) == 0
		)
		{
			/* REMOVEME
			fprintf(fp, "%d\n", endbyte);
			fflush(fp);
			*/
			*(shared+endbyte) = 1;

			if (SYN_ON && ACK_ON && !FIN_ON)
			{
				*hoststateindex = 'S';
				if (!opt_quiet && scanmethod != OSPROBE)
				{
					C_NOTIFY_SYNACK_SYNFINSCAN
				}

				if ( scanmethod == OSPROBE )
				{
					C_NOTIFY_SYNACK_OSPROBE
				}
			}
			else if (RST_ON && ACK_ON)
			{
				*hoststateindex = 'R';
				if (opt_verbose && scanmethod == SYNSCAN)
				{
					C_NOTIFY_RSTACK_SYNSCAN
				}
				if (!opt_quiet && scanmethod == FINSCAN)
				{
					C_NOTIFY_RSTACK_FINSCAN
				} 
			}
			else if (SYN_ON && ACK_ON && FIN_ON)
			{
				*hoststateindex = 'L';
				if (!opt_quiet)
				{
					C_NOTIFY_SYNACKFIN_OSPROBE
				}
			}
			else if (!SYN_ON && ACK_ON && !FIN_ON)
			{
				*hoststateindex = 'B';
				if (!opt_quiet)
				{
					C_NOTIFY_ACK_OSPROBE
				}
			}

		}
		/* the rest of packets from attacked host */
		else if	(
		opt_sensitive &&
		!memcmp(&ip->saddr, &remote.sin_addr, sizeof(ip->saddr)) &&
		!memcmp(&ip->daddr, &local.sin_addr, sizeof(ip->saddr))
		)
		{
			printf("***> from %s.%d to %s.%d proto: %d, "
				"size: %d\n",
				src_addr,
				ntohs(tcp->th_sport),
				dst_addr,
				ntohs(tcp->th_dport),
				ip->protocol,
				size);
		}
	}
	return 0;
}
