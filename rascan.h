#ifndef __RASCAN_H
#define __RASCAN_H

#include <sys/types.h>
#include <netinet/in.h>
#include "byteorder.h"
#include "systype.h"

/* types */
#ifndef __u8
#define __u8		u_int8_t
#endif /* __u8 */
#ifndef __u16
#define __u16		u_int16_t
#endif /* __u16 */
#ifndef __u32
#define __u32		u_int32_t
#endif /* __u32 */

#ifndef __uint8_t
#define __uint8_t	u_int8_t
#endif /* __uint8_t */
#ifndef __uint16_t
#define __uint16_t	u_int16_t
#endif /* __uint16_t */
#ifndef __uint32_t
#define __uint32_t	u_int32_t
#endif /* __uint32_t */

/* protocols header size */
#ifndef ICMPHDR_SIZE
#define ICMPHDR_SIZE	sizeof(struct myicmphdr)
#endif
#ifndef UDPHDR_SIZE
#define UDPHDR_SIZE	sizeof(struct myudphdr)
#endif
#ifndef TCPHDR_SIZE
#define TCPHDR_SIZE	sizeof(struct mytcphdr)
#endif
#ifndef IPHDR_SIZE
#define IPHDR_SIZE	sizeof(struct myiphdr)
#endif

/* usefull defines */
#ifndef TRUE
#define TRUE	1
#define FALSE	0
#endif
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif
#ifndef PF_PACKET
#define PF_PACKET 17		/* kernel 2.[12].* with 2.0.* kernel headers? */
#endif
#ifndef ETH_P_IP
#define ETH_P_IP  0x0800	/* Internet Protocol packet     */
#endif

/* header size of some physical layer type */
#define PPPHDR_SIZE	0
#define ETHHDR_SIZE	14
#define LOHDR_SIZE	14 /* FIXME: this is true only for linux */

/* packet size (physical header size + ip header + tcp header + 0 data bytes) */
#define MAX_IP_SIZE	65535
#define LINK_PACKETSIZE	( linkhdr_size +	\
			  MAX_IP_SIZE		)

/* tcp flags */
#ifndef	TH_FIN
#define TH_FIN  0x01
#endif
#ifndef TH_SYN
#define TH_SYN  0x02
#endif
#ifndef TH_RST
#define TH_RST  0x04
#endif
#ifndef TH_PUSH
#define TH_PUSH 0x08
#endif
#ifndef TH_ACK
#define TH_ACK  0x10
#endif
#ifndef TH_URG
#define TH_URG  0x20
#endif
#ifndef TH_X
#define	TH_X 0x40	/* X tcp flag */
#endif
#ifndef TH_Y
#define TH_Y 0x80	/* Y tcp flag */
#endif

/* ICMP TYPE */
#define ICMP_ECHOREPLY          0       /* Echo Reply                   */
#define ICMP_DEST_UNREACH       3       /* Destination Unreachable      */
#define ICMP_SOURCE_QUENCH      4       /* Source Quench                */
#define ICMP_REDIRECT           5       /* Redirect (change route)      */
#define ICMP_ECHO               8       /* Echo Request                 */
#define ICMP_TIME_EXCEEDED      11      /* Time Exceeded                */
#define ICMP_PARAMETERPROB      12      /* Parameter Problem            */
#define ICMP_TIMESTAMP          13      /* Timestamp Request            */
#define ICMP_TIMESTAMPREPLY     14      /* Timestamp Reply              */
#define ICMP_INFO_REQUEST       15      /* Information Request          */
#define ICMP_INFO_REPLY         16      /* Information Reply            */
#define ICMP_ADDRESS            17      /* Address Mask Request         */
#define ICMP_ADDRESSREPLY       18      /* Address Mask Reply           */

/* Codes for UNREACHABLE */
#define ICMP_NET_UNREACH        0       /* Network Unreachable          */
#define ICMP_HOST_UNREACH       1       /* Host Unreachable             */
#define ICMP_PROT_UNREACH       2       /* Protocol Unreachable         */
#define ICMP_PORT_UNREACH       3       /* Port Unreachable             */
#define ICMP_FRAG_NEEDED        4       /* Fragmentation Needed/DF set  */
#define ICMP_SR_FAILED          5       /* Source Route failed          */
#define ICMP_NET_UNKNOWN        6
#define ICMP_HOST_UNKNOWN       7
#define ICMP_HOST_ISOLATED      8
#define ICMP_NET_ANO            9
#define ICMP_HOST_ANO           10
#define ICMP_NET_UNR_TOS        11
#define ICMP_HOST_UNR_TOS       12
#define ICMP_PKT_FILTERED       13      /* Packet filtered */
#define ICMP_PREC_VIOLATION     14      /* Precedence violation */
#define ICMP_PREC_CUTOFF        15      /* Precedence cut off */
#define NR_ICMP_UNREACH 15        /* instead of hardcoding immediate value */

/* Codes for REDIRECT */
#define ICMP_REDIR_NET          0       /* Redirect Net                 */
#define ICMP_REDIR_HOST         1       /* Redirect Host                */
#define ICMP_REDIR_NETTOS       2       /* Redirect Net for TOS         */
#define ICMP_REDIR_HOSTTOS      3       /* Redirect Host for TOS        */

/* Codes for TIME_EXCEEDED */
#define ICMP_EXC_TTL            0       /* TTL count exceeded           */
#define ICMP_EXC_FRAGTIME       1       /* Fragment Reass time exceeded */

/*
 * IP header
 */
struct myiphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8    ihl:4,
                version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
        __u8    version:4,
                ihl:4;
#else
#error  "Please, edit Makefile and add -D__(LITTLE|BIG)_ENDIAN_BITFIEND"
#endif
        __u8    tos;
        __u16   tot_len;
        __u16   id;
        __u16   frag_off;
        __u8    ttl;
        __u8    protocol;
        __u16   check;
        __u32   saddr;
        __u32   daddr;
};

/*
 * UDP header
 */
struct myudphdr { 
	__u16 uh_sport;     /* source port */
	__u16 uh_dport;     /* destination port */
	__u16 uh_ulen;      /* udp length */
	__u16 uh_sum;       /* udp checksum */
};

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct mytcphdr {
	__u16	th_sport;               /* source port */
	__u16	th_dport;               /* destination port */
	__u32	th_seq;                 /* sequence number */
	__u32	th_ack;                 /* acknowledgement number */
#if defined (__LITTLE_ENDIAN_BITFIELD)
	__u8    th_x2:4,                /* (unused) */
		th_off:4;               /* data offset */
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8    th_off:4,               /* data offset */
		th_x2:4;                /* (unused) */
#else
#error  "Please, edit Makefile and add -D__(LITTLE|BIG)_ENDIAN_BITFIEND"
#endif
	__u8    th_flags;
	__u16   th_win;                 /* window */
	__u16   th_sum;                 /* checksum */
	__u16   th_urp;                 /* urgent pointer */
};

/*
 * ICMP header
 */
struct myicmphdr
{
	__u8          type;
	__u8          code;
	__u16         checksum;
	union
	{
		struct
		{
			__u16   id;
			__u16   sequence;
		} echo;
		__u32   gateway;
	} un;
};

/*
 * UDP/TCP pseudo header
 * for cksum computing
 */
struct pseudohdr
{
	__u32 saddr;
	__u32 daddr;
	__u8  zero;
	__u8  protocol;
	__u16 lenght;
};

#define PSEUDOHDR_SIZE sizeof(struct pseudohdr)

#define IP_PACKETSIZE	IPHDR_SIZE+TCPHDR_SIZE

#define LINK_OFFSETETH		0
#define LINK_OFFSETIP		linkhdr_size
#define LINK_OFFSETTCP		linkhdr_size+IPHDR_SIZE
#define IP_OFFSETIP		0
#define IP_OFFSETTCP		IPHDR_SIZE

#define DEFAULT_SPORT		(rand() % 20000)
#define DEFAULT_SCANSTART	1
#define	DEFAULT_SCANEND		1024
#define DEFAULT_SEND_UTIME	1000
#define SYNSCAN			1
#define FINSCAN			2
#define OSPROBE			3
#define DEFAULT_SCANMETHOD	SYNSCAN		/* SYN */

struct  tcp_pseudohdr
{
	struct in_addr saddr;
	struct in_addr daddr;
	u_char zero;
	u_char protocol;
	u_short lenght;
	struct mytcphdr tcpheader;
};

/* protos */
__u16	cksum(__u16 *buf, int nbytes);
void	resolve(struct sockaddr * addr, char *hostname);
void	if_close(int);
int	listener(char*);
int	synsender(char*);
void	usage(char*);
void	print_report_target(void);
void	print_report_Cnet(void);
int	parse_options(int, char**);
void	get_linkhdrsize	(char *);
void	rascan_exit(int sid);
void	received_sync(int *);
void	parse_subnet(void);
void	parse_range(char *arg);
void	get_subnet(void);
void	get_linkhdrsize(char *iface);
int	if_promisc_on(int s);
int	if_promisc_off(int s);
int	getinterface(void);
void	received_sync(int *received_tab);
int	wasreceived(int n, char *received_tab);
void	all_received(void);
void	get_default_if(char *i, int maxlen);
int	shm_creat(int size);
char	*shm_attach(void);
int	shm_detach(char *addr);

#endif /* __RASCAN_H */
