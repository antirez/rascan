#include <stdio.h>              /* perror */
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>         /* struct sockaddr_in */
#include <arpa/inet.h>          /* inet_ntoa */
#include <net/if.h>
#include <unistd.h>             /* close */
#include "rascan.h"
#include "globals.h"

int getinterface(void)
{
	int fd;
	struct ifconf ifc;
	struct ifreq ibuf[16], ifr, *ifrp, *ifend;
	struct sockaddr_in sa;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("[getinterface] socket()");
		exit(1);
	}
	ifc.ifc_len = sizeof ibuf;
	ifc.ifc_buf = (caddr_t)ibuf;

	memset((char *)ibuf, 0, sizeof(ibuf));
	if (ioctl(fd, SIOCGIFCONF, (char *)&ifc) < 0 ||
		ifc.ifc_len < sizeof(struct ifreq)) {
		perror("[getinterface] ioctl()");
		exit(1);
	}

	ifrp = ibuf;
	ifend = (struct ifreq *)((char *)ibuf + ifc.ifc_len);
 
	for (; ifrp < ifend; ifrp++) {

		strncpy(ifr.ifr_name, ifrp->ifr_name, sizeof(ifr.ifr_name));
		if (ioctl(fd, SIOCGIFFLAGS, (char *)&ifr) < 0) {
			perror("[getinterface] ioctl()");
			exit(1);
		}

		if ((ifr.ifr_flags & IFF_UP) == 0)
			continue;

		memcpy(&sa, &(ifrp->ifr_addr), sizeof(struct sockaddr_in));
		if (opt_verbose)
			printf("found interface %s, address %s ...",
				ifr.ifr_name,
				inet_ntoa(sa.sin_addr) );

		if (	strstr (ifr.ifr_name, "lo")
		&&	!opt_dontskiplo		  )
		{
			if (opt_verbose)
				printf("skip\n");
			continue;
		}
		if (	interface[0] != 0 )
		{
			if ( !strstr(ifr.ifr_name, interface) )
			{
				if (opt_verbose)
					printf("skip\n");
				continue;
			}
		}

		if (opt_verbose)
			printf("ok\n");

		strncpy(interface, ifr.ifr_name, 1024);
		if (!source_flag)
		{
			strncpy(source, inet_ntoa(sa.sin_addr), 1024);
			source_flag = TRUE;
		}
		else
			if (opt_verbose)
				printf("source ip address: %s\n", source);

		if ( close(fd) == -1)
		{
			perror("[getinterface] close()");
			exit(1);
		}
		return 0;
	}
	if ( close(fd) == -1)
	{
		perror("[getinterface] close()");
		exit(1);
	}
	return -1;
}
