#include <stdio.h>
#include <netdb.h>
#include "rascan.h"
#include "globals.h"

void print_report_Cnet(void)
{
	int y;

	printf("\nhost\t\t\t state\n");

	if (scanmethod == SYNSCAN)
		for (y = Cnet_first; y <= Cnet_last; y++)
		{
			if ( *(host_state+y) == 0 )
			{
				if (opt_moreverbose)
					printf(".%-25dhost is down or ACL on port\n", y);
			}
			else if ( *(host_state+y) == 'R' )
			{
				if (opt_moreverbose)
					printf(".%-25dclose\n", y);
			}
			else if ( *(host_state+y) == 'S' )
			{
				printf(".%-25dopen   *\n", y);
			}
		}
}

void print_report_target(void)
{
	int	y,
		x = 0,
		acl_flag=0,
		acl_start = 0,
		acl_stop = 0;
	struct	servent *service;
	char	buffer[1024];

	printf("\nport\t\t\t service\n\n");
	for (y = scanstart; y <= scanend; y++, x++)
	{
		if (acl_flag)
		{
			if ( *(port_state+x) == 0 )
			{
				acl_stop = y;
				continue;
			}
			if ( acl_start+1 == y )
				acl_stop = acl_start;
			sprintf(buffer, "%d - %d", acl_start, acl_stop);
			printf("%-25s*it could be an ACL*\n", buffer);
			acl_flag = 0;
		}

		if (	(*(port_state+x) == 0)
		&&	opt_uncoveracl
		&&	(scanmethod == SYNSCAN)	)
		{
			acl_start = y;
			acl_flag = 1;
			continue;
		}

		if (    (*(port_state+x) == 0)
		&&      (scanmethod == FINSCAN)       )
		{
			service = getservbyport(htons(y), "tcp");
			printf("%-25d%s\n", y,
				(service) ? service->s_name : "unknonw");
		}

		if ( *(port_state+x) == 'S' )
		{
			service = getservbyport(htons(y), "tcp");
			printf("%-25d%s\n", y,
				(service) ? service->s_name : "unknonw");
		}
	}
	if (acl_flag)
	{
		sprintf(buffer, "%d - %d", acl_start, acl_stop);
		printf("%-25s*it could be an ACL*\n", buffer);
	}
}
