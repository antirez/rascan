#include <stdio.h>
#include <string.h>
#include "rascan.h"
#include "globals.h"

void get_linkhdrsize(char *iface)
{
	if ( strstr(iface, "ppp") )
	{
		linkhdr_size = PPPHDR_SIZE;
		return;
	}
	else if ( strstr(iface, "eth") )
	{
		linkhdr_size = ETHHDR_SIZE;
		return;
	}
	else if ( strstr(iface, "lo") )
	{
		linkhdr_size = ETHHDR_SIZE; /* ??? */
		return ;
	}
	else
	{
		printf("[get_linkhdrsize] physical layer header size unknown\n");
		exit(0);
	}
}
