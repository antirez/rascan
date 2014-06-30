#include <stdio.h>
#include <stdlib.h>
#include "rascan.h"
#include "globals.h"

/*
REMOVEME
void received_sync(int *received_tab)
{
	int i;
	char buffer[1024];

	rewind(fp);
	if (opt_target)
		for (i = scanstart; ( (i <= scanend) && (!feof(fp)) ); i++)
		{
			fscanf(fp, "%s", buffer);
		if ( (*received_tab = atoi(buffer)) == hpit )
			hpit--;
		received_tab++;
		}
	else if (opt_Cnet)
		for (i = Cnet_first; ( (i <= Cnet_last) && (!feof(fp)) ); i++)
		{
			fscanf(fp, "%s", buffer);
		if ( (*received_tab = atoi(buffer)) == hhit )
			hhit--;
		received_tab++;
		}
}
*/

/*
REMOVEME
int wasreceived(int n, int *received_tab)
{
	int i, tmp = FALSE;

	if (opt_target)
		for (i = 0; i < (scanend - scanstart + 1); i++)
		{
			if ( *received_tab == n )
			{
				tmp = TRUE;
				break;
			}
			received_tab++;
		}
	else if (opt_Cnet)
		for (i = Cnet_first; i <= Cnet_last; i++)
		{
			if ( *received_tab == n )
			{
				tmp = TRUE;
				break;
			}
			received_tab++;
		}

	return tmp;
}
*/

int wasreceived(int n, char *received_tab)
{
	if (opt_target)
		return *(received_tab+n-scanstart);
	else if (opt_Cnet)
		return *(received_tab+n);
	return 0;
}
