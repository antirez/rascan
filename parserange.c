#include <stdio.h>
#include "rascan.h"
#include "globals.h"

void parse_range(char *arg)
{
	int r, tmp;

	r = sscanf(arg, "%d-%d", &scanstart, &scanend);
	if ( (r == 2) && (scanstart > scanend) ) /* swap */
	{
		tmp = scanstart;
		scanstart = scanend;
		scanend = tmp;
	}

	if ( scanstart <= 0 || scanend <= 0 )
	{
		printf("[parse_range] parse error\n");
		exit(1);
	}
	if ( scanstart && !scanend )
		scanend = scanstart;
	if (r == 1)
		scanend = scanstart;
}
