#include <stdio.h>
#include "rascan.h"
#include "globals.h"

void all_received(void)
{
	while(1)
	{
		if (opt_target)
			printf("\nresponse received from all port, press ctrl+c\n");
		else if (opt_Cnet)
			printf("\nresponse received from all host, press ctrl+c\n");
		fflush(stdout);
		getchar();
	}
}
