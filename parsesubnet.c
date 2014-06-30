#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rascan.h"
#include "globals.h"

void parse_subnet(void)
{
	char *mask;

	Cnet_mask = 0;
	mask = strchr(Cnet, '/');
	if (mask == NULL) {
		printf("missing /mask, assuming /24 (C class)\n");
		Cnet_mask = 24;
	}

	if (Cnet_mask == 0)
		Cnet_mask = atoi(mask+1);

	if (Cnet_mask < 24) {
		printf("sorry, netmask must be >= 24\n");
		exit(1);
	} else if (Cnet_mask > 32) {
		printf("sorry, netmask must be <= 32\n");
		exit(1);
	} else if (Cnet_mask == 31) {
		printf("sorry, netmask 31 is not correct\n");
	}
	
	if (mask)
		*mask = '\0';	/* cut Cnet on '/' */
	printf("--(debug) net : %s\n", Cnet);
	printf("--(debug) mask: %d\n", Cnet_mask);
}
