#include <stdio.h>
#include "rascan.h"
#include "globals.h"

void get_subnet(void)
{
	int j = 0;
	unsigned char	a,	/* first byte */
			b,	/* second byte */
			c,	/* ... */
			d,	/* .. */
			m = 0,
			mask = 32 - Cnet_mask;
	char		*p = (unsigned char*) &remote.sin_addr;

	a = b = c = d = 0;
	a = *p++;
	b = *p++;
	c = *p++;
	d = *p;

	printf("--(debug) %u.%u.%u.%u\n", a, b, c, d);

	for (j=0; j<mask; j++)
		m += (1 << j);

	printf("--(debug) decimal mask: %u\n", m);
	
	Cnet_first = (d&(m^255));
	Cnet_last  = (d|m);

	if (Cnet_first != Cnet_last) {
		Cnet_first++;
		Cnet_last--;
	}
		
	printf("--(debug) first addr: %u.%u.%u.%u\n", a, b, c, Cnet_first);
	printf("--(debug) last  addr:    %u.%u.%u.%u\n", a, b, c, Cnet_last);
}
