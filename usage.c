#include <stdio.h>

void usage(char *pname)
{
	char *usagestring =
	"usage: %s [-s saddr] <-t daddr | -C netaddr> [I:S:qvr:T:a129dDlh]\n";
	char *optstring[] = {
	"\tI  - interface name (default the first not lo interface)\n",
	"\ts  - source host (default the addr. of used interface)\n",
	"\tt  - target host\n",
	"\tS  - source port (default random)\n",
	"\tq  - quiet mode\n",
	"\tv  - verbose mode (logs SYN|RST)\n",
	"\tvv - more verbose mode (logs a lot of stuffs)\n",
	"\tp  - port range x-y, x (default 1-1024)\n",
	"\tT  - sending interval utime among packets\n",
	"\ta  - try to uncover ACLed port (only with SYN scan)\n",
	"\t1  - SYN scan (default)\n",
	"\t2  - FIN scan\n",
	"\t9  - SYN|FIN OS probing *sperimental*\n",
	"\tC  - target-net/mask (if omitted default mask is /24)\n",
	"\td  - sensitive mode, logs all unexpected packets from target host\n",
	"\tD  - debug mode, logs all received packets in raw format\n",
	"\tl  - don't skip loopback interface\n",
	"\th  - this help\n",
	NULL };
	int index = 0;

	printf(usagestring, pname);
	while (optstring[index])
	{
		printf(optstring[index]);
		index++;
	}
		
	exit(0);
}
