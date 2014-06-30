#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include "rascan.h"
#include "globals.h"

void rascan_exit(int sid)
{
	switch(sid)
	{
	case SIGSEGV:
	case SIGILL:
	case SIGBUS:
	case SIGFPE:
		printf("[rascan_exit] INTERNAL ERROR: cought signal %d\n", sid);
		exit(1);
	}

	if (childpid != getpid()) /* parent */
	{
		/* kill child */
		kill(childpid, SIGTERM);

		/* close PC file */
		(void) fclose(fp);

		/* remove PC file */
		if (unlink(PCfilename) == -1 && opt_debug)
			perror("[rascan_exit] fclose()");

		/* se off promiscuous mode */
		if (opt_source)
			if_promisc_off(r_sock);

		/* close socket */
		if (close(r_sock) == -1 && opt_debug)
			perror("[rascan_exit] close()");

	}

	if (sid == -1)
		exit(1);

	/* show scan result */
	if (opt_target)
		print_report_target();
	if (opt_Cnet)
		print_report_Cnet();
	exit(0);
}
