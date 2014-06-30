#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rascan.h"
#include "globals.h"

int parse_options(int argc, char **argv)
{
	char c;

	if (argc < 2)
		return -1;

	while ( (c = getopt(argc, argv, "vs:t:p:S:T:hI:a129qC:dDl")) != EOF )
	{
		switch(c)
		{
			case '?':
				return -1;
			case 'v':
				if (opt_verbose == TRUE)
					opt_moreverbose = TRUE;
				opt_verbose = TRUE;
				break;
			case 's':
				strncpy(source, optarg, 1024);
				source_flag = TRUE;
				opt_source = TRUE;
				break;
			case 't':
				strncpy(target, optarg, 1024);
				opt_target = TRUE;
				break;
			case 'C':
				strncpy(Cnet, optarg, 1024);
				opt_Cnet = TRUE;
				parse_subnet();
				break;
			case 'T':
				send_utime = atoi(optarg);
				break;
			case 'p':
				parse_range(optarg);
				break;
			case 'S':
				sport = atoi(optarg);
				break;
			case 'I':
				strncpy(interface, optarg, 1024);
				break;
			case 'a':
				opt_uncoveracl = TRUE;
				break;
			case '1':
				scanmethod = SYNSCAN;
				break;
			case '2':
				scanmethod = FINSCAN;
				break;
			case '9':
				scanmethod = OSPROBE;
				break;
			case 'q':
				opt_quiet = TRUE;
				break;
			case 'd':
				opt_sensitive = TRUE;
				break;
			case 'D':
				opt_debug = TRUE;
				break;
			case 'l':
				opt_dontskiplo = TRUE;
				break;
			case 'h':
				return -1;
		}
	}
	/* force dep. set/unset */
	if (opt_debug) {
		opt_quiet = TRUE;
		opt_verbose = FALSE;
		opt_moreverbose =FALSE;
	}

	return 0;
}
