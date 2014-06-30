/*
 * rascan portscanner
 * Copyright (C) 1998 Salvatore Sanfilippo | antirez
 *
 * version: RASCAN PRE 2_12 (12 Feb 1999)
 */

#ifdef _BSD_SOURCE
#undef _BSD_SOURCE
#endif /* _BSD_SOURCE */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "rascan.h"

extern	char *optarg;

/* globals */
int	w_sock,
	r_sock,
	parentpid,
	childpid = -1,
	linkhdr_size,
	sport,
	scanstart	= DEFAULT_SCANSTART,
	scanend		= DEFAULT_SCANEND,
	scanmethod	= DEFAULT_SCANMETHOD,
	opt_verbose	= FALSE,
	opt_moreverbose	= FALSE,
	opt_target	= FALSE,
	opt_Cnet	= FALSE,
	opt_source	= FALSE,
	source_flag	= FALSE,
	opt_uncoveracl	= FALSE,
	opt_quiet	= FALSE,
	opt_sensitive	= FALSE,
	opt_dontskiplo	= FALSE,
	opt_debug	= FALSE,
	send_utime	= DEFAULT_SEND_UTIME,
	hpit,					/* highest port in time out */
	hhit;					/* highest host in time out */

unsigned char	Cnet_first	= 1,		/* first host of net */
		Cnet_last	= 254, 		/* last host on net */
		Cnet_mask;			/* Cnet mask */

struct	sockaddr_in	local,
			remote;
char	*port_state,
	*host_state,
	interface[1024],
	source[1024],
	target[1024],
	Cnet[1024],
	PCfilename[1024];
FILE	*fp;

int main(int argc, char **argv)
{
	int result = 0;

	srand(time(NULL));
	sport = DEFAULT_SPORT;
	bzero(interface, sizeof(interface));

	if ( parse_options(argc, argv) == -1)
		usage(argv[0]);

#ifdef HAVE_PROC
	if (interface[0] == '\0')
		get_default_if(interface, 1024);
#endif /* HAVE_PROC */

	if ( getinterface() == -1 )
	{
		printf("[getinterface] No such device\n");
		exit(1);
	}

	if ( ( !opt_target && !opt_Cnet) || !source_flag )
	{
		printf("You must specify source and target\n");
		exit(0);
	}

	if ( opt_target && opt_Cnet )
	{
		printf("-C and -t can't be to coexist\n");
		exit(0);
	}

	if ( opt_Cnet && (scanmethod == FINSCAN) )
	{
		printf("Class C one port fast scanning don't support FIN scan\n");
		exit(0);
	}

	if ( opt_Cnet && ( scanstart != scanend ) )
	{
		printf("Multiple ports scanning not allowed with -C\n");
		exit(0);
	}

	if ( opt_quiet && opt_verbose )
	{
		printf("Quiet and verbose mode can't be setted simultaneously\n");
		exit(0);
	}

	if ( opt_verbose && opt_moreverbose )
		printf("more verbose mode\n");
	else
		if (opt_verbose)
			printf("verbose mode\n");

	printf("Using interface %s\n", interface);

	if (opt_verbose)
		if (scanstart != scanend)
			printf("port range: %d - %d\n", scanstart, scanend);
		else
			printf("port range: %d\n", scanstart);

	get_linkhdrsize(interface);
	if (opt_moreverbose)
		printf("Physical layer header size: %d\n", linkhdr_size);
	if (opt_verbose)
		printf("Source port: %d\n", sport);

	if (!opt_Cnet)
		resolve((struct sockaddr*)&remote, target);
	else
	{
		resolve((struct sockaddr*)&remote, Cnet);
		get_subnet();
	}

	resolve((struct sockaddr*)&local, source);

	/* store parent pid */
	parentpid = getpid();

	/* create shared memory segment */
	if (opt_target)
		result = shm_creat(scanend-scanstart+1);
	else if (opt_Cnet)
		result = shm_creat(256);

	if (result == -1)
	{
		printf("[main] shm_creat() error!\n");
		rascan_exit(-1);
	}

	snprintf(PCfilename, 1024, "/tmp/_PCfile_.%d", parentpid);
	if ( (childpid = fork()) == -1)
	{
		perror("[main] fork()");
		exit(1);
	}

	if (childpid)	/* parent */
	{
		listener(interface);
	}
	else		/* child */
	{
		synsender(interface);
	}
	return 0;
}

void childabort(int sid)
{
	printf("*** [listener] child abort!\n Please report this problem to <antirez@seclab.com> or <md5330@mclink.it> specifing version of rascan and the options that has caused this failure\nthanks, antirez\n");
	exit(1);
}
