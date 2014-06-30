/* 
 * $smu-mark$ 
 * $name: getdefaultif.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:47 MET 1999$ 
 * $rev: 8$ 
 */ 

#ifdef HAVE_PROC
#include <stdio.h>
#include <string.h>

#include "rascan.h"
#include "globals.h"

void get_default_if(char *i, int maxlen)
{
#if (defined OSTYPE_LINUX)
	char buffer[1024];
	char interface[1024], dest[1024];
	FILE *fp;

	fp = fopen("/proc/net/route", "r");
	if (fp == NULL)
	{
		perror("[get_default_if] fopen");
		exit(1);
	}

	while(fgets(buffer, 1024, fp) != NULL)
	{
		sscanf(buffer, "%1024s %1024s", interface, dest);
		if (!strcmp(dest, "00000000"))
		{
			if (!opt_quiet)
				printf("%s default routing interface "
					"selected (according to /proc)\n",
					interface);
			strncpy(i, interface, maxlen);
			fclose(fp);
			return;
		}
	}

	if (!opt_quiet)
		printf("default routing not present\n");
	fclose (fp);
#endif /* OSTYPE_LINUX */
}
#endif /* HAVE_PROC */
