/* trivial shared memory handler for rascan
 * Copyright (C) 1999 by Salvatore Sanfilippo
 * email: <antirez@invece.org>
 * Covered by GPL version 2 of license (see COPYING)
 */

#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <unistd.h> /* fork() */
#include <string.h> /* memset() */
#include <stdlib.h> /* NULL macro */
#include "rascan.h"
#include "globals.h"

static int id;

int shm_creat(int size)
{
	id = shmget(IPC_PRIVATE, 40, IPC_CREAT | 0777);
	if (id == -1)
	{
		if (opt_debug)
			perror("[shm_creat] shmget");
		return -1; /* on error -1 */
	}
	return id; /* on success > 0 */
}

char *shm_attach(void)
{
	char *shared;

	shared = shmat(id, 0, 0);
	if (shared == (char*) -1)
	{
		if (opt_debug)
			perror("shmat");
		return NULL; /* on error NULL */
	}
	return shared; /* on success the address */
}

int shm_detach(char *addr)
{
	return shmdt(addr);
}
