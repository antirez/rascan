#ifndef __RASCAN_GLOBALS_H
#define __RASCAN_GLOBALS_H

#include <stdio.h> /* FILE type, TODO: use unix I/O */

extern int
	w_sock,
	r_sock,
	parentpid,
	childpid,
	linkhdr_size,
	sport,
	scanstart,
	scanend,
	scanmethod,
	opt_verbose,
	opt_moreverbose,
	opt_target,
	opt_Cnet,
	opt_source,
	source_flag,
	opt_uncoveracl,
	opt_quiet,
	opt_sensitive,
	opt_dontskiplo,
	opt_debug,
	send_utime,
	hpit,
	hhit;

extern unsigned char
	Cnet_first,
	Cnet_last,
	Cnet_mask;

extern struct ifreq
	ifr;

extern struct sockaddr_in
	local,
	remote;

extern char
	*port_state,
	*host_state,
	interface[1024],
	source[1024],
	target[1024],
	Cnet[1024],
	PCfilename[1024];

extern FILE
	*fp;

#endif /* __RASCAN_GLOBALS_H */
