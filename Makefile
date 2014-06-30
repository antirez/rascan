CC= gcc
CCOPT= -O2 -Wall
DEBUG= -g
DEFS= -DHAVE_PROC -D_BSD_SOURCE
PCAP= libpcap/libpcap.a

OBJ=	main.o cksum.o resolve.o \
	parserange.o exit.o \
	report.o usage.o parseopt.o \
	getlhs.o if_promisc.o getif.o \
	getsubnet.o parsesubnet.o table.o \
	parent.o child.o allreceived.o \
	getdefaultif.o sharedmem.o

all: byteorder.h $(OBJ)
	$(CC) -o rascan $(CCOPT) $(DEBUG) $(COMPILE_TIME) $(DEFS) $(OBJ)

byteorder.h:
	./configure

.c.o:
	$(CC) -c $(CCOPT) $(DEBUG) $(COMPILE_TIME) $(DEFS) $<

clean:
	rm -rf rascan *.o systype.h byteorder.h
