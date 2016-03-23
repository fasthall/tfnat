CFLAGS = -lpcap -pthread -std=gnu99 -O2 -Wall
CC = gcc
EXE = wtfnat

all: binary

debug: CFLAGS += -DDEBUG -g
debug: binary

binary: filter.o iptable.o packet.o address.o checksum.o firewall.o log.o
	$(CC) -o $(EXE) filter.o iptable.o packet.o address.o checksum.o firewall.o log.o $(CFLAGS)

filter.o: filter.c
	$(CC) -c filter.c $(CFLAGS)

iptable.o: iptable.c iptable.h
	$(CC) -c iptable.c $(CFLAGS)

packet.o: packet.c packet.h
	$(CC) -c packet.c $(CFLAGS)

address.o: address.c address.h
	$(CC) -c address.c $(CFLAGS)

checksum.o: checksum.c checksum.h
	$(CC) -c checksum.c $(CFLAGS)

firewall.o: firewall.c firewall.h
	$(CC) -c firewall.c $(CFLAGS)

log.o: log.c log.h
	$(CC) -c log.c $(CFLAGS)

clean:
	rm -f *.o $(EXE) log

