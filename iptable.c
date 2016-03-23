/**
 * @file iptable.c
 *
 * Maintain the iptable for routing
 *
 * @version $201201101146$
 * @author "Wei-Tsung Lin" <fasthall@gmail.com>
 * @note Copyright(c) 2012., all rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <netinet/in.h>
#include "iptable.h"
#include "log.h"

/* initialize */
void iptInitialize(void) {
	/* actually port 0 to 7999 are not usable */
	for (int i = 0; i < 65536; i++) {
		iptPortMap[i] = 0;
	}

	/* initialize the linked list */
	iptSize = 0;
	iptHead = NULL;
	iptNow = NULL;
	iptPrev = NULL;
}

/* push new entry */
struct TableEntry* iptNewEntry(__be32 srcAddr, __be16 oriPort) {
	struct TableEntry *entry = (struct TableEntry*)malloc(sizeof(struct TableEntry));
	entry->srcAddr = srcAddr;
	entry->oriPort = oriPort;

	/* get an unused port for postrouting */
	__be16 port = iptGetUnusedPort();
	if (port == -1) {
		fprintf(stderr, "Error: No usable port.\n");
		exit(EXIT_FAILURE);
	}
	entry->modPort = ntohs(port);
	entry->next = NULL;

	iptNow = iptHead;
	if (iptNow == NULL) {
		iptHead = entry;
		return iptHead;
	}
	while (iptNow != NULL) {
		iptPrev = iptNow;
		iptNow = iptNow->next;
	}
	iptNow = entry;
	iptPrev->next = iptNow;
	iptSize++;

	return entry;
}

/* lookup an entry by source ip and port */
struct TableEntry* iptLookup(__be32 srcAddr, __be16 oriPort) {
	iptNow = iptHead;
	while (iptNow != NULL) {
		if (iptNow->srcAddr == srcAddr && iptNow->oriPort == oriPort) {
			return iptNow;
		}
		iptNow = iptNow->next;
	}
	return NULL;
}

/* reverse lookup */
struct TableEntry* iptLookupMod(__be16 modPort) {
	iptNow = iptHead;
	while (iptNow != NULL) {
		if (iptNow->modPort == modPort) {
			return iptNow;
		}
		iptNow = iptNow->next;
	}
	return NULL;
}

/* find a unused port on nat server */
int iptGetUnusedPort(void) {
	for (int i = 8000; i < 65536; i++) {
		if (iptPortMap[i] == 0) {
			iptPortMap[i] = 1;
			return i;
		}
	}
	return -1;
}

/* print all the entries in iptable */
void iptPrintTable(void) {
	int index = 0;
	iptNow = iptHead;

	printf("iptSize: %d\n", iptSize);
	while (iptNow != NULL) {
		printf("entry:%d", index++);
		printf("   %d", iptNow->srcAddr);
		printf("   %d", iptNow->oriPort);
		printf("   %d", iptNow->modPort);
		iptNow = iptNow->next;
	}
}

/* free all the entries in iptable */
void iptFreeTable(struct TableEntry* entry) {
	if (entry == NULL) {
		iptInitialize();
		return;
	} else {
		/* free entry's next node, and free the entry itself */
		iptFreeTable(entry->next);
		free(entry);		
	}
}

