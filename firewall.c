/**
 * @file firewall.h
 * 
 * Firewall module.
 * Please read README to learn the usage.
 *
 * @version $201201110207$
 * @author "Wei-Tsung Lin" <fasthall@gmail.com>
 * @note Copyright(c) 2012., all rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "firewall.h"

/* initialize */
void fwInitialize(void) {
	fwSize = 0;
	fwAddrHead = NULL;
	fwAddrNow = NULL;
	fwAddrPrev = NULL;
	fwPortHead = NULL;
	fwPortNow = NULL;
	fwPortPrev = NULL;
	return;
}

/* load rules */
void fwLoadRules(char *filename) {
	char buffer[FW_BUFSIZE];
	FILE *fp = fopen(filename, "r");
	if (fp == NULL) {
		fprintf(stderr, "Cannot open %s.\n", filename);
	}
	while (fgets(buffer, FW_BUFSIZE, fp) != NULL) {
		if (!strncmp(buffer, "ip", 2)) {
			char *tok = (char *)(buffer + 3);
			tok[strlen(tok) - 1] = '\0';
			fwNewAddress(tok);
		} else if (!strncmp(buffer, "port", 4)) {
			char *tok = (char *)(buffer + 5);
			tok[strlen(tok) - 1] = '\0';
			int port = atoi(tok);
			fwNewPort(port);
		}
	}
}

/* new address to be blocked */
void fwNewAddress(char *addr) {
	struct BlockAddress *entry = (struct BlockAddress*)malloc(sizeof(struct BlockAddress));
	strcpy(entry->addr, addr);
	entry->next = NULL;

	if (fwAddrHead == NULL) {
		fwAddrHead = entry;
		return;
	}
	fwAddrNow = fwAddrHead;
	while (fwAddrNow != NULL) {
		fwAddrPrev = fwAddrNow;
		fwAddrNow = fwAddrNow->next;
	}
	fwAddrNow = entry;
	fwAddrPrev->next = fwAddrNow;
	return;
}

/* new address to be blocked */
void fwNewPort(unsigned short port) {
	struct BlockPort *entry = (struct BlockPort*)malloc(sizeof(struct BlockPort));
	entry->port = port;
	entry->next = NULL;

	if (fwPortHead == NULL) {
		fwPortHead = entry;
		return;
	}
	fwPortNow = fwPortHead;
	while (fwPortNow != NULL) {
		fwPortPrev = fwPortNow;
		fwPortNow = fwPortNow->next;
	}
	fwPortNow = entry;
	fwPortPrev->next = fwPortNow;
	return;
}

int fwIsAddrBlocked(char *addr) {
	fwAddrNow = fwAddrHead;
	while (fwAddrNow != NULL) {
		if (!strcmp(fwAddrNow->addr, addr)) {
			return 1;
		}
		fwAddrNow = fwAddrNow->next;
	}
	return 0;
}

int fwIsPortBlocked(unsigned short port) {
	fwPortNow = fwPortHead;
	while (fwPortNow != NULL) {
		if (fwPortNow->port == port) {
			return 1;
		}
		fwPortNow = fwPortNow->next;
	}
	return 0;
}

void fwFreeAddress(struct BlockAddress *entry) {
	if (entry == NULL) {
		return;
	}
	fwFreeAddress(entry->next);
	free(entry);
	return;
}

void fwFreePort(struct BlockPort *entry) {
	if (entry == NULL) {
		return;
	}
	fwFreePort(entry->next);
	free(entry);
	return;
}

void fwPrintList(void) {
	printf("Blocked address:\n");
	fwAddrNow = fwAddrHead;
	while (fwAddrNow != NULL) {
		printf("%s ", fwAddrNow->addr);
		fwAddrNow = fwAddrNow->next;
	}
	printf("\nBlocked port:\n");
	fwPortNow = fwPortHead;
	while (fwPortNow != NULL) {
		printf("%d", fwPortNow->port);
		fwPortNow = fwPortNow->next;
	}
	printf("\n");
	return;
}

