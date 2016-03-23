/**
 * @file iptable.h
 *
 * Maintain the iptable for routing
 *
 * @version $201201101146$
 * @author "Wei-Tsung Lin" <fasthall@gmail.com>
 * @note Copyright(c) 2012., all rights reserved.
 */
#ifndef IPTABLE_H
#define IPTABLE_H

#include <linux/types.h>

/* Entry structure in the IPTable */
struct TableEntry {
	__be32 srcAddr;
	__be16 oriPort;
	__be16 modPort;
	struct TableEntry *next;
};

int iptPortMap[65536];

/* Linked list structure */
int iptSize;
struct TableEntry *iptHead;
struct TableEntry *iptNow;
struct TableEntry *iptPrev;

void iptInitialize(void);
struct TableEntry* iptNewEntry(__be32 srcAddr, __be16 oriPort);
struct TableEntry* iptLookup(__be32 srcAddr, __be16 oriPort);
struct TableEntry* iptLookupMod(__be16 modPort);
int iptGetUnusedPort(void);
void iptPrintTable(void);
void iptFreeTable(struct TableEntry *entry);

#endif
