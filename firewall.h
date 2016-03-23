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
#ifndef FIREWALL_H
#define FIREWALL_H

#define FW_BUFSIZE 32

struct BlockAddress {
	char addr[32];
	struct BlockAddress *next;
};

struct BlockPort {
	unsigned short port;
	struct BlockPort *next;
};

int fwSize;
struct BlockAddress *fwAddrHead;
struct BlockAddress *fwAddrNow;
struct BlockAddress *fwAddrPrev;
struct BlockPort *fwPortHead;
struct BlockPort *fwPortNow;
struct BlockPort *fwPortPrev;

void fwInitialize(void);
void fwLoadRules(char *filename);
void fwNewAddress(char *addr);
void fwNewPort(unsigned short port);
int fwIsAddrBlocked(char *addr);
int fwIsPortBlocked(unsigned short port);
void fwFreeAddress(struct BlockAddress *entry);
void fwFreePort(struct BlockPort *entry);
void fwPrintList(void);

#endif
