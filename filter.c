/**
 * @file filter.c
 *
 * This is the entry point of the program.
 * The program uses libpcap as the library to capture the packet.
 *
 * @version $201201111039$
 * @author "Wei-Tsung Lin" <fasthall@gmail.com>
 * @note Copyright(c) 2012., all rights reserved.
 */
#include <pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <arpa/inet.h>
#include "iptable.h"
#include "packet.h"
#include "checksum.h"
#include "address.h"
#include "log.h"
#include "firewall.h"

#define RO_PREROUTING 0
#define RO_POSTROUTING 1
#define DEVICE_NAME_LEN 256

void *capture(void *ptr);
void *control(void *ptr);
void gotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void processTCP(const u_char *packet, int ipLength, int routing);
void processUDP(const u_char *packet, int ipLength, int routing);
void processICMP(const u_char *packet, int ipLength);
int isFromPrivate(char *srcAddr);
char* getProtocol(__u8 protocol);

pthread_t outThread, lanThread, ctrlThread;

int main(int argc, char *argv[]) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *outHandle, *lanHandle;

	/* read arguments */
	if (argc < 3) {
		fprintf(stderr, "Usage: %s OUT_DEVICE_NAME LAN_DEVICE_NAME [RULE_FILE_NAME]\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	strcpy(outDevice, argv[1]);
	strcpy(lanDevice, argv[2]);
	getDeviceIP(outDevice);

	/* firewall system */
	if (argc == 4) {
		printf("Loading firewall rules......\n");
		fwInitialize();
		fwLoadRules(argv[3]);
#ifdef DEBUG
		fwPrintList();
#endif
		printf("Loading success.\n");
	} else {
		printf("Firewall rules not set.\n");
	}

	/* initialize log system */
	logInitialize();

	outHandle = pcap_open_live(outDevice, BUFSIZ, 1, 1000, errbuf);
	if (outHandle == NULL) {
		fprintf(stderr, "Error: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}
	lanHandle = pcap_open_live(lanDevice, BUFSIZ, 1, 1000, errbuf);
	if (lanHandle == NULL) {
		fprintf(stderr, "Error: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	/* block the incoming packet */
	if (system("iptables -A INPUT -j DROP") == -1) {
		fprintf(stderr, "Blocking incoming packet may be failed.\n");
	}

	/* welcome message */
	printf("Device: %s %s\n", outDevice, lanDevice);
	printf("Physical IP: %s\n\n", physicalIP);
	printf("Welcome to the Wonderful Tiny Functionless NAT!\n");
	printf("Press enter to stop the service.\n\n");

	/* loop */
	pthread_create(&outThread, NULL, capture, (void *)outHandle);
	pthread_create(&lanThread, NULL, capture, (void *)lanHandle);
	pthread_create(&ctrlThread, NULL, control, NULL);
	pthread_join(outThread, NULL);
	pthread_join(lanThread, NULL);
	pthread_join(ctrlThread, NULL);

	/* cleanup */
	pcap_close(outHandle);
	pcap_close(lanHandle);
	iptFreeTable(iptHead);
	fwFreeAddress(fwAddrHead);
	fwFreePort(fwPortHead);
	logClose();
	if (system("iptables -F") == -1) {
		fprintf(stderr, "Flush iptables rules failed.\n");
	}

	return 0;
}

void *capture(void *ptr) {
	pcap_t *handle;
	handle = (pcap_t *)ptr;
	pcap_loop(handle, 0, gotPacket, NULL);
	return (void *)NULL;
}

void *control(void *ptr) {
	getchar();
	pthread_cancel(outThread);
	pthread_cancel(lanThread);
	return (void *)NULL;
}

/* Capture the packet */
void gotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	struct iphdr *ip;		/* ip header */
	int ipLength;			/* ip header length */
	
	ip = (struct iphdr*)(packet + 14);
	if ((ipLength = ip->ihl * 4) < 20) {
		return;
	}
	struct in_addr srcAddr, dstAddr;
	srcAddr.s_addr = ip->saddr;
	dstAddr.s_addr = ip->daddr;

#ifdef DEBUG
	printf("\nPacket type: %s\n", getProtocol(ip->protocol));
	printf("Source IP: %s\n", inet_ntoa(srcAddr));
	printf("Target IP: %s\n", inet_ntoa(dstAddr));
	printf("IP header length: %d\n", ipLength);					/* ip header length = ip->ihl * 4 */
#endif

	/* firewall access */
	if (fwIsAddrBlocked(inet_ntoa(srcAddr)) || fwIsAddrBlocked(inet_ntoa(dstAddr))) {
#ifdef DEBUG
		printf("Drop a packet with blocked address.\n");
#endif
		sprintf(logString, "Drop a packet with blocked address.\n");
		logPush();
		return;
	}

	switch (ip->protocol) {
	case IPPROTO_TCP:
		if (!strcmp(inet_ntoa(dstAddr), physicalIP)) {
			/* route to private ip */
			processTCP(packet, ipLength, RO_PREROUTING);
		} else if (strcmp(inet_ntoa(srcAddr), physicalIP)) {
			/* outcoming packet routing */
			if (isFromPrivate(inet_ntoa(srcAddr))) {
				processTCP(packet, ipLength, RO_POSTROUTING);
			}
		}
		break;
	case IPPROTO_UDP:
		if (!strcmp(inet_ntoa(dstAddr), physicalIP)) {
			/* route to private ip */
			processUDP(packet, ipLength, RO_PREROUTING);
		} else if (strcmp(inet_ntoa(srcAddr), physicalIP)) {
			/* outcoming packet routing */
			if (isFromPrivate(inet_ntoa(srcAddr))) {
				processUDP(packet, ipLength, RO_POSTROUTING);
			}
		}
		break;
	case IPPROTO_ICMP:
		processICMP(packet, ipLength);
		break;
	default:
		break;
	}
	return;
}

/* modify TCP packet */
void processTCP(const u_char *packet, int ipLength, int routing) {
	struct iphdr *ip = (struct iphdr*)(packet + 14);
	struct tcphdr *tcp = (struct tcphdr*)(packet + 14 + ipLength);
	unsigned short tcpLength = tcp->doff * 4;

#ifdef DEBIG
	printf("TCP header length: %d\n", tcpLength);
	printf("Source port: %d\n", ntohs(tcp->source));
	printf("Target port: %d\n", ntohs(tcp->dest));
#endif

	/* firewall access */
	if (fwIsPortBlocked(ntohs(tcp->source)) || fwIsPortBlocked(ntohs(tcp->dest))) {
#ifdef DEBUG
		printf("Drop a packet with blocked port.\n");
#endif
		sprintf(logString, "Drop a packet with blocked port.\n");
		logPush();
		return;
	}

	/* modify packet here */
	struct TableEntry *entry;
	__be32 addr;
	__be16 port;
	switch (routing) {
	case RO_PREROUTING:	/* deal with incoming packet */
		entry = iptLookupMod(tcp->dest);
		if (entry == NULL) {
			/* do nothing and receive the packe itself */
			sprintf(logString, "Packet to NAT server.\n");
			logPush();
		} else {
			/* modify destination address and port of incoming packet by lookup table */
			addr = entry->srcAddr;
			port = entry->oriPort;
			u_long oriAddr = ntohl(ip->daddr);
			u_short oriPort = ntohs(tcp->dest);
			ip->daddr = addr;
			tcp->dest = port;
			int length = ntohs(ip->tot_len) - (ip->ihl * 4) - tcpLength;
			tcp->check = htons(calcChecksum(ntohs(tcp->check), oriAddr, oriPort, ntohl(addr), ntohs(port)));
			ip->check = htons(calcChecksum(ntohs(ip->check), oriAddr, 0, ntohl(addr), 0));
			/* send modified packet */
			sendTCP(lanDevice, (char *)packet, length);
			struct in_addr tmp;
			tmp.s_addr = ip->daddr;
			sprintf(logString, "Prerouting to %s:%d\n", inet_ntoa(tmp), ntohs(tcp->dest));
			logPush();
		}
		break;
	case RO_POSTROUTING:		/* deal with outcoming packet */
		entry = iptLookup(ip->saddr, tcp->source);
		if (entry == NULL) {
			/* push new entry */
			struct in_addr temp;
			temp.s_addr = ip->saddr;
			struct TableEntry *n = iptNewEntry(ip->saddr, tcp->source);
			sprintf(logString, "Push new entry: %s:%d to %d\n", inet_ntoa(temp), ntohs(tcp->source), ntohs(n->modPort));
			logPush();
			addr = physicalIP__be32;
			port = n->modPort;

			/* modify source address and port of outcoming packet */
			u_long oriAddr = ntohl(ip->saddr);
			u_short oriPort = ntohs(tcp->source);
			ip->saddr = addr;
			tcp->source = port;
			int length = ntohs(ip->tot_len) - (ip->ihl * 4) - tcpLength;
			tcp->check = htons(calcChecksum(ntohs(tcp->check), oriAddr, oriPort, ntohl(addr), ntohs(port)));
			ip->check = htons(calcChecksum(ntohs(ip->check), oriAddr, 0, ntohl(addr), 0));
			/* send modified packet */
			sendTCP(outDevice, (char *)packet, length);
			struct in_addr tmp;
			tmp.s_addr = ip->daddr;
			sprintf(logString, "Postrouting to %s:%d\n", inet_ntoa(tmp), ntohs(tcp->dest));
			logPush();
		} else {
			addr = physicalIP__be32;
			port = entry->modPort;

			u_long oriAddr = ntohl(ip->saddr);
			u_short oriPort = ntohs(tcp->source);
			ip->saddr = addr;
			tcp->source = port;
			int length = ntohs(ip->tot_len) - (ip->ihl * 4) - tcpLength;
			tcp->check = htons(calcChecksum(ntohs(tcp->check), oriAddr, oriPort, ntohl(addr), ntohs(port)));
			ip->check = htons(calcChecksum(ntohs(ip->check), oriAddr, 0, ntohl(addr), 0));
			/* send modified packet */
			sendTCP(outDevice, (char *)packet, length);
			struct in_addr tmp;
			tmp.s_addr = ip->daddr;
			sprintf(logString, "Postrouting to %s:%d\n", inet_ntoa(tmp), ntohs(tcp->dest));
			logPush();
		}
		break;
	}
}

void processUDP(const u_char *packet, int ipLength, int routing) {
	struct iphdr *ip = (struct iphdr*)(packet + 14);
	struct udphdr *udp = (struct udphdr*)(packet + 14 + ipLength);
	int udpLength = ntohs(udp->len);

#ifdef DEBUG
	printf("UDP header length: %d\n", udpLength);
	printf("Source port: %d\n", ntohs(udp->source));
	printf("Target port: %d\n", ntohs(udp->dest));
#endif

	if (fwIsPortBlocked(ntohs(udp->source)) || fwIsPortBlocked(ntohs(udp->dest))) {
#ifdef DEBUG
		printf("Drop a packet with blocked port.\n");
#endif
		sprintf(logString, "Drop a packet with blocked port.\n");
		logPush();
		return;
	}

	/* modify ip and port here */
	struct TableEntry *entry;
	__be32 addr;
	__be16 port;
	switch (routing) {
	case RO_PREROUTING:	/* deal with incoming packet */
		entry = iptLookupMod(udp->dest);
		if (entry == NULL) {
			/* do nothing and receive the packe itself */
			sprintf(logString, "Packet to NAT server.\n");
			logPush();
		} else {
			/* modify destination address and port of incoming packet by lookup table */
			addr = entry->srcAddr;
			port = entry->oriPort;
			u_long oriAddr = ntohl(ip->daddr);
			u_short oriPort = ntohs(udp->dest);
			ip->daddr = addr;
			udp->dest = port;
			int length = ntohs(ip->tot_len) - (ip->ihl * 4) - udpLength;
			udp->check = htons(calcChecksum(ntohs(udp->check), oriAddr, oriPort, ntohl(addr), ntohs(port)));
			ip->check = htons(calcChecksum(ntohs(ip->check), oriAddr, 0, ntohl(addr), 0));
			/* send modified packet */
			sendUDP(lanDevice, (char *)packet, length);
			struct in_addr tmp;
			tmp.s_addr = ip->daddr;
			sprintf(logString, "Prerouting to %s:%d\n", inet_ntoa(tmp), ntohs(udp->dest));
			logPush();
		}
		break;
	case RO_POSTROUTING:		/* deal with outcoming packet */
		entry = iptLookup(ip->saddr, udp->source);
		if (entry == NULL) {
			struct in_addr temp;
			temp.s_addr = ip->saddr;
			/* push new entry */
			struct TableEntry *n = iptNewEntry(ip->saddr, udp->source);
			sprintf(logString, "Push new entry: %s:%d to %d\n", inet_ntoa(temp), ntohs(udp->source), ntohs(n->modPort));
			logPush();
			addr = physicalIP__be32;
			port = n->modPort;

			/* modify source address and port of outcoming packet */
			u_long oriAddr = ntohl(ip->saddr);
			u_short oriPort = ntohs(udp->source);
			ip->saddr = addr;
			udp->source = port;
			int length = ntohs(ip->tot_len) - (ip->ihl * 4) - udpLength;
			udp->check = htons(calcChecksum(ntohs(udp->check), oriAddr, oriPort, ntohl(addr), ntohs(port)));
			ip->check = htons(calcChecksum(ntohs(ip->check), oriAddr, 0, ntohl(addr), 0));
			/* send modified packet */
			sendUDP(outDevice, (char *)packet, length);
			struct in_addr tmp;
			tmp.s_addr = ip->daddr;
			sprintf(logString, "Postrouting to %s:%d\n", inet_ntoa(tmp), ntohs(udp->dest));
			logPush();
		} else {
			addr = physicalIP__be32;
			port = entry->modPort;

			u_long oriAddr = ntohl(ip->saddr);
			u_short oriPort = ntohs(udp->source);
			ip->saddr = addr;
			udp->source = port;
			int length = ntohs(ip->tot_len) - (ip->ihl * 4) - udpLength;
			udp->check = htons(calcChecksum(ntohs(udp->check), oriAddr, oriPort, ntohl(addr), ntohs(port)));
			ip->check = htons(calcChecksum(ntohs(ip->check), oriAddr, 0, ntohl(addr), 0));
			/* send modified packet */
			sendUDP(outDevice, (char *)packet, length);
			struct in_addr tmp;
			tmp.s_addr = ip->daddr;
			sprintf(logString, "Postrouting to %s:%d\n", inet_ntoa(tmp), ntohs(udp->dest));
			logPush();
		}
		break;
	}
}

void processICMP(const u_char *packet, int ipLength) {
	/* refer to RFC 3424 */
}

/* check if the address is in the local network */
int isFromPrivate(char *srcAddr) {
	if (!strncmp(srcAddr, "10.", 3)) {
		return 1;
	}
	if (!strncmp(srcAddr, "192.168.", 8)) {
		return 1;
	}
	for (int i = 16; i < 32; i++) {
		char prefix[8];
		sprintf(prefix, "172.%d.", i);
		if (!strncmp(srcAddr, prefix, 7)) {
			return 1;
		}
	}
	return 0;
}

/* translate protocol to string */
char* getProtocol(__u8 protocol) {
	switch (protocol) {
	case IPPROTO_TCP:
		return "TCP";
		break;
	case IPPROTO_UDP:
		return "UDP";
		break;
	case IPPROTO_ICMP:
		return "ICMP";
		break;
	default:
		return "Unknown protocol";
		break;
	}
}

