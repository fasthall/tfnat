#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "packet.h"
#include "log.h"

void sendTCP(char *device, char *packet, int length) {
	char *buffer = packet + 14;
	struct iphdr *ip = (struct iphdr*)(packet + 14);
	struct tcphdr *tcp = (struct tcphdr*)(packet + 14 + ip->ihl * 4);
	struct sockaddr_in dest;
	struct in_addr daddr;
	int optval = 1;

	int sd = socket(PF_INET , SOCK_RAW , IPPROTO_TCP);	
	if (sd == -1) {
		fprintf(stderr, "Cannot open the socket.\n");
		exit(EXIT_FAILURE);	
	}
	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) == -1) {
		fprintf(stderr, "Cannot set IP_HDRINCL.\n");
		exit(EXIT_FAILURE);
	}
	if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, device, sizeof(device)) == -1) {
		fprintf(stderr, "Device %s is not usable.\n", device);
		exit(EXIT_FAILURE);
	}

	daddr.s_addr = ip->daddr;
	dest.sin_family = AF_INET;
	dest.sin_addr = daddr;
	dest.sin_port = tcp->dest;

#ifdef DEBUG
	printf("Sending to %s:%d\n", inet_ntoa(daddr), ntohs(tcp->dest));
#endif

	if (sendto(sd, buffer, length + tcp->doff * 4 + ip->ihl * 4, 0, (struct sockaddr*)&dest, sizeof(dest)) == -1) {
		fprintf(stderr, "Error sending TCP packet.\n");
		exit(EXIT_FAILURE);
	}

	close(sd);
	return ;
}

void sendUDP(char *device, char *packet, int length) {
	char *buffer = packet + 14;
	struct iphdr *ip = (struct iphdr*)(packet + 14);
	struct udphdr *udp = (struct udphdr*)(packet + 14 + ip->ihl * 4);
	struct sockaddr_in dest;
	struct in_addr daddr;
	int optval = 1;
	
	int sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
	if (sd == -1) {
		fprintf(stderr, "Cannot open the socket.\n");
		exit(EXIT_FAILURE);
	}
	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) == -1) {
		fprintf(stderr, "Cannot set IP_HDRINCL,\n");
		exit(EXIT_FAILURE);
	}
	if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, device, sizeof(device)) == -1) {
		fprintf(stderr, "Device %s is not usable.\n", device);
		exit(EXIT_FAILURE);
	}
	
	buffer = packet + 14;
	daddr.s_addr = ip->daddr;
	dest.sin_family = AF_INET;
	dest.sin_addr = daddr;
	dest.sin_port = udp->dest;

#ifdef DEBUG
	printf("UDP Sending to %s:%d\n", inet_ntoa(daddr), ntohs(udp->dest));
#endif

	if (sendto(sd, buffer, length + ntohs(udp->len) + ip->ihl * 4, 0, (struct sockaddr*)&dest, sizeof(dest)) == -1) {
		fprintf(stderr, "Error sending UDP packet.\n");
		exit(EXIT_FAILURE);
	}
	close(sd);
	
	return ;
}

