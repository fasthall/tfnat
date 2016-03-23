#ifndef PACKET_H
#define PACKET_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

void sendTCP(char *device, char *packet, int length);
void sendUDP(char *device, char *packet, int length);

#endif

