#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include "address.h"

/* get the physical ip address */
void getDeviceIP(char *device) {
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);

	ioctl(fd, SIOCGIFADDR, &ifr);
	strcpy(physicalIP, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	physicalIP__be32 = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
	close(fd);

	return;
}

