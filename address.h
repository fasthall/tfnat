#ifndef ADDRESS_H
#define ADDRESS_H

#include <linux/types.h>

char outDevice[256];
char lanDevice[256];
__be32 physicalIP__be32;
char physicalIP[32];
void getDeviceIP(char *device);

#endif

