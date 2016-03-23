#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <linux/types.h>

__be16 calcChecksum(__be16 check, __be32 oriAddr, __be16 oriPort, __be32 modAddr, __be16 modPort);

#endif

