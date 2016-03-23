#include "checksum.h"

__be16 calcChecksum(__be16 check, __be32 oriAddr, __be16 oriPort, __be32 modAddr, __be16 modPort) {
	__be16 origin[3];
	__be16 modified[3];
	long sum;
	origin[0] = (oriAddr >> 16) & 0xffff;
	origin[1] = oriAddr & 0xffff;
	origin[2] = oriPort;
	modified[0] = (modAddr >> 16) & 0xffff;
	modified[1] = modAddr & 0xffff;
	modified[2] = modPort;

	sum = (~check) & 0xffff;
	for (int i = 0; i < 3; i++) {
		sum += modified[i] & 0xffff;
		sum -= origin[i] & 0xffff;
		if (sum < 0) {
			sum--;
			sum &= 0xffff;
		}
		if(sum > 0xffff) {
			sum++;
			sum &= 0xffff;
		}
	}
	return (__be16)(~sum) & 0xffff;
}

