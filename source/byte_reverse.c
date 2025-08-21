/* Public domain. */

#include "byte.h"

void byte_reverse(register char *buf, register unsigned int len)
{
	unsigned int k;
	for (k = len / 2;k > 0;) {
		--k;
		register const char c = buf[k];
		buf[k] = buf[len - k - 1];
		buf[len - k - 1] = c;
	}
}
