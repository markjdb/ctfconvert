#include <stdio.h>

#include "t.h"

struct a *
f2(struct b *b)
{
	printf("f2\n");
	return b->a;
}
