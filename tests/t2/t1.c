#include <stdio.h>

#include "t.h"

struct b *
f1(struct a *a)
{
	printf("f1\n");
	return a->b;
}
