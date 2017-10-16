#include <sys/types.h>

struct a {
	int num : 4;
};

int
f1(struct a *a)
{
	return a->num;
}
