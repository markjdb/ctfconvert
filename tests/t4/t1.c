#include <sys/types.h>

struct a {
	size_t num;
};

size_t
f1(struct a *a)
{
	return a->num;
}
