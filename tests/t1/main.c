#include "t.h"

int f1(myenum);
int f2(myenum);

int
main(void)
{
	(void)f1(MYENUM1);
	(void)f2(MYENUM2);
	return (0);
}
