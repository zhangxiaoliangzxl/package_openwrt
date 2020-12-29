#include "self.h"
#include <sys/stat.h>

int mychmod(char *field, int mode)
{
	mode_t cmode = 0;
	int u = mode / 100;
	int g = mode % 100 / 10;
	int o = mode % 10;
	cmode = u * 8 * 8 + g * 8 + o;
	return chmod(field, cmode);
}
