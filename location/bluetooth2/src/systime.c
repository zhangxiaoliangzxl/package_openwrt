#include "systime.h"

int get_time_date()
{
	time_t timep;
	struct tm *p_time;
	int sys_time = 0;

	sys_time = time(&timep);
	return sys_time;
}

void get_now_time_date(char *time_data)
{
    time_t rawtime;
    struct tm * timeinfo;
    char buffer [64];

    time (&rawtime);
    timeinfo = localtime (&rawtime);

    strftime (buffer,sizeof(buffer),"%Y/%m/%d %H:%M:%S",timeinfo);
    sprintf(time_data, "%s", buffer); 
    return 0;
}


