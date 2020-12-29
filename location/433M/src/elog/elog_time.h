/*************************************************************************
	> File Name : time_utils.h
	> Author : zxl
	> Mail :
	> Created Time: Wed 30 Oct 2019 09 : 20 : 19 AM CST
*************************************************************************/

#ifndef _ELOG_TIME_H
#define _TIME_TIME_H

#include <time.h>

void elog_time_init(void);
int elog_localtime(time_t unix_sec, struct tm *tm);

#endif
