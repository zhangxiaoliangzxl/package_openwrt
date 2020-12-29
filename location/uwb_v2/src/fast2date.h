/*************************************************************************
>  File Name: fast2date.h
>  Author: zxl
>  Mail:
>  Created Time: Thu 22 Aug 2019 10:05:43 AM CST
*************************************************************************/

#ifndef _FAST2DATE_H
#define _FAST2DATE_H

#include <time.h>

void my_time_init(void);
int my_FastSecondToDate(time_t unix_sec, struct tm *tm);

#endif
