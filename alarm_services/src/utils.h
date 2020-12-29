/*************************************************************************
>  File Name: utils.h
>  Author: zxl
>  Mail:
>  Created Time: Wed 31 Jul 2019 05:44:31 PM CST
*************************************************************************/

#ifndef _UTILS_H
#define _UTILS_H

int get_result_syscmd(const char *cmd, char *result, int len);
void get_now_time_date(char *time_data);
ssize_t getfilesize(const char *file);

#endif
