/*************************************************************************
>  File Name: utils.h
>  Author: zxl
>  Mail:
>  Created Time: Wed 18 Sep 2019 11:51:47 AM CST
*************************************************************************/

#ifndef _UTILS_H
#define _UTILS_H

typedef void (*sighandler_t)(int);
int pox_system(const char *cmd_line);
int system_call(const char *cmd);

#endif
