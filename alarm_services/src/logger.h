/*************************************************************************
>  File Name: logger.h
>  Author: zxl
>  Mail:
>  Created Time: Wed 31 Jul 2019 05:44:49 PM CST
*************************************************************************/

#ifndef _LOGGER_H
#define _LOGGER_H

#define LOGFILE "/tmp/alarm_services.log"
#define DEBUG_BUFFER_MAX_LENGTH 8192
#define LOGSIZE (2 * 1024 * 1024)

void printlog(char *file, char *format, ...);

#define MYLOG_TEST(format, ...)                                                  \
	{                                                                            \
		printlog(LOGFILE, "(%s:%d) " format, __func__, __LINE__, ##__VA_ARGS__); \
	}

#define MYLOG(format, ...)                        \
	{                                             \
		printlog(LOGFILE, format, ##__VA_ARGS__); \
	}

#endif
