#ifndef __LOG_H__
#define __LOG_H__

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>

/*
#ifndef DEBUG
#define DEBUG 1
#endif
*/

/*
#ifndef DEBUG_TEST
#define DEBUG_TEST 1
#endif
*/

#define LOCKFILE "/var/run/blue_daemon.pid"
#define ERROR_LOG "/tmp/blue/log"
#define DATA_LOG "/tmp/blue/printdata"
#define DATA_JIFFIES "/tmp/blue/datajiffies"
#define LOG_SIZE 1 * 1024 * 1024 // 2M

#define errorLOG(...)                      \
	{                                      \
		FILE *file;                        \
		int size;                          \
		struct stat statbuf;               \
		stat(ERROR_LOG, &statbuf);         \
		size = statbuf.st_size;            \
		if (size > LOG_SIZE)               \
			file = fopen(ERROR_LOG, "w+"); \
		else                               \
			file = fopen(ERROR_LOG, "a+"); \
		if (file != NULL)                  \
		{                                  \
			fputs(__VA_ARGS__, file);      \
		}                                  \
		fclose(file);                      \
	}

/* log to logfile */
#define dataLOG(...)                      \
	{                                     \
		FILE *file;                       \
		int size;                         \
		struct stat statbuf;              \
		stat(DATA_LOG, &statbuf);         \
		size = statbuf.st_size;           \
		if (size > LOG_SIZE)              \
			file = fopen(DATA_LOG, "w+"); \
		else                              \
			file = fopen(DATA_LOG, "a+"); \
		if (file != NULL)                 \
		{                                 \
			fputs(__VA_ARGS__, file);     \
			fputs("\n", file);            \
		}                                 \
		fclose(file);                     \
	}

#define LOG_LOG(fmt, args...) printlog(__FUNCTION__, __LINE__, fmt, ##args)

void get_now_time_date(char *time_data);
void printlog(const char *func, unsigned int line, char *fmt, ...);
void printdata(char *);
void write_jiffies(FILE *fp, char *buff);

#endif
