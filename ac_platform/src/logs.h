#ifndef __MLOGS_H__
#define __MLOGS_H__

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#define LOGFILE "/tmp/debugAC"

#define DEBUG_BUFFER_MAX_LENGTH 8192

#define LOGSIZE 2097152

extern void printlog(char *file, char *format, ...);

#define LOG_DEBUG 1

/*
#define PRINTF(format, ...) \
		{\
		 if (LOG_DEBUG) { printlog(LOGFILE, "(%s:%d) "format, __func__, __LINE__, ##__VA_ARGS__);}\
		 else { printlog(LOGFILE, format, ##__VA_ARGS__);}\
		}

#endif
*/

#define PRINTF(format, ...)                       \
	{                                             \
		printlog(LOGFILE, format, ##__VA_ARGS__); \
	}

#endif
