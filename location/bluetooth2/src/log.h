#ifndef __LOG_H__
#define __LOG_H__

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h> 


#define ERROR_LOG "/tmp/blutooth/error_log"
#define DATA_ERROR_LOG "/tmp/blutooth/data_error"
#define DATA_LOG "/tmp/blutooth/data"

#define LOG_SIZE 2*1024*1024 //2M

#define MY_LOG(...){ \
		FILE *file;\
		int size;\
		struct stat statbuf;\
        stat(ERROR_LOG,&statbuf);\
        size=statbuf.st_size;\
        if(size > LOG_SIZE)\
            file = fopen(ERROR_LOG, "w+");	\
        else\
            file = fopen(ERROR_LOG, "a+");	\
		if(file != NULL) { \
			fputs(__VA_ARGS__, file);	\
		}	\
		fclose(file); \
}


#define SEND_DATA_LOG(...){ \
		FILE *file;\
		int size;\
		struct stat statbuf;\
        stat(DATA_LOG,&statbuf);\
        size=statbuf.st_size;\
        if(size > LOG_SIZE)\
            file = fopen(DATA_LOG, "w+");	\
        else\
		    file = fopen(DATA_LOG, "a+");	\
		if(file != NULL) { \
			fputs(__VA_ARGS__, file);	\
			fputs("\n", file);	\
		}	\
		fclose(file); \
}

#define DATA_ERROR(...){\
	FILE *file;	\
	file = fopen(ERROR_LOG, "a+");\
	fputs(__VA_ARGS__, file);\
	fputs("\n-------------------\n\n", file);\
	fclose(file); \
}

#define LOG_LOG(fmt, args...)	\
	printlog(__FUNCTION__, __LINE__,fmt, ##args)


#define CHECK_CORRECT 0
#define CHECK_ERROR 1
#define LEN_CHECKA_CORRECT 5
#define LEN_CHECK_ERROR 1


void printlog(char *func, unsigned int line, char *fmt, ...);
void printdata(char *);
void data_error(char *, int);
void send_date_log(char *);


#endif 
