/*************************************************************************
>  File Name: tty_433.h
>  Author: zxl
>  Mail:
>  Created Time: Wed 20 Mar 2019 02:33:12 PM CST
*************************************************************************/

#ifndef _TTY_433_H
#define _TTY_433_H

#include "ring_buf.h"
#include "util.h"

#define PRINT_BUFF_SIZE 1024
#define READSIZE 512
#define MAXLENGTH_JSONDATA 1024
#define MAXFRAMELEN 512

#define DATA_LOG "/tmp/433M/printdata"
#define DATA_JIFFIES "/tmp/433M/data_jiffies"
#define LOG_SIZE 1 * 1024 * 1024 // 1M

#define ENDCHAR '\0'

typedef struct config_t
{
	int serverport;
	int print_enable;
	char serverhost[20];
	char mac[20];
	unsigned char mac16[MAC_ADDRESS_LEN + 1];
	char tty[20];
	char *print_buff;
} config;

typedef enum
{
	sendstat_start = 0,
	sendstat_creat,
	sendstat_send,
	sendstat_end
} sendstat;

typedef struct ttyread_data_t
{
	int len;
	char data[READSIZE];
} ttyread_data;

typedef struct send_data_t
{
	int length;
	char data[MAXLENGTH_JSONDATA];
} send_data;

typedef struct thread_data_t
{
	config *con;
	Rbuf_Type *ring_buffer;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_condattr_t conda;
} Thread_data;

typedef struct thread_indata_t
{
	Thread_data *in_buffer;
	Thread_data *out_buffer;
} Thread_indata;

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

int init_tty(char *ttydev, int ttyinit);
int TTY_OPEN(char *ttydev);
int recevice_from_tty(int fd, Thread_data *ttyread_buffer);

void *parse_thread_func(void *indata);
void *send_thread_func(void *indata);

#endif
