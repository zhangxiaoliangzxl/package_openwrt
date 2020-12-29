/*************************************************************************
>  File Name: blue.h
>  Author: zxl
>  Mail:
>  Created Time: Fri 08 Nov 2019 01:49:58 PM CST
*************************************************************************/
#ifndef _BLUE_H
#define _BLUE_H

#include <semaphore.h>

#include "ring_buf.h"
#include "send.h"
#include "util.h"

#include <cjson/cJSON.h>

#define USE_SEM

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define PRINT_BUFF_SIZE 1024
#define READSIZE 512
#define MAXFRAMELEN 128
#define MAXLENGTH_JSONDATA 512

/*****************************************************************************************/
#define SERVERHOST "uci get blconfig.con.ip 2>/dev/null | tr -d '\n'"
#define SERVERPORT "uci get blconfig.con.port 2>/dev/null | tr -d '\n'"
#define TTY "uci get blconfig.con.tty 2>/dev/null | tr -d '\n'"
#define PRINT_ENABLE "uci get blconfig.con.printdata 2>/dev/null | tr -d '\n'"
#define BAUDRATE "uci get blconfig.con.baudrate 2>/dev/null | tr -d '\n'"
#define MAC "cat /sys/class/net/eth0/address 2>/dev/null | tr -d '\n'"
#ifdef TCP_SEND
#define TCP_NAGLE "uci get blconfig.con.tcp_nagle 2>/dev/null | tr -d '\n'"
#endif
/****************************************************************************************/
#define SPLIT_DELIMITER ','
#define ENDCHAR '\0'

/* blue type index */
#define TYPE_BLUE0 "ADDR:"
#define TYPE_BLUE1 "IDSN:"
#define TYPE_BLUE2 "RDL52B1:"
#define TYPE_BLUE3 "RDL52B2:"
#define TYPE_BLUE4 "AOAMAC:" /*AOA test*/

typedef enum _data_type_t
{
	_BLUE0 = 0,
	_BLUE1,
	_BLUE2,
	_BLUE3,
	_BLUE4
} data_type_t;

typedef enum
{
	start = 0,
	serail,
	senddata,
	readdata,
	end
} runstats;

typedef enum
{
	sendstat_start = 0,
	sendstat_creat,
	sendstat_send,
	sendstat_end
} sendstat;

typedef struct config_t
{
	int serverport;
	int print_enable;
#ifdef TCP_SEND
	int tcp_nagle;
#endif
	int baudrate;
	char *print_buff;
	char serverhost[20];
	char devmac[20];
	char tty[20];
} config;

typedef struct thread_data_t
{
	config *con;
	Rbuf_Type *ring_buffer;
#ifdef USE_SEM
	sem_t sem;
#else
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_condattr_t conda;
#endif
} Thread_data;

typedef struct frame_data_t
{
	Thread_data *frame_buffer;
	Thread_data *send_buffer;
} Frame_data;

typedef struct send_data_t
{
	int length;
	char data[MAXLENGTH_JSONDATA];
} Send_data;

typedef struct _ttyread_data_t
{
	int len;
	char data[READSIZE];
} Ttyread_data;

int init_tty(char *devtty, int baudrate, int ttyinit);
int open_ttydev(config *con);
int config_init(config *con);
int recevice_from_tty(int fd, Thread_data *ttyread_buffer);
void *blue_parse_thread_func(void *indata);
void *send_thread_func(void *indata);

#endif
