#ifndef __DATA_BL_H__
#define __DATA_BL_H__

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include "main.h"
#include "log.h"
#include "us_list.h"
#include "systime.h"

/*******luci库************/
#include<sys/socket.h>
#include<arpa/inet.h>
#include <sys/types.h>

/*********libcurl************/
#include <curl/curl.h>

/*******luci库************/
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define DEV_BL_ID_1 0x30
#define DEV_BL_ID_2 0x30
#define CHECK_CORRECT 0
#define CHECK_ERROR 1
#define LEN_CHECKA_CORRECT 5
#define LEN_CHECK_ERROR 1
#define NO_DATA '5'
#define HAVE_DATA '7'
#define REAL_DATA_LEN(i) (5 + i * 18)
#define GET_DEV_NUM(i) ((i- 5)/18)
#define msleep(i) usleep(i*1000)
#define UDP	0
#define TCP	1
#define HTTP 2

int data_16(char *);
void *get_bl_data(void *);
int BL_FILE();
int read_data(int, char *);
int data_check(char *, int );
int len_check(int , char * );
void change_data(char *, char *);
void data_string(char *, int , char *);
int set_bl_devid();
int get_real_len(char *);
int parsing_data(char *);
int addlist(char *, int);
int new_staruct(char *, char *, char *);
struct bluetooth_data *new_bl();
void *json_data_send(void *);
int timeout(int, int);
//int get_time_date();
//void *json_data_send();
//void json_data_send();
void json_send_modle();
extern int get_time_date();
#if 1
void udp_send_data(char *, int );
int udp_client(struct sockaddr_in *);
//void tcp_send_data(char *);
//void http_send_data(char *);
int udp_send(int ,struct sockaddr_in *, char *, int len);
#endif
#endif
