/*************************************************************************
>  File Name: util.h
>  Author: zxl
>  Mail:
>  Created Time: Wed 20 Mar 2019 04:14:14 PM CST
*************************************************************************/

#ifndef _UTIL_H
#define _UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <linux/serial.h>

#include <stdbool.h>
#include <stdint.h>
#include <sys/select.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef SUCCESS
#define SUCCESS 1
#endif

#ifndef FAIL
#define FAIL 0
#endif

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define DEF_CRC_INIT 0xFFFF

#ifndef uint
#define uint unsigned int
#endif
#ifndef uchar
#define uchar unsigned char
#endif

#define MAC_ADDRESS_LEN 6
#define MAC_ADDRESS_STRLEN 17

typedef enum Mac_Format_t
{
	MAC_FORMAT_2PART = 0,
	MAC_FORMAT_3PART,
	MAC_FORMAT_6PART_1,
	MAC_FORMAT_6PART_2,
	MAC_FORMAT_ANY,
	MAC_FORMAT_BUTT
} Mac_Format;

typedef struct strParseInfo
{
	char *szFmt;
	uint  uiLen;
} STR_PARSE_INFO_S;

uint16_t calccrc(uint8_t crcbuf, uint16_t crc);
uint16_t CRC_Check(uint16_t crc, uint8_t *buf, uint16_t len);
void     JSONDATA_TIME(struct timeval *tv, char *data_time);
char *   time_revises(int len, char *time);
void     replace_char(char *source, char s1, char s2);
uint16_t crc16_ccitt(uint8_t *data, uint16_t len);
bool     mac2hex(Mac_Format enMacfmt, char *szMac, uchar *pucMac);

#endif
