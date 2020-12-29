/*************************************************************************
>  File Name: util.h
>  Author: zxl
>  Mail:
>  Created Time: Wed 20 Mar 2019 04:14:14 PM CST
*************************************************************************/
#ifndef _UTIL_H
#define _UTIL_H
#include <stdint.h>
#include <sys/types.h>

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

#define DEF_CRC_INIT 0xFFFF

uint16_t calccrc(uint8_t crcbuf, uint16_t crc);
uint16_t CRC_Check(uint16_t crc, uint8_t *buf, uint16_t len);
void JSONDATA_TIME(struct timeval *tv, char *data_time);
char *time_revises(int len, char *time);
void replace_char(char *source, char s1, char s2);
void mac2hex(const char *macstr, unsigned char *machex);
uint16_t crc16_ccitt(uint8_t *data, uint16_t len);
void printf_hex(char *title, unsigned char *hex, int n);

#endif
