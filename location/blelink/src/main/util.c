/*************************************************************************
>  File Name: util.c
>  Author: zxl
>  Mail:
>  Created Time: Wed 20 Mar 2019 04:14:07 PM CST
*************************************************************************/
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "util.h"
//#include <sys/resource.h>

STR_PARSE_INFO_S g_astMacInfo[MAC_FORMAT_BUTT] = {{"%c%c%c%c%c%c-%c%c%c%c%c%c", 13},
												  {"%c%c%c%c-%c%c%c%c-%c%c%c%c", 14},
												  {"%c%c-%c%c-%c%c-%c%c-%c%c-%c%c", 17},
												  {"%c%c:%c%c:%c%c:%c%c:%c%c:%c%c", 17},
												  {"", 0}};

bool str_2_hex(char *szData, uchar *pucHex)
{
	uint  uiLen     = 0;
	uint  i         = 0;
	char  szByte[3] = {0};
	char *pcEndptr  = NULL;

	if ((NULL == szData) || (NULL == pucHex))
	{
		printf("Invalid points: p1(%p),p2(%p).", szData, pucHex);
		return false;
	}

	uiLen = ( uint )strlen(szData);
	if (0 != uiLen % 2)
	{
		printf("Invalid strlen(mac add should be even) : %d\n", uiLen);
		return false;
	}

	for (i = 0; i < uiLen; i += 2, pucHex++)
	{
		szByte[0] = szData[i];
		szByte[1] = szData[i + 1];
		*pucHex   = ( uchar )strtoul(szByte, &pcEndptr, 16);
		if (2 != (uint)(pcEndptr - szByte))
		{
			printf("Invalid source str(%s).", szData);
			return false;
		}
	}
	return true;
}

bool mac2hex(Mac_Format enMacfmt, char *szMac, uchar *pucMac)
{
	uint uiBegin                        = 0;
	uint uiEnd                          = 0;
	uint uiLoop                         = 0;
	int  iParseCnt                      = 0;
	char szChs[MAC_ADDRESS_LEN * 2 + 1] = {0};

	if ((enMacfmt >= MAC_FORMAT_BUTT) || (NULL == szMac) || (NULL == pucMac))
	{
		printf("Invalid inputs: p1(%d),p2(%p),p3(%p)\n", enMacfmt, szMac, pucMac);
		return false;
	}
	if (MAC_FORMAT_ANY == enMacfmt)
	{
		uiBegin = MAC_FORMAT_2PART;
		uiEnd   = MAC_FORMAT_6PART_2;
	}
	else
	{
		uiBegin = enMacfmt;
		uiEnd   = enMacfmt;
	}
	for (uiLoop = uiBegin; uiLoop <= uiEnd; ++uiLoop)
	{
		iParseCnt = sscanf(szMac, g_astMacInfo[uiLoop].szFmt, &szChs[0], &szChs[1], &szChs[2], &szChs[3], &szChs[4],
						   &szChs[5], &szChs[6], &szChs[7], &szChs[8], &szChs[9], &szChs[10], &szChs[11]);
		if (MAC_ADDRESS_LEN * 2 == iParseCnt)
		{
			break;
		}
	}

	if (true != str_2_hex(szChs, pucMac))
	{
		printf("Parse failed!\n");
		return false;
	}
	return true;
}

uint16_t calccrc(uint8_t crcbuf, uint16_t crc)
{
	uint8_t i;
	uint8_t chk;
	crc = crc ^ crcbuf;

	for (i = 0; i < 8; i++)
	{
		chk = crc & 1;
		crc = crc >> 1;
		crc = crc & 0x7fff;

		if (chk == 1)
			crc = crc ^ 0xa001;

		crc = crc & 0xffff;
	}

	return crc;
}

uint16_t CRC_Check(uint16_t crc, uint8_t *buf, uint16_t len)
{
	uint8_t  hi, lo;
	uint16_t i;

	for (i = 0; i < len; i++)
	{
		crc = calccrc(*buf, crc);
		buf++;
	}

	hi  = crc % 256;
	lo  = crc / 256;
	crc = (hi << 8) | lo;

	return crc;
}

int get_time( )
{
	time_t     timep;
	struct tm *p_time;
	int        sys_time = 0;

	sys_time = time(&timep);

	return sys_time;
}

void JSONDATA_TIME(struct timeval *tv, char *data_time)
{
	char  time[20] = {0};
	char *p        = NULL;

	sprintf(time, "%ld%03ld", tv->tv_sec, tv->tv_usec / 1000);

	p = time;
	while (*p) *data_time++ = *p++;
}

char *time_revises(int len, char *time)
{
	char  buff[10] = {0};
	char *new_time = malloc(10);

	if (len == 3)
	{
		strcpy(new_time, time);
		return new_time;
	}
	else
	{
		free(new_time);
		sprintf(buff, "0%s", time);
		time_revises(len + 1, buff);
	}
}

void replace_char(char *source, char s1, char s2)
{
	int   i = 0;
	char *q = NULL;

	q = source;
	for (i = 0; i < strlen(q); i++)
	{
		if (q[i] == s1)
		{
			q[i] = s2;
		}
	}
}

/* crc16 ccitt */
const uint16_t crc_table[256] = {
	0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7, 0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad,
	0xe1ce, 0xf1ef, 0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6, 0x9339, 0x8318, 0xb37b, 0xa35a,
	0xd3bd, 0xc39c, 0xf3ff, 0xe3de, 0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485, 0xa56a, 0xb54b,
	0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d, 0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
	0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc, 0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861,
	0x2802, 0x3823, 0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b, 0x5af5, 0x4ad4, 0x7ab7, 0x6a96,
	0x1a71, 0x0a50, 0x3a33, 0x2a12, 0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a, 0x6ca6, 0x7c87,
	0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41, 0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
	0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70, 0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a,
	0x9f59, 0x8f78, 0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f, 0x1080, 0x00a1, 0x30c2, 0x20e3,
	0x5004, 0x4025, 0x7046, 0x6067, 0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e, 0x02b1, 0x1290,
	0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256, 0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
	0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405, 0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e,
	0xc71d, 0xd73c, 0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634, 0xd94c, 0xc96d, 0xf90e, 0xe92f,
	0x99c8, 0x89e9, 0xb98a, 0xa9ab, 0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3, 0xcb7d, 0xdb5c,
	0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a, 0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
	0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9, 0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83,
	0x1ce0, 0x0cc1, 0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8, 0x6e17, 0x7e36, 0x4e55, 0x5e74,
	0x2e93, 0x3eb2, 0x0ed1, 0x1ef0};

uint16_t crc16_ccitt(uint8_t *data, uint16_t len)
{
	uint16_t crc16 = 0x0000;
	uint16_t crc_h8, crc_l8;

	while (len--)
	{
		crc_h8 = (crc16 >> 8);
		crc_l8 = (crc16 << 8);
		crc16  = crc_l8 ^ crc_table[crc_h8 ^ *data];
		data++;
	}

	return crc16;
}
