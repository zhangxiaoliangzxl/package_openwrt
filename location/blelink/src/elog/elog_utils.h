/*************************************************************************
>  File Name: elog_utils.h
>  Author: zxl
>  Mail:
>  Created Time: Tue 02 Jun 2020 11:01:43 AM CST
*************************************************************************/

#ifndef _ELOG_UTILS_H
#define _ELOG_UTILS_H

/* EasyLogger error code */
typedef enum
{
	ELOG_NO_ERR,
} ElogErrCode;

/* elog_utils.c */
size_t elog_strcpy(size_t cur_len, char *dst, const char *src);
size_t elog_cpyln(char *line, const char *log, size_t len);
void * elog_memcpy(void *dst, const void *src, size_t count);

#endif
