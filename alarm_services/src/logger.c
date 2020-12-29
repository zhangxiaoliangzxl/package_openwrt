/*************************************************************************
>  File Name: logger.c
>  Author: zxl
>  Mail:
>  Created Time: Wed 31 Jul 2019 05:44:54 PM CST
*************************************************************************/

#include "logger.h"
#include "common.h"
#include "utils.h"

void printlog(char *file, char *format, ...)
{
	char buffer[DEBUG_BUFFER_MAX_LENGTH + 1] = {0};
	FILE *fp;
	char time_data[32] = {0};
	va_list arg;
	va_start(arg, format);
	vsnprintf(buffer, DEBUG_BUFFER_MAX_LENGTH, format, arg);
	strcat(buffer, "\n");
	va_end(arg);
	size_t fsize = getfilesize(file);
	if (fsize > LOGSIZE)
	{
		fp = fopen(file, "w+");
	}
	else
	{
		fp = fopen(file, "a+");
	}
	get_now_time_date(time_data);
	// stime[strlen(stime) - 2] = '\0';
	fprintf(fp, "[%s] %s", time_data, buffer);
	fclose(fp);
}

