/*************************************************************************
>  File Name: utils.c
>  Author: zxl
>  Mail:
>  Created Time: Wed 31 Jul 2019 05:44:26 PM CST
*************************************************************************/

#include <sys/timeb.h>

#include "common.h"
#include "fast2date.h"

int get_result_syscmd(const char *cmd, char *result, int len)
{
	FILE *fp = NULL;

	fp = popen(cmd, "r");
	if (fp == NULL)
	{
		printf("get_result_syscmd popen error.\n");
		return MQTT_ERR_ERROR;
	}

	memset(result, 0, len);
	fgets(result, len, fp);
	pclose(fp);

	return MQTT_ERR_SUCCESS;
}

ssize_t getfilesize(const char *file)
{
	struct stat fst;
	int ret = stat(file, &fst);
	if (ret < 0)
	{
		return 0;
	}
	return fst.st_size;
}

void get_now_time_date(char *time_data)
{
	struct timeb nowtimeb;
	time_t rawtime;
	struct tm timeinfo;
	char buffer[64];

	ftime(&nowtimeb);

	rawtime = nowtimeb.time;
	my_FastSecondToDate(rawtime, &timeinfo);

	strftime(buffer, sizeof(buffer), "%Y/%m/%d %H:%M:%S", &timeinfo);
	sprintf(time_data, "%s.%03d", buffer, nowtimeb.millitm);
	return;
}
