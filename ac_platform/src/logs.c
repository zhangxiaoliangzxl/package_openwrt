
#include "logs.h"

static ssize_t getfilesize(const char *file)
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
	time_t rawtime;
	struct tm *timeinfo;
	char buffer[64];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(buffer, sizeof(buffer), "%Y/%m/%d %H:%M:%S", timeinfo);
	sprintf(time_data, "%s", buffer);
	return;
}

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
