#include "log.h"
#include "fast2date.h"

void printdata(char *buff)
{
	dataLOG(buff);
}

void printlog(const char *func, unsigned int line, char *fmt, ...)
{
	char *p = NULL;
	char name[2][40];
	char buff[256], fmt_buf[128];
	int num = 0, i = 0;
	char time_data[32] = {0};

	memset(name, 0, sizeof(name));
	memset(buff, 0, sizeof(buff));

	va_list ap;
	va_start(ap, fmt);

	vsnprintf(fmt_buf, sizeof(fmt_buf), fmt, ap);
	va_end(ap);
	get_now_time_date(time_data);
#ifdef DEBUG_TEST
	snprintf(buff, sizeof(buff), "[%s](%s:%d) %s\n", time_data, func, line, fmt_buf);
#else
	snprintf(buff, sizeof(buff), "[%s] %s\n", time_data, fmt_buf);
#endif
	errorLOG(buff);
}

void get_now_time_date(char *time_data)
{
	time_t rawtime;
	struct tm timeinfo;
	char buffer[64];

	rawtime = time(NULL);
	my_FastSecondToDate(rawtime, &timeinfo);

	strftime(buffer, sizeof(buffer), "%Y/%m/%d %H:%M:%S", &timeinfo);
	sprintf(time_data, "%s", buffer);
	return;
}

void write_jiffies(FILE *fp, char *buff)
{
	if (NULL == fp) {
		return;
	}

	fseek(fp, 0, SEEK_SET);
	fwrite(buff, strlen(buff), 1, fp);
	fflush(fp);

	return;
}

