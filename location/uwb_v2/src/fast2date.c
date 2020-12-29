/*************************************************************************
>  File Name: fast2date.c
>  Author: zxl
>  Mail:
>  Created Time: Thu 22 Aug 2019 10:04:56 AM CST
*************************************************************************/

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static int systime_zone;

static int get_time_zone(void)
{
	time_t time_utc = 0;
	struct tm *p_tm_time;
	int time_zone = 0;

	p_tm_time = localtime(&time_utc);
	time_zone = (p_tm_time->tm_hour > 12) ? (p_tm_time->tm_hour -= 24) : p_tm_time->tm_hour;

	return time_zone;
}

static int FastSecondToDate(time_t unix_sec, struct tm *tm, int time_zone)
{
	static const int kHoursInDay = 24;
	static const int kMinutesInHour = 60;
	static const int kDaysFromUnixTime = 2472632;
	static const int kDaysFromYear = 153;
	static const int kMagicUnkonwnFirst = 146097;
	static const int kMagicUnkonwnSec = 1461;

	tm->tm_sec = unix_sec % kMinutesInHour;
	int i = (unix_sec / kMinutesInHour);
	tm->tm_min = i % kMinutesInHour; // nn
	i /= kMinutesInHour;
	tm->tm_hour = (i + time_zone) % kHoursInDay; // hh
	tm->tm_mday = (i + time_zone) / kHoursInDay;
	int a = tm->tm_mday + kDaysFromUnixTime;
	int b = (a * 4 + 3) / kMagicUnkonwnFirst;
	int c = (-b * kMagicUnkonwnFirst) / 4 + a;
	int d = ((c * 4 + 3) / kMagicUnkonwnSec);
	int e = -d * kMagicUnkonwnSec;
	e = e / 4 + c;
	int m = (5 * e + 2) / kDaysFromYear;
	tm->tm_mday = -(kDaysFromYear * m + 2) / 5 + e + 1;
	tm->tm_mon = (-m / 10) * 12 + m + 2;
	tm->tm_year = b * 100 + d - 6700 + (m / 10);

	return 0;
}

void my_time_init(void)
{
	systime_zone = get_time_zone();
}

int my_FastSecondToDate(time_t unix_sec, struct tm *tm)
{
	return FastSecondToDate(unix_sec, tm, systime_zone);
}

static int time_test(void)
{
	struct tm timeinfo;
	char buffer[64];
	time_t unix_sec = 0;

	/* init systime zone */
	my_time_init();

	/* get current time */
	unix_sec = time(NULL);

	/* convert to data */
	FastSecondToDate(unix_sec, &timeinfo, systime_zone);

	strftime(buffer, sizeof(buffer), "%Y/%m/%d %H:%M:%S", &timeinfo);
	printf("%s", buffer);

	return 0;
}

