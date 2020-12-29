/*************************************************************************
    > File Name: log.c
    > Created Time: Tue 27 Jun 2017 03:24:56 PM CST
 ************************************************************************/

#include <stdio.h>
#include <string.h>
#include "log.h"
#include "systime.h"

#include <stdarg.h>
#include <syslog.h>
#include <assert.h>


void printlog(char *func, unsigned int line, char *fmt, ...)
{
    char *p = NULL;    
    char name[2][40];
    char buff[256], fmt_buf[128];
    char time_data[32] = {0};
    int num = 0, i = 0;

    memset(name, 0, sizeof(name));
    memset(buff, 0, sizeof(buff));

    va_list ap;
    va_start(ap, fmt);
    /*
    while(*fmt){
        switch(*fmt++)    {
            case 's':
                p = va_arg(ap, char *);
                strcpy(name[i++], p);
                break;

            case 'd':
                num = va_arg(ap, int);
                break;
        }
    }*/

    vsnprintf(fmt_buf, sizeof(fmt_buf), fmt, ap);
    va_end(ap);
    get_now_time_date(time_data);
    snprintf(buff, sizeof(buff), "[%s](%s:%d) %s\n", time_data, func, line, fmt_buf);
    MY_LOG(buff);
}

void data_error(char *buff, int error_model)
{
    char data[10] = "0";

    memset(data, 0, 10);
    if(LEN_CHECK_ERROR == error_model){
        strcpy(data, "data len error\n");
    }else if(CHECK_ERROR == error_model){
        strcpy(data, "data check error\n");
    }

    DATA_ERROR(strcat(buff, data));
}

void send_date_log(char *p)
{
    SEND_DATA_LOG(p);
}


