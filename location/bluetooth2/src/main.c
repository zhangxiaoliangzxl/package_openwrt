/*************************************************************************
    > File Name: main.c
    > Created Time: Tue 27 Jun 2017 10:06:43 AM CST
 ************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "list.h"
#include "init.h"
#include "data_bl.h"
#include "pthread.h"
#include "main.h"

#include "us_list.h"

int main()
{
    int ret, fd;
    char buff[READ_LEN] = {0};
    int agin_flag = {0};
    int time;   

    con = (struct config *)malloc(sizeof(struct config));

    /*init*/
    if (pool_create(3) != 0) {
        LOG_LOG("create pool_thread error!");
        goto ERROR;
    }

    ret = init();
    if(ret < 0){
        LOG_LOG("init error!");
        goto ERROR;
    }

AGIN:
    agin_flag = 0;
    if (fd) {
        close(fd);
    }
    fd = BL_FILE();
    if(fd < 0)
    {
        LOG_LOG("usb tty open error, retyr after 3s!");
        sleep(3);
        goto AGIN;
    }
    time = get_time_date();
    
    while(1)
    {
        /*time out*/
        time = timeout(time, con->send_time);
        memset(buff, 0, sizeof(buff));

        /*循环读取数据*/
        ret = read_data(fd, buff);
        if(ret < 0){
            LOG_LOG("read form bluetooth error, next time read !");
            msleep(300);
            continue;
        }
        else if(ret == 2)
        {
            //LOG_LOG("read blocking!");
            time = get_time_date();

            agin_flag++;

            if(agin_flag >= 10){
                LOG_LOG("read blocking long times!");
                goto AGIN;
            }
            
            msleep(300);

        }
        else if(ret == 1)
        {
            LOG_LOG("no data read !");
        }
        else {
            agin_flag = 0;
            msleep(300);
        }
    }

ERROR:
    if (fd)
        close(fd);
    pool_destroy();
    free(con);
    return 0;
}

