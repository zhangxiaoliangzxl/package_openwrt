/*************************************************************************
>  File Name: common.h
>  Author: zxl
>  Mail:
>  Created Time: Thu 01 Aug 2019 03:38:00 PM CST
*************************************************************************/

#ifndef _COMMON_H
#define _COMMON_H

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MQTT_ERR_SUCCESS 0
#define MQTT_ERR_ERROR 1

#define GET_DISABLED "uci get alarm.main.disabled | tr -d '\n'"
#define GET_HOST "uci get alarm.main.host | tr -d '\n'"
#define GET_PORT "uci get alarm.main.port | tr -d '\n'"
#define GET_USERNAME "uci get alarm.main.username | tr -d '\n'"
#define GET_PASSWD "uci get alarm.main.passwd | tr -d '\n'"
#define GET_MAC "cat /sys/class/net/eth0/address | tr -d '\n'"

#define TOPIC_ZIGBEE "ALARM/ZIGBEE"
#define TOPIC_ZIGBEE_ALL "ALARM/ZIGBEE/ALL"

#define ALARM_STATE "/tmp/alarm_state"

#endif
