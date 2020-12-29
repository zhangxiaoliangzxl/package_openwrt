/*************************************************************************
>  File Name: function.h
>  Author: zxl
>  Mail:
>  Created Time: Fri 02 Aug 2019 02:11:18 PM CST
*************************************************************************/

#ifndef _FUNCTION_H
#define _FUNCTION_H

#include <pthread.h>
#include "MyQueue.h"
#include "mqtt.h"

#define CMD_QUEUE_NUM 512
#define CMD_MAXLEN 128

#define WAITTIME 500 * 1000 // 500ms

typedef struct thread_userdata_t
{
	myQueueHandle_t queue;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
#if 0
	pthread_condattr_t conda;
#endif
} Thread_userdata;

typedef struct allthread_userdata_t
{
	int ipcmsgid;
	struct thread_userdata_t uwb;
	struct thread_userdata_t ble;
} ALLThread_userdata;

int init_config(mqtt_config *cfg);
void my_sub_topics_add(struct mosq_config *cfg);
void my_message_handler(const struct mosquitto_message *message);
void *thread_CmdExecute(void *indata);
void *thread_BLECmdExecute(void *indata);

#endif
