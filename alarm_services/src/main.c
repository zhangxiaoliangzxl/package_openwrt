/*************************************************************************
>  File Name: main.c
>  Author: zxl
>  Mail:
>  Created Time: Wed 31 Jul 2019 05:42:28 PM CST
*************************************************************************/
#include <errno.h>
#include <pthread.h>
#include <signal.h>

#include "MyQueue.h"
#include "common.h"
#include "fast2date.h"
#include "function.h"
#include "ipcmsg.h"
#include "logger.h"
#include "mqtt.h"
#include "utils.h"

typedef enum
{
	run_start = 0,
	run_mqtt_init,
	run_mqtt_connect,
	run_mqtt_reconnect,
	run_mqtt_loop,
	run_end
} run_status;

struct mosq_config my_mqttcfg;
struct mosquitto *my_mosq = NULL;

// Thread_userdata thread_msgcmd_data;
ALLThread_userdata thread_msgcmd_data;

static void my_int_handler(int signum)
{
	MYLOG("exit code %d, ctrl+c ", signum);
	mqtt_client_uninit(my_mosq, &my_mqttcfg);
	exit(-1);
}

static void my_term_handler(int signum)
{
	MYLOG("exit code %d, by term killed", signum);
	mqtt_client_uninit(my_mosq, &my_mqttcfg);
	exit(-1);
}

static void my_hup_handler(int signum)
{
	MYLOG("exit code %d", signum);
	mqtt_client_uninit(my_mosq, &my_mqttcfg);
	exit(-1);
}

static void my_segv_handler(int signum)
{
	MYLOG("exit code %d, segmentation fault or out of memory", signum);
	mqtt_client_uninit(my_mosq, &my_mqttcfg);
	exit(-1);
}

/* thread func: get mosquitto client state */
static void *thread_func_cs_state(void *usrdata)
{
	if (NULL == usrdata)
		return NULL;

	int cs_state = 0;
	char cmd_buf[1024] = {0};
	struct mosquitto *mosq = (struct mosquitto *)usrdata;

	while (true)
	{
		cs_state = mosquitto_client_state_get(mosq);
		// MYLOG(">>> mosq client state %d", cs_state);

		if (cs_state != 1)
		{
			cs_state = 0;
		}

		/* write to state files */
		memset(cmd_buf, 0, sizeof(cmd_buf));
		sprintf(cmd_buf, "echo %d > %s", cs_state, ALARM_STATE);
		system(cmd_buf);

		sleep(5);
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	int loop = 1;
	int ret = 0;

	struct mosq_config *mqtt_cfg = &my_mqttcfg;
	struct mosquitto *mosq = my_mosq;

	pthread_t thread_cs_state;

	/* uwb */
	myQueueHandle_t cmdQueue;
	pthread_t thread_msgcmd;
	/* ble */
	myQueueHandle_t bleQueue;
	pthread_t thread_msgble;

	run_status main_status = run_start;

	/* init logger */
	my_time_init();

	mqtt_cfg->libinit = 0;
	/* signal handler */
	signal(SIGINT, my_int_handler);
	signal(SIGTERM, my_term_handler);
	signal(SIGHUP, my_hup_handler);
	signal(SIGSEGV, my_segv_handler);

	/* init ipc msg */
	key_t ipcmsgkey = ftok(IPC_PATHNAME, IPC_PROJECTID);
	int ipcmsgid = msgget(ipcmsgkey, 0666 | IPC_CREAT);
	if (ipcmsgid == -1)
	{
		MYLOG("msgget failed width error: %d", errno);
		exit(EXIT_FAILURE);
	}

	thread_msgcmd_data.ipcmsgid = ipcmsgid;

	/* main loop */
	loop = 1;
	while (loop)
	{
		switch (main_status)
		{
		case run_start:
			/* init config */
			MYLOG("=========== run status is run_start ==========");
			if (MQTT_ERR_SUCCESS != init_config(mqtt_cfg))
			{
				MYLOG("init_config error, go end!");
				main_status = run_end;
			}
			else
			{
				main_status = run_mqtt_init;
			}

			/* uwb msg cmd thread */
			thread_msgcmd_data.uwb.queue = myQueueCreate(CMD_QUEUE_NUM, CMD_MAXLEN * 2);

			pthread_mutex_init(&thread_msgcmd_data.uwb.mutex, NULL);
			pthread_cond_init(&thread_msgcmd_data.uwb.cond, NULL);

			ret = pthread_create(&thread_msgcmd, NULL, thread_CmdExecute, (void *)(&thread_msgcmd_data));
			if (ret != 0)
			{
				MYLOG("uwb msg cmd thread create failed!");
				main_status = run_end;
				break;
			}
			else
			{
				pthread_detach(thread_msgcmd);
				main_status = run_mqtt_init;
			}

			/* ble msg cmd thread */
			thread_msgcmd_data.ble.queue = myQueueCreate(CMD_QUEUE_NUM, CMD_MAXLEN);

			pthread_mutex_init(&thread_msgcmd_data.ble.mutex, NULL);
			pthread_cond_init(&thread_msgcmd_data.ble.cond, NULL);

			ret = pthread_create(&thread_msgble, NULL, thread_BLECmdExecute, (void *)(&thread_msgcmd_data));
			if (ret != 0)
			{
				MYLOG("ble msg cmd thread create failed!");
				main_status = run_end;
			}
			else
			{
				pthread_detach(thread_msgble);
				main_status = run_mqtt_init;
			}

			break;
		case run_mqtt_init:
			/* mqtt client init */
			MYLOG("======== run status is run_mqtt_init =========");
			/* mqtt config init */
			mqtt_client_config_init(mqtt_cfg);

			/* init libmosquitto */
			mosquitto_lib_init();
			mqtt_cfg->libinit = 1;

			/* creat new mosquitto */
			MYLOG("client id %s", mqtt_cfg->id);
			mosq = mosquitto_new(mqtt_cfg->id, mqtt_cfg->clean_session, mqtt_cfg);
			if (NULL == mosq)
			{
				MYLOG("create new mqtt client failed !");
				if (errno == ENOMEM)
				{
					MYLOG("Error: Out of memory");
				}
				else if (errno == EINVAL)
				{
					MYLOG("Error: Invalid id and/or clean_session");
				}
				main_status = run_end;
			}
			else
			{
				mqtt_client_init(mosq, mqtt_cfg);
				/* add sub topics */
				my_sub_topics_add(mqtt_cfg);

				/* mosquitto client state thread */
				ret = pthread_create(&thread_cs_state, NULL, thread_func_cs_state, (void *)mosq);
				if (ret != 0)
				{
					MYLOG("cs_state thread create failed!");
					main_status = run_end;
				}
				else
				{
					pthread_detach(thread_cs_state);
					main_status = run_mqtt_connect;
				}
			}
			break;
		case run_mqtt_connect:
			/* connect to server */
			MYLOG("====== run status is run_mqtt_connect ========");
			if (mqtt_client_connect(mosq, mqtt_cfg) != MQTT_ERR_SUCCESS)
			{
				MYLOG("mqtt client connect failed, wait reconnect !");
				main_status = run_mqtt_reconnect;
				sleep(5);
			}
			else
			{
				main_status = run_mqtt_loop;
			}
			break;
		case run_mqtt_reconnect:
			/* reconnect to server */
			MYLOG("====== run status is run_mqtt_reconnect ======");
			if (mqtt_client_reconnect(mosq) != MQTT_ERR_SUCCESS)
			{
				MYLOG("mqtt client reconnect failed, wait reconnect !");
				main_status = run_mqtt_reconnect;
				sleep(5);
			}
			else
			{
				main_status = run_mqtt_loop;
			}
			break;
		case run_mqtt_loop:
			/* mqtt loop */
			MYLOG("======== run status is run_mqtt_loop =========");
			mosquitto_loop_forever(mosq, -1, 1);
			main_status = run_end;
			break;
		case run_end:
			MYLOG("=========== run status is run_end ============");
			MYLOG("main status is end !");
			loop = 0;
			break;
		default:
			MYLOG("========= unkwon run status, go end ==========");
			loop = 0;
			break;
		}
	}

	/* mqtt client uninit */
	mqtt_client_uninit(mosq, mqtt_cfg);

	/* thread_cs_state cancel */
	ret = -1;
	do
	{
		ret = pthread_cancel(thread_cs_state);
	} while (ret != 0);

	ret = -1;
	do
	{
		ret = pthread_cancel(thread_msgcmd);
	} while (ret != 0);

	ret = -1;
	do
	{
		ret = pthread_cancel(thread_msgble);
	} while (ret != 0);

	myQueueDelete(thread_msgcmd_data.uwb.queue);
	myQueueDelete(thread_msgcmd_data.ble.queue);

	return 1;
}
