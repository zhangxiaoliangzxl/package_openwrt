/*************************************************************************
>  File Name: function.c
>  Author: zxl
>  Mail:
>  Created Time: Fri 02 Aug 2019 02:11:12 PM CST
*************************************************************************/

#include <cjson/cJSON.h>

#include "MyQueue.h"
#include "common.h"
#include "function.h"
#include "ipcmsg.h"
#include "logger.h"
#include "mqtt.h"
#include "utils.h"

extern ALLThread_userdata thread_msgcmd_data;

int init_config(mqtt_config *cfg)
{
	char buf[256] = {0};

	/* get disabled */
	if (get_result_syscmd(GET_DISABLED, buf, sizeof(buf)) != MQTT_ERR_SUCCESS)
	{
		return MQTT_ERR_ERROR;
	}
	if (atoi(buf) == 1)
	{
		MYLOG("==> program switch disabled, exit <==");
		return MQTT_ERR_ERROR;
	}

	/* get host */
	if (get_result_syscmd(GET_HOST, buf, sizeof(buf)) != MQTT_ERR_SUCCESS)
	{
		return MQTT_ERR_ERROR;
	}
	if (strlen(buf) < 1)
	{
		MYLOG("==> config.host is error, exit <==");
		return MQTT_ERR_ERROR;
	}
	else
	{
		snprintf(cfg->host, sizeof(cfg->host), "%s", buf);
	}

	/* get port */
	if (get_result_syscmd(GET_PORT, buf, sizeof(buf)) != MQTT_ERR_SUCCESS)
	{
		return MQTT_ERR_ERROR;
	}
	if (atoi(buf) < 1 || atoi(buf) > 65535)
	{
		MYLOG("==> config.port is error, exit <==");
		return MQTT_ERR_ERROR;
	}
	else
	{
		cfg->port = atoi(buf);
	}

	/* get username */
	if (get_result_syscmd(GET_USERNAME, buf, sizeof(buf)) != MQTT_ERR_SUCCESS)
	{
		return MQTT_ERR_ERROR;
	}
	if (strlen(buf) < 1)
	{
		MYLOG("==> config.username is error, exit <==");
		return MQTT_ERR_ERROR;
	}
	else
	{
		snprintf(cfg->username, sizeof(cfg->username), "%s", buf);
	}

	/* get passwd */
	if (get_result_syscmd(GET_PASSWD, buf, sizeof(buf)) != MQTT_ERR_SUCCESS)
	{
		return MQTT_ERR_ERROR;
	}
	if (strlen(buf) < 1)
	{
		MYLOG("==> config.passwd is error, exit <==");
		return MQTT_ERR_ERROR;
	}
	else
	{
		snprintf(cfg->passwd, sizeof(cfg->passwd), "%s", buf);
	}

	/* get dev mac */
	if (get_result_syscmd(GET_MAC, buf, sizeof(buf)) != MQTT_ERR_SUCCESS)
	{
		return MQTT_ERR_ERROR;
	}
	if (strlen(buf) < 1)
	{
		MYLOG("==> config get dev mac error, exit <==");
		return MQTT_ERR_ERROR;
	}
	else
	{
		snprintf(cfg->id, sizeof(cfg->id), "%s", buf);
	}

	/* dump config info */
	MYLOG("#######################################");
	MYLOG("host    : %s", cfg->host);
	MYLOG("port    : %d", cfg->port);
	MYLOG("username: %s", cfg->username);
	MYLOG("passwd  : %s", cfg->passwd);
	MYLOG("#######################################");

	return MQTT_ERR_SUCCESS;
}

void my_sub_topics_add(struct mosq_config *cfg)
{
	char *topic_str = NULL;
	int topic_str_len = 0;

	MYLOG("config init add sub topics!");
	/* zigbee bcast topic */
	cfg_add_sub_topic(cfg, TOPIC_ZIGBEE_ALL);

	/* zigbee single topic */
	topic_str_len = strlen(TOPIC_ZIGBEE) + strlen(cfg->id) + 1;
	topic_str = malloc(topic_str_len);
	memset(topic_str, 0, topic_str_len);
	sprintf(topic_str, "%s/%s", TOPIC_ZIGBEE, cfg->id);

	cfg_add_sub_topic(cfg, topic_str);

	free(topic_str);
}

static void alarm_msg_handler(cJSON *alarmObject)
{
	cJSON *cmdlist = NULL;
	cJSON *listnode = NULL;

	char cmd[CMD_MAXLEN * 2] = {0};
	int prefix_len = 0;
	int listnum = 0;
	int i = 0;

	if (NULL == alarmObject)
		return;

	MYLOG("find alarm message !");

	/* cmdlist */
	cmdlist = cJSON_GetObjectItem(alarmObject, "cmdlist");
	if (cmdlist != NULL && cmdlist->type == cJSON_Array)
	{
		listnum = cJSON_GetArraySize(cmdlist);
		if (listnum < 1 || listnum > 10)
		{
			MYLOG("cmdlist is null or more then max num!");
		}
		else
		{
			for (i = 0; i < listnum; i++)
			{
				listnode = cJSON_GetArrayItem(cmdlist, i);

				if (NULL == listnode)
				{
					continue;
				}

				if (listnode->type == cJSON_String && strlen(listnode->valuestring))
				{
					if (strlen(listnode->valuestring) < CMD_MAXLEN)
					{
						memset(cmd, 0, sizeof(cmd));
						snprintf(cmd, sizeof(cmd), "UWB \"%s\"", listnode->valuestring);

						pthread_mutex_lock(&thread_msgcmd_data.uwb.mutex);

						if (!myQueuePut(thread_msgcmd_data.uwb.queue, cmd, 1))
						{
							MYLOG("put alarm msg queue fail, maybe queue is full");
						}

						pthread_cond_signal(&thread_msgcmd_data.uwb.cond);
						pthread_mutex_unlock(&thread_msgcmd_data.uwb.mutex);
					}
					else
					{
						MYLOG("cmd value len > %d !", CMD_MAXLEN);
					}
				}
				else
				{
					MYLOG("json array item error !");
				}
			}
		}
	}
}

static void ble_msg_handler(cJSON *bleObject)
{
	cJSON *cmdlist = NULL;
	cJSON *blelist = NULL;
	cJSON *listnode = NULL;

	char cmd[CMD_MAXLEN] = {0};
	int prefix_len = 0;
	int listnum = 0;
	int i = 0;

	if (NULL == bleObject)
		return;

	MYLOG("find ble message !");

	/* cmdlist */
	cmdlist = cJSON_GetObjectItem(bleObject, "cmdlist");
	if (cmdlist != NULL && cmdlist->type == cJSON_Array)
	{
		listnum = cJSON_GetArraySize(cmdlist);
		if (listnum < 1 || listnum > 10)
		{
			MYLOG("cmdlist is null or more then max num!");
		}
		else
		{
			for (i = 0; i < listnum; i++)
			{
				listnode = cJSON_GetArrayItem(cmdlist, i);

				if (NULL == listnode)
				{
					continue;
				}

				if (listnode->type == cJSON_String && strlen(listnode->valuestring))
				{
					if (strlen(listnode->valuestring) < CMD_MAXLEN)
					{
						memset(cmd, 0, sizeof(cmd));
						snprintf(cmd, sizeof(cmd), "%s", listnode->valuestring);

						pthread_mutex_lock(&thread_msgcmd_data.ble.mutex);

						if (!myQueuePut(thread_msgcmd_data.ble.queue, cmd, 1))
						{
							MYLOG("put ble msg queue fail, maybe queue is full");
						}

						pthread_cond_signal(&thread_msgcmd_data.ble.cond);
						pthread_mutex_unlock(&thread_msgcmd_data.ble.mutex);
					}
					else
					{
						MYLOG("ble msg value len > %d !", CMD_MAXLEN);
					}
				}
				else
				{
					MYLOG("json array item error !");
				}
			}
		}
	}
}

/* my mqtt message handler */
void my_message_handler(const struct mosquitto_message *message)
{
	cJSON *root = NULL, *object = NULL;
	char *msg = NULL;

	msg = malloc(message->payloadlen);
	memset(msg, 0, message->payloadlen);
	memcpy(msg, message->payload, message->payloadlen);

	root = cJSON_Parse(msg);
	if (root == NULL)
	{
		MYLOG("message json parse error, not a json message !");
		goto ERROR;
	}

	/* alarm object */
	if ((object = cJSON_GetObjectItem(root, "alarm")) != NULL)
	{
		alarm_msg_handler(object);
	}
	else if ((object = cJSON_GetObjectItem(root, "ble")) != NULL)
	{
		ble_msg_handler(object);
	}
	else
	{
		/**/
	}

	/* other object ... */

ERROR:
	if (NULL != root)
	{
		cJSON_Delete(root);
	}
	free(msg);
	return;
}

void *thread_CmdExecute(void *indata)
{
	int locked = 0;
	int ret = 0;

	ALLThread_userdata *data = (ALLThread_userdata *)indata;
	char *cmd = malloc(CMD_MAXLEN * 2);

	MYLOG("msg queue handle running ...");

	while (true)
	{
		memset(cmd, 0, CMD_MAXLEN * 2);
		ret = myQueueGet(data->uwb.queue, cmd, 1);

		if (ret <= 0)
		{
			pthread_mutex_lock(&data->uwb.mutex);
			locked = 1;

			pthread_cond_wait(&data->uwb.cond, &data->uwb.mutex);
		}
		else
		{
			if (locked)
			{
				pthread_mutex_unlock(&data->uwb.mutex);
			}

			/* system cmd */
			MYLOG("queue cmd:(%s)", cmd);
			system(cmd);
			/* wait for zigbee */
			usleep(WAITTIME);
		}
	}
}

void *thread_BLECmdExecute(void *indata)
{
	int locked = 0;
	int ret = 0;

	struct msg_st msgdata;
	ALLThread_userdata *data = (ALLThread_userdata *)indata;
	char *cmd = malloc(CMD_MAXLEN * 2);

	MYLOG("ble msg queue handle running ...");

	while (true)
	{
		memset(cmd, 0, CMD_MAXLEN * 2);
		ret = myQueueGet(data->ble.queue, cmd, 1);

		if (ret <= 0)
		{
			pthread_mutex_lock(&data->ble.mutex);
			locked = 1;

			pthread_cond_wait(&data->ble.cond, &data->ble.mutex);
		}
		else
		{
			if (locked)
			{
				pthread_mutex_unlock(&data->ble.mutex);
			}
#if 0
			/* system cmd */
			MYLOG("queue cmd:(%s)", cmd);
			system(cmd);
#else
			/* put blelink msglist */
			memset(&msgdata, 0, sizeof(struct msg_st));
			msgdata.msg_type = MSG_TYPE_BLE;
			msgdata.msg_data.len = strlen(cmd);
			memcpy(msgdata.msg_data.data, cmd, msgdata.msg_data.len);

			if (msgsnd(data->ipcmsgid, (void *)&msgdata, sizeof(struct ipcmsg_t), IPC_NOWAIT) < 0)
			{
				MYLOG("put msg to blelink fail, queue full !");
			}
#endif
		}
	}
}
