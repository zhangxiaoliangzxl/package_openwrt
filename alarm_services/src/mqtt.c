/*************************************************************************
>  File Name: mqtt.c
>  Author: zxl
>  Mail:
>  Created Time: Thu 01 Aug 2019 01:50:31 PM CST
*************************************************************************/

#include "mqtt.h"
#include "common.h"
#include "function.h"
#include "logger.h"

static void my_message_callback(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message)
{
	MYLOG("received a mqtt message !");
	if (message->payloadlen > 0)
	{
		MYLOG("topic  : %s", message->topic);
		MYLOG("payload: ***");
		// MYLOG("payload: %s", message->payload);

		/* message handler */
		my_message_handler(message);
	}
	else
	{
		MYLOG("%s message is null", message->topic);
	}
}

static void my_connect_callback(struct mosquitto *mosq, void *userdata, int result)
{
	int i = 0;
	mqtt_config *mqtt_cfg = (mqtt_config *)userdata;

	if (0 == result)
	{ /* successful */
		if (mqtt_cfg->subscribed == 1)
		{
			MYLOG("mqtt client reconnect successful !");
			/* need unsubscribe topics */
			mosquitto_unsubscribe_multiple(mosq, NULL, mqtt_cfg->topic_count, mqtt_cfg->topics, NULL);
		}
		else
		{
			MYLOG("mqtt client connect successful !");
		}
		/* Subscribe topics on successful connect broker */
		MYLOG("subscribe alarm topics !");
		mosquitto_subscribe_multiple(mosq, NULL, mqtt_cfg->topic_count, mqtt_cfg->topics, mqtt_cfg->qos, 0, NULL);
		mqtt_cfg->subscribed = 1;
	}
	else
	{ /* error */
		MYLOG("mqtt client connect error:%s !", mosquitto_connack_string(result));
	}
}

static void my_subscribe_callback(struct mosquitto *mosq, void *userdata, int mid, int qos_count,
								  const int *granted_qos)
{
	int i;
	MYLOG("Subscribed mid: %d qos: %d", mid, granted_qos[0]);
	for (i = 1; i < qos_count; i++)
	{
		MYLOG("Subscribed mid: %d qos: %d", mid, granted_qos[0]);
	}
}

static void my_log_callback(struct mosquitto *mosq, void *userdata, int level, const char *str)
{
	/* Pring all log messages regardless of level. */
	MYLOG("[Libmqtt] %s", str);
}

static int mqtt_client_opts_set(struct mosquitto *mosq, struct mosq_config *cfg)
{
	/* set mqtt version */
	mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V311);

	/* set username && password */
	if (mosquitto_username_pw_set(mosq, cfg->username, cfg->passwd) != MQTT_ERR_SUCCESS)
	{
		MYLOG("set username and passwd failed !");
		return MQTT_ERR_ERROR;
	}

	return MQTT_ERR_SUCCESS;
}

int cfg_add_sub_topic(struct mosq_config *cfg, char *topic)
{
	if (mosquitto_validate_utf8(topic, strlen(topic)))
	{
		MYLOG("Error: Malformed UTF-8 in argument.");
		return MQTT_ERR_ERROR;
	}

	if (mosquitto_sub_topic_check(topic) == MOSQ_ERR_INVAL)
	{
		MYLOG("Error: Invalid subscription topic '%s', are all '+' and '#' wildcards correct?", topic);
		return MQTT_ERR_ERROR;
	}
	cfg->topic_count++;
	cfg->topics = realloc(cfg->topics, cfg->topic_count * sizeof(char *));
	if (!cfg->topics)
	{
		MYLOG("Error: Out of memory.");
		return MQTT_ERR_ERROR;
	}
	cfg->topics[cfg->topic_count - 1] = strdup(topic);
	MYLOG("add topic: %s", cfg->topics[cfg->topic_count - 1]);
	return MQTT_ERR_SUCCESS;
}

void mqtt_client_config_init(struct mosq_config *cfg)
{
	cfg->keepalive = MQTT_KEEP_ALIVE;
	cfg->clean_session = true;
	cfg->debug = true;
	cfg->qos = MQTT_QOS2;
	cfg->subscribed = 0;
	cfg->topic_count = 0;

	/* init topics malloc addr */
	cfg->topics = malloc(sizeof(char *));
	/* add sub topics */
}

void mqtt_client_config_uninit(struct mosq_config *cfg)
{
	int i = 0;
	if (cfg->topics)
	{
		for (i = 0; i < cfg->topic_count; i++)
		{
			free(cfg->topics[i]);
		}
		free(cfg->topics);
	}
}

int mqtt_client_init(struct mosquitto *mosq, struct mosq_config *cfg)
{
	/* mosquitto option set */
	if (mqtt_client_opts_set(mosq, cfg) != MQTT_ERR_SUCCESS)
	{
		MYLOG("mosquitto option set error !");
		return MQTT_ERR_ERROR;
	}

	/* set callback function */
	mosquitto_connect_callback_set(mosq, my_connect_callback);
	mosquitto_message_callback_set(mosq, my_message_callback);
	if (cfg->debug)
	{
		mosquitto_log_callback_set(mosq, my_log_callback);
		mosquitto_subscribe_callback_set(mosq, my_subscribe_callback);
	}

	return MQTT_ERR_SUCCESS;
}

int mqtt_client_uninit(struct mosquitto *mosq, struct mosq_config *cfg)
{
	if (mosq != NULL)
	{
		mosquitto_destroy(mosq);
	}
	mqtt_client_config_uninit(cfg);
	if (cfg->libinit == 1)
	{
		mosquitto_lib_cleanup();
	}
	return MQTT_ERR_SUCCESS;
}

int mqtt_client_connect(struct mosquitto *mosq, struct mosq_config *cfg)
{
	int rc;
	char *err = NULL;

	rc = mosquitto_connect(mosq, cfg->host, cfg->port, cfg->keepalive);
	if (rc > 0)
	{
		MYLOG("unable to connect mqtt server!");
		if (rc == MOSQ_ERR_ERRNO)
		{
			err = strerror(errno);
			MYLOG("Error: %s", err);
		}
		else
		{
			MYLOG("Error: %s", mosquitto_strerror(rc));
		}

		return rc;
	}

	return MQTT_ERR_SUCCESS;
}

/* must use after call mqtt_client_connect */
int mqtt_client_reconnect(struct mosquitto *mosq)
{
	if (MOSQ_ERR_SUCCESS != mosquitto_reconnect(mosq))
	{
		MYLOG("reconnect mqtt server error !");
		return MQTT_ERR_ERROR;
	}

	return MQTT_ERR_SUCCESS;
}
