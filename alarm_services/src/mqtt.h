/*************************************************************************
>  File Name: mqtt.h
>  Author: zxl
>  Mail:
>  Created Time: Thu 01 Aug 2019 01:50:27 PM CST
*************************************************************************/

#ifndef _MQTT_H
#define _MQTT_H

#include <mosquitto.h>

#define MQTT_KEEP_ALIVE 30

#define MQTT_QOS0 0
#define MQTT_QOS1 1
#define MQTT_QOS2 2

typedef struct mosq_config
{
	char id[32];
	char host[128];
	char username[32];
	char passwd[32];
	int port;
	int keepalive;
	int libinit;
	bool clean_session;
	bool debug;
	int qos;
	int subscribed;  /* sub */
	char **topics;   /* sub */
	int topic_count; /* sub */
} mqtt_config;

int cfg_add_sub_topic(struct mosq_config *cfg, char *topic);
void mqtt_client_config_init(struct mosq_config *cfg);
void mqtt_client_config_uninit(struct mosq_config *cfg);
int mqtt_client_init(struct mosquitto *mosq, struct mosq_config *cfg);
int mqtt_client_uninit(struct mosquitto *mosq, struct mosq_config *cfg);
int mqtt_client_connect(struct mosquitto *mosq, struct mosq_config *cfg);
int mqtt_client_reconnect(struct mosquitto *mosq);

#endif
