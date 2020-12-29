#ifndef __INIT_H__
#define __INIT_H__

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#include "func.h"
#include "logs.h"
#include "maclist.h"
#include "mcurl.h"

#include <pthread.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#define LISTEN_PORT 59001
#define SEND_PORT 59000

#define UWB_JIFFIES "/tmp/uwb/data_jiffies"

#define ALARM_STATE "/tmp/alarm_state"
#define STATUS_PATH "/tmp/ac/status"

#define BUFSIZE 4096			  //缓存大小
#define ACVERSION "20151028V101t" // AC版本
#define MACLEN 18
#define IPLEN 18
#define LITTLEBUF 32
#define BUF 4094

/* the type of the system  */
#define FAT 2
#define FIT 1
#define GATE 3

#define ERRORCODE "code"
#define DESCRIPTION "msg"

/*
#define ERRORCODE "errorcode"
#define DESCRIPTION "description"
*/

typedef struct linearg
{
	char apmac[20];
	LinkList L;
	int disabled;
	int rssi;
	int encryption;
	char *cloudinterface;
} Linearg;

Linearg marg;

char *order;

extern int count(char *cmd);
extern int gainWific(void);
extern cJSON *init(int type);
extern cJSON *getwireless(void);
extern int getVlanNum(void);

extern int switch_vlan_num;
extern int wifi_iface_num;
extern int interface_num;
extern int delc;

#endif
