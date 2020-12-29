#ifndef __MAIN_H__
#define __MAIN_H__

#include "list.h"
#include <unistd.h>
#include "log.h"

#define READ_LEN 10240
#define msleep(m) usleep(m*1000)

typedef struct config{
	char ip[20];
	int prot; 
	int send_model;
	char curl_data[50];
	int collet_mod;
	char collet_mac[33];
	int send_time;
	int show_mode;
	int disabled;
	char interface[10];
	int getdata_time;
	int min_rssi;
	int max_rssi;
}CONFIG;

typedef struct bluetooth_data{
	char id[33];
	int rssi;
	int lev;
	int num;
	struct list_head list;
}BL_DATA;

struct list_head list1;
struct list_head list2;
struct list_head list3;
struct config *con;
int getdata_time;
int min_rssi;
int max_rssi;

#endif
