#ifndef __US_LIST_H__
#define __US_LIST_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "main.h"
#include "list.h"
#include "log.h"
#include "cJSON.h"
#include "systime.h"

#define REPEAT 0
#define DIS_REPEAT 0
#define SET_DEV_ID "cat /sys/class/net/eth0/address | tr -d '\n'"

void Initialization();
int list_ret();
void insert_list(BL_DATA *, int); /*加入链表*/
void delet_list(int);		/*删除链表*/
int copy_list();			/*拷贝链表*/
BL_DATA *cp_list_data(BL_DATA *);
/*删除指定某一个*/
void delete_one(char *);
void addlist3();
int list_null(int); /*判断某个链表是否为空*/
int json_data(char *, int);
void show(int);

#endif
