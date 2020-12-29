#ifndef __INIT_H__
#define __INIT_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "uwb.h"

#define IP "uci get uwbcon.con.ip 2>/dev/null | tr -d '\n'"
#define PORT "uci get uwbcon.con.port 2>/dev/null | tr -d '\n'"
#define TTY "uci get uwbcon.con.tty 2>/dev/null | tr -d '\n'"
#define PRINT_ENABLE "uci get uwbcon.con.printdata 2>/dev/null | tr -d '\n'"
#define TCP_NAGLE "uci get uwbcon.con.tcp_nagle 2>/dev/null | tr -d '\n'"
#define DEBUG_ENABLE "uci get uwbcon.con.debug_enable 2>/dev/null | tr -d '\n'"
#define DEBUG_SERVERIP "uci get uwbcon.con.debug_serverip 2>/dev/null | tr -d '\n'"
#define DEBUG_SERVERPORT "uci get uwbcon.con.debug_serverport 2>/dev/null | tr -d '\n'"

#define MAC "cat /sys/class/net/eth0/address 2>/dev/null | tr -d '\n'"

#define UWB_MODE "uci get uwbcon.uwb.mode 2>/dev/null | tr -d '\n'"
#define UWB_LOCALID "uci get uwbcon.uwb.localid 2>/dev/null | tr -d '\n'"
#define UWB_MATID "uci get uwbcon.uwb.matid 2>/dev/null | tr -d '\n'"
#define UWB_CH "uci get uwbcon.uwb.ch 2>/dev/null | tr -d '\n'"
#define UWB_PANID "uci get uwbcon.uwb.panid 2>/dev/null | tr -d '\n'"
#define UWB_PCODE "uci get uwbcon.uwb.pcode 2>/dev/null | tr -d '\n'"
#define UWB_PALNA "uci get uwbcon.uwb.palna 2>/dev/null | tr -d '\n'"
#define UWB_COARSEGAIN "uci get uwbcon.uwb.coarsegain 2>/dev/null | tr -d '\n'"
#define UWB_FINEGAIN "uci get uwbcon.uwb.finegain 2>/dev/null | tr -d '\n'"
#define UWB_ROLE "uci get uwbcon.uwb.role 2>/dev/null | tr -d '\n'"

int init(config *);
int save_uwb_config(config *con);

#endif
