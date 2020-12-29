#ifndef __INIT_H__
#define __INIT_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tty433.h"

#define DISABLED "uci get 433Mcon.con.disabled | tr -d '\n'"
#define IP "uci get 433Mcon.con.ip 2>/dev/null | tr -d '\n'"
#define PORT "uci get 433Mcon.con.port 2>/dev/null | tr -d '\n'"
#define TTY "uci get 433Mcon.con.tty 2>/dev/null | tr -d '\n'"
#define PRINT_ENABLE "uci get 433Mcon.con.printdata 2>/dev/null | tr -d '\n'"
#define MAC "cat /sys/class/net/eth0/address 2>/dev/null | tr -d '\n'"

int init(config *);

#endif
