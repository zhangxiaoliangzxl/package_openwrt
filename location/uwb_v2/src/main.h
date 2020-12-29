#ifndef __MAIN_H__
#define __MAIN_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "init.h"
#include "log.h"
#include "ring_buf.h"
#include "send.h"
#include "tty_ppp.h"
#include "uwb.h"

#define DISABLED "uci get uwbcon.con.disabled | tr -d '\n'"
#define PRINT "uci get uwbcon.con.print | tr -d '\n'"

#define UNIX_DOMAIN "/tmp/uwb/socket.domain"

typedef enum
{
	start = 0,
	serail,
	tcp,
	senddata,
	readdata,
	end
} runstats;

typedef enum
{
	uwb_start = 0,
	uwb_creat,
	uwb_send,
	uwb_end
} uwbstats;

typedef enum
{
	debug_start = 0,
	debug_creat,
	debug_send,
	debug_end
} debugstats;

void Free_Thread_data(Thread_data data);

#endif
