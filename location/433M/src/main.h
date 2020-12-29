#ifndef __MAIN_H__
#define __MAIN_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "elog.h"
#include "init.h"
#include "ring_buf.h"
#include "send.h"
#include "tty433.h"

#define UNIX_DOMAIN_CMD "/tmp/433M_unix.domain"
#define LOGFILE_NAME "/tmp/433M/log"

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
