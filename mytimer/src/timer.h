/*************************************************************************
>  File Name: mytimer.h
>  Author: zxl
>  Mail:
>  Created Time: 2020-12-01 16:34:08
*************************************************************************/

#ifndef _MYTIMER_H
#define _MYTIMER_H

#include "minheap-internal.h"
/* for test debug */
//#define TIMER_DEBUG

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define LIMIT_TIMER 1
#define CYCLE_TIMER 2

#define EPOLL_SIZE 1024

typedef unsigned long _ev_timer;
/*
typedef struct evtimer
{
	struct event *ev;
} _ev_timer;
*/

extern void timer_init( );
extern void timer_destroy( );
extern void timer_loop( );
extern int  timer_remove(_ev_timer *timer);

extern unsigned int timer_add(_ev_timer *timer, int interval, int (*fun)(void *), void *arg, int flag, int exe_num);

#endif
