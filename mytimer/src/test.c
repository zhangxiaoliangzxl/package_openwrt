/*************************************************************************
>  File Name: main.c
>  Author: zxl
>  Mail:
>  Created Time: 2020-12-01 16:32:58
*************************************************************************/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/epoll.h>
#include <sys/resource.h> /*setrlimit */
#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "timer.h"

static int timerfun_callback1( )
{
	printf("timer1 test !\n");
	time_t currentTm = time(NULL);
	puts(asctime(localtime(&currentTm)));
}

static int timerfun_callback2( )
{
	printf("timer2 test !\n");
	time_t currentTm = time(NULL);
	puts(asctime(localtime(&currentTm)));
}

static int timerfun_callback3( )
{
	printf("timer3 test !!!\n");
	time_t currentTm = time(NULL);
	puts(asctime(localtime(&currentTm)));
}

int main(int argc, char *argv[])
{
	int       ret    = 0;
	_ev_timer timer1 = 0, timer2 = 0, timer3 = 0;

	timer_init( );
	timer_loop( );

	printf("%lu %lu %lu\n", timer1, timer2, timer3);

	// timer test
	sleep(1);
	printf("test timer...\n");
	time_t currentTm = time(NULL);
	puts(asctime(localtime(&currentTm)));

	timer_add(&timer1, 1000, timerfun_callback1, NULL, LIMIT_TIMER, 0); // ms
	timer_add(&timer2, 4000, timerfun_callback2, NULL, LIMIT_TIMER, 0); // ms
	timer_add(&timer3, 2000, timerfun_callback3, NULL, CYCLE_TIMER, 0); // ms

	printf("%lu %lu %lu\n", timer1, timer2, timer3);

	sleep(8);
	printf("del timer...\n");
	timer_remove(&timer1);
	timer_remove(&timer2);
	// timer_remove(&timer3);
	printf("%lu %lu %lu\n", timer1, timer2, timer3);

	sleep(10);
	printf("del timer...\n");
	timer_remove(&timer3);

	printf("%lu %lu %lu\n", timer1, timer2, timer3);

	currentTm = time(NULL);
	puts(asctime(localtime(&currentTm)));

	sleep(10);
	currentTm = time(NULL);
	puts(asctime(localtime(&currentTm)));
	printf("set timer...\n");
	timer_add(&timer1, 1000, timerfun_callback1, NULL, CYCLE_TIMER, 0); // ms
	printf("%lu %lu %lu\n", timer1, timer2, timer3);

#if 1
	while (1)
	{
		sleep(60);
	}
#endif

	timer_destroy( );
	return 0;
}
