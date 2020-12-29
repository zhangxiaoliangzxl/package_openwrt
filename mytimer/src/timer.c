/*************************************************************************
>  File Name: mytimer.c
>  Author: zxl
>  Mail:
>  Created Time: 2020-12-01 16:32:09
*************************************************************************/
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

#include "timer.h"

static struct min_heap _min_heap;
static int             pipe_fd[2];
static pthread_t       thread_loop;

static int timer_run     = 0;
static int timer_fd      = 0;
static int timer_epollfd = 0;

static inline void epoll_wakeup( )
{
	if ((&_min_heap)->n == 1)
		write(pipe_fd[1], "0", 1);
}

/* pipe init */
static void timer_pipeinit( )
{
	pipe(pipe_fd);
}

/* init epoll */
static int timer_epollinit( )
{
	timer_epollfd = epoll_create(EPOLL_SIZE);
	if (timer_epollfd < 0)
	{
		perror("timer epoll create fail !\n");
		return -1;
	}

	return timer_epollfd;
}

static int timer_timerfdinit( )
{
	timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (timer_fd < 0)
	{
		perror("timer timerfd create fail !\n");
		return -1;
	}

	return timer_fd;
}

static int timer_process( )
{
	struct event *  event;
	struct timeval  now;
	struct timespec ts;
	int             ret = 0;

	while ((event = min_heap_top_(&_min_heap)) != NULL)
	{
		gettime(&now, &ts);
		if (evutil_timercmp(&now, &(event->ev_timeout), <))
			break;

		min_heap_pop_(&_min_heap);

		/* timer function callback */
#ifdef TIMER_DEBUG
		printf("timer_id %lu callback !\n", event->timer_id);
#endif
		ret = event->ev_callback(event->ev_arg);

		if (ret == 0) // kill timer
		{
			event->ev_flags   = LIMIT_TIMER;
			event->ev_exe_num = 0;
		}

		if (event->ev_flags == CYCLE_TIMER || (event->ev_flags == LIMIT_TIMER && --event->ev_exe_num > 0))
		{
			evutil_timeradd(&(event->ev_timeout), &(event->ev_interval), &(event->ev_timeout));
			min_heap_push_(&_min_heap, event);
		}
		else
		{
			*event->timer = 0;
			free(event);
		}
	}

	return 0;
}

static void *timer_epoll_loop(void *data)
{
	int       eventNum = 0;
	int       i        = 0;
	long      timeout  = -1;
	int       tmpfd    = 0;
	uint64_t  tmpExp   = 0;
	long long ms       = 0;

	struct itimerspec  new_value;
	struct epoll_event events[EPOLL_SIZE];

	struct event *  event;
	struct timeval  tv;
	struct timeval *tvp = NULL;
	struct timespec ts;

	while (timer_run)
	{
#ifdef TIMER_DEBUG
		printf("timer_epoll_loop wakeup !\n");
#endif
		if ((event = min_heap_top_(&_min_heap)) != NULL)
		{
			gettime(&tv, &ts);
			tvp = &tv;
			/* How many milliseconds we need to wait for the next time event to fire? */
			ms = (event->ev_timeout.tv_sec - tv.tv_sec) * 1000 + (event->ev_timeout.tv_usec - tv.tv_usec) / 1000;

			if (ms > 0)
			{
				tvp->tv_sec  = ms / 1000;
				tvp->tv_usec = (ms % 1000) * 1000;
			}
			else
			{
				tvp->tv_sec  = 0;
				tvp->tv_usec = 0;
			}
		}
		else
		{
			tvp = NULL;
		}

		if (tvp != NULL)
		{
			if (ms > 0)
			{
#ifdef TIMER_DEBUG
				printf("next timer wait:%ld\n", tvp->tv_sec * 1000 + tvp->tv_usec / 1000);
#endif
				/* set next timerfd */
				/*init time*/
				new_value.it_value.tv_sec  = tvp->tv_sec;
				new_value.it_value.tv_nsec = tvp->tv_usec * 1000;
				/*time interval*/
				new_value.it_interval.tv_sec  = tvp->tv_sec;
				new_value.it_interval.tv_nsec = tvp->tv_usec * 1000;

				timerfd_settime(timer_fd, 0, &new_value, NULL);
			}
			else
			{
				timer_process( );
			}
		}
		else
		{
			/*init time*/
			new_value.it_value.tv_sec  = 0;
			new_value.it_value.tv_nsec = 0;
			/*time interval*/
			new_value.it_interval.tv_sec  = 0;
			new_value.it_interval.tv_nsec = 0;

			timerfd_settime(timer_fd, 0, &new_value, NULL);
		}

		eventNum = epoll_wait(timer_epollfd, events, EPOLL_SIZE, timeout);

		/* handle Events */
		for (i = 0; i < eventNum; ++i)
		{
			int tmpfd = events[i].data.fd;
			if (events[i].events & EPOLLIN)
			{
				if (timer_fd == tmpfd)
				{
					/*handle timer_fd*/
					tmpExp = 0;
					/*must read*/
					read(timer_fd, &tmpExp, sizeof(uint64_t));
#ifdef TIMER_DEBUG
					printf("epoll wait wakeup by timer\n");
#endif
				}
				else if (pipe_fd[0] == tmpfd)
				{
					tmpExp = 0;
					/*must read*/
					read(pipe_fd[0], &tmpExp, sizeof(uint64_t));
#ifdef TIMER_DEBUG
					printf("epoll wait wakeup by pipe\n");
#endif
				}
			}
		}

		timer_process( );
	}

	return NULL;
}

void timer_loop( )
{
	/* creat loop thread */
	pthread_create(&thread_loop, NULL, timer_epoll_loop, NULL);
	pthread_detach(thread_loop);
}

void timer_init( )
{
	struct epoll_event ev;

	min_heap_ctor_(&_min_heap);
	timer_epollinit( );
	timer_timerfdinit( );
	timer_pipeinit( );
	timer_run = TRUE;

	ev.events  = EPOLLIN | EPOLLHUP | EPOLLRDHUP;
	ev.data.fd = timer_fd;
	epoll_ctl(timer_epollfd, EPOLL_CTL_ADD, timer_fd, &ev);

	ev.events  = EPOLLIN;
	ev.data.fd = pipe_fd[0];
	epoll_ctl(timer_epollfd, EPOLL_CTL_ADD, pipe_fd[0], &ev);
}

void timer_destroy( )
{
	int i   = 0;
	int ret = 0;

	timer_run = FALSE;

	/* cancel thread */
	// pthread_join(thread_loop, NULL);
	do
	{
		ret = pthread_cancel(thread_loop);
	} while (ret != 0);

	for (i = 0; i < _min_heap.n; i++)
	{
		free(_min_heap.p[i]);
	}
	min_heap_dtor_(&_min_heap);

	/* closed fd */
	if (timer_epollfd)
	{
		close(timer_epollfd);
	}
	if (timer_fd)
	{
		close(timer_fd);
	}
	if (pipe_fd[0])
	{
		close(pipe_fd[0]);
	}
	if (pipe_fd[1])
	{
		close(pipe_fd[1]);
	}
}

/* = CYCLE_TIMER */
unsigned int timer_add(_ev_timer *timer, int interval, int (*fun)(void *), void *arg, int flag, int exe_num)
{
	struct itimerspec new_value;
	struct event *    ev = ( struct event * )malloc(sizeof(struct event));
	min_heap_elem_init_(ev);
	if (NULL == ev)
		return 0;
	struct timeval  now;
	struct timespec ts;
	gettime(&now, &ts);
	ev->ev_interval.tv_sec  = interval / 1000;
	ev->ev_interval.tv_usec = (interval % 1000) * 1000;
	evutil_timeradd(&now, &(ev->ev_interval), &(ev->ev_timeout));
	ev->ev_flags    = flag;
	ev->ev_callback = fun;
	ev->ev_arg      = arg;
	ev->ev_exe_num  = exe_num;
	ev->timer_id    = ( _ev_timer )ev;
	ev->timer       = timer;
	*timer          = ev->timer_id;

#ifdef TIMER_DEBUG
	printf("add timer_id %lu !\n", *timer);
#endif
	min_heap_push_(&_min_heap, ev);

	/* wakeup epoll_wait */
	epoll_wakeup( );

	return ev->timer_id;
}

int timer_remove(_ev_timer *timer)
{
	if (*timer == 0)
		return 0;

	int i = 0;
	for (i = 0; i < _min_heap.n; i++)
	{
		if (*timer == _min_heap.p[i]->timer_id)
		{
#ifdef TIMER_DEBUG
			printf("del timer_id %lu !\n", *timer);
#endif
			struct event *e = _min_heap.p[i];
			min_heap_erase_(&_min_heap, _min_heap.p[i]);
			free(e);
			*timer = 0;
			return 1;
		}
	}
	return 0;
}
