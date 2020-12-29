#ifndef __PTHRAD_H__
#define __PTHRAD_H__

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#define THREAD_NUM 3

typedef struct pool_work {
    void*               (*routine)(void*);  
	void                *arg;               
	struct pool_work   *next;                    
}pool_work_t;

typedef struct pool {
   int             shutdown;               
   int             max_thr_num;            
   pthread_t       *thr_id;                
   pool_work_t    *queue_head;             
   pthread_mutex_t queue_lock;                    
   pthread_cond_t  queue_ready;    
}pool_t;

int  pool_create(int max_thr_num);
void pool_destroy();
int pool_add_work(void*(*routine)(void*), void *arg);
static pool_t *pool = NULL;
void *hello(void *);

#endif
