#include "pthread.h" 
#include "log.h"

/* 工作者线程函数, 从任务链表中取出任务并执行 */
static void* thread_routine(void *arg)
{
    pool_work_t *work;
    while(1) {
            pthread_mutex_lock(&pool->queue_lock);
            while(!pool->queue_head && !pool->shutdown) {
                pthread_cond_wait(&pool->queue_ready, &pool->queue_lock);
            }
            if (pool->shutdown) {
                    pthread_mutex_unlock(&pool->queue_lock);
                    pthread_exit(NULL);
            }
                    
            work = pool->queue_head;
            pool->queue_head = pool->queue_head->next;
            pthread_mutex_unlock(&pool->queue_lock);
            
            work->routine(work->arg);
            free(work);
    }
    return NULL;    
}

/*
 * 创建线程池 
 */
int pool_create(int max_thr_num)
{
    int i;
    
    pool = calloc(1, sizeof(pool_t));
    if (!pool) {
            printf("calloc failed\n");
            exit(1);
    }
    
    /* 初始化 */
    pool->max_thr_num = max_thr_num; //最大线程数
    pool->shutdown = 0;              //线程是否销毁 
    pool->queue_head = NULL;         //链表头
    
    if (pthread_mutex_init(&pool->queue_lock, NULL) !=0) {
             printf("pthread_mutex_init failed, errno:%d, error:%s\n", errno, strerror(errno));
             exit(1);
    }
    
    if (pthread_cond_init(&pool->queue_ready, NULL) !=0 ) {
            printf("pthread_cond_init failed, errno:%d, error:%s\n", errno, strerror(errno));
            exit(1);
    }
    
    /* 创建工作者线程 */
    pool->thr_id = calloc(max_thr_num, sizeof(pthread_t));
    if (!pool->thr_id) {
            printf("calloc failed\n");
            exit(1);
    }
    
    for (i = 0; i < max_thr_num; ++i) {
            if (pthread_create(&pool->thr_id[i], NULL, thread_routine, NULL) != 0){
                    printf("pthread_create failed, errno:%d, error:%s\n", errno, strerror(errno));
                    exit(1);
            }    
    }
    
    return 0;
}
                                        
/* 销毁线程池 */
void pool_destroy()
{
    printf("destruction the thread_pool\n");
    int i;
    pool_work_t *member;
    
    if (pool->shutdown) {
             return;
    }
    pool->shutdown = 1;
    
    pthread_mutex_lock(&pool->queue_lock);
    pthread_cond_broadcast(&pool->queue_ready);
    pthread_mutex_unlock(&pool->queue_lock);
    for (i = 0; i < pool->max_thr_num; ++i) {
            pthread_join(pool->thr_id[i], NULL);
    }
    free(pool->thr_id);
    
    while(pool->queue_head) {
            member = pool->queue_head;
            pool->queue_head = pool->queue_head->next;
            free(member);
    }
    
    pthread_mutex_destroy(&pool->queue_lock);    
    pthread_cond_destroy(&pool->queue_ready);
    
    free(pool);    
}

int pool_add_work(void*(*routine)(void*), void *arg)
{
    pool_work_t *work, *member;
    
    if (!routine){
            printf("%s:Invalid argument\n", __FUNCTION__);
            return -1;
    }
            
    work = malloc(sizeof(pool_work_t));
    if (!work) {
            printf("%s:malloc failed\n", __FUNCTION__);
            return -1;
    }
    
    work->routine = routine;
    work->arg = arg;
    work->next = NULL;
    
    pthread_mutex_lock(&pool->queue_lock);   //上锁 
    member = pool->queue_head;
    if (!member) {
            pool->queue_head = work;
    } 
    else {
            while(member->next) {
                    member = member->next;
            }
            member->next = work;
    }    
    /* 通知工作者线程，有新任务添加 */
    pthread_cond_signal(&pool->queue_ready);
    pthread_mutex_unlock(&pool->queue_lock);
    
    return 0;   
}

