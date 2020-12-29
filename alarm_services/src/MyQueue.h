/*************************************************************************
>  File Name: MyQueue.h
>  Author: zxl
>  Mail:
>  Created Time: 2020-07-14 09:56:56
*************************************************************************/

#ifndef __MYQUEUE_H
#define __MYQUEUE_H

#include <stdbool.h>
#include <stdlib.h>

typedef struct myQueue *myQueueHandle_t;

myQueueHandle_t myQueueCreate(size_t queue_len, size_t item_size);

void myQueueDelete(myQueueHandle_t queue);

size_t myQueueNum(const myQueueHandle_t queue);

size_t myQueueLeftNum(const myQueueHandle_t queue);

size_t myQueueCapacity(const myQueueHandle_t queue);

bool myQueueIsFull(const myQueueHandle_t queue);

bool myQueueIsEmpty(const myQueueHandle_t queue);

bool myQueuePut(myQueueHandle_t queue, const void *buf, size_t num);

bool myQueueGet(myQueueHandle_t queue, void *buf, size_t num);

bool myQueuePeek(const myQueueHandle_t queue, void *buf, size_t num, size_t offset);

bool myQueuePop(myQueueHandle_t queue, size_t num);

bool myQueuePopAll(myQueueHandle_t queue);

#endif
