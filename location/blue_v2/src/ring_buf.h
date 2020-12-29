#ifndef __RBUF_H_
#define __RBUF_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>

typedef struct ring_buffer_t
{
	unsigned int Depth;
	unsigned int Head;
	unsigned int Tail;
	unsigned int Counter;
	unsigned int ElementBytes;
	void *Buff;
} Rbuf_Type;

void Rbuf_Init(Rbuf_Type *pBuf, void *pBuffer, unsigned int elementBytes, unsigned int depth);

void Rbuf_Clear(Rbuf_Type *pBuf);

void Rbuf_Free(Rbuf_Type *pBuf);

unsigned char Rbuf_AddOne(Rbuf_Type *pBuf, void *pValue);

unsigned int Rbuf_Add(Rbuf_Type *pBuf, void *pValues, unsigned int bytesToAdd);

unsigned char Rbuf_GetOne(Rbuf_Type *pBuf, void *pValue);

unsigned int Rbuf_Get(Rbuf_Type *pBuf, void *pValues, unsigned int bytesToRead);

unsigned char Rbuf_IsEmpty(Rbuf_Type *pBuf);

unsigned char Rbuf_IsFull(Rbuf_Type *pBuf);

#endif
