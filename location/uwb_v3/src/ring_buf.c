#include "ring_buf.h"

/********************************************************************
 * ring buffer init
 *********************************************************************/
void Rbuf_Init(Rbuf_Type *pBuf, void *pBuffer, unsigned int elementBytes, unsigned int depth)
{
	pBuf->ElementBytes = elementBytes;
	pBuf->Depth = depth;
	pBuf->Head = 0;
	pBuf->Tail = 0;
	pBuf->Counter = 0;
	pBuf->Buff = pBuffer;
}

void Rbuf_Clear(Rbuf_Type *pBuf)
{
	pBuf->Counter = 0;
	pBuf->Head = 0;
	pBuf->Tail = 0;
	memset(pBuf->Buff, 0, (pBuf->ElementBytes * pBuf->Depth));
}

void Rbuf_Free(Rbuf_Type *pBuf)
{
	pBuf->Counter = 0;
	pBuf->Head = 0;
	pBuf->Tail = 0;
	free(pBuf->Buff);
}

unsigned char Rbuf_IsEmpty(Rbuf_Type *pBuf)
{
	return (pBuf->Counter == 0);
}

unsigned char Rbuf_IsFull(Rbuf_Type *pBuf)
{
	return (pBuf->Counter == pBuf->Depth);
}

unsigned char Rbuf_AddOne(Rbuf_Type *pBuf, void *pValue)
{
	unsigned char *p;

	if (Rbuf_IsFull(pBuf))
	{
		return 0;
	}

	p = (unsigned char *)pBuf->Buff;
	memcpy(p + pBuf->Tail * pBuf->ElementBytes, (unsigned char *)pValue, pBuf->ElementBytes);

	pBuf->Tail++;
	if (pBuf->Tail >= pBuf->Depth)
	{
		pBuf->Tail = 0;
	}
	pBuf->Counter++;
	return 1;
}

unsigned int Rbuf_Add(Rbuf_Type *pBuf, void *pValues, unsigned int bytesToAdd)
{
	unsigned char *p;
	unsigned int cnt = 0;

	p = (unsigned char *)pValues;
	while (bytesToAdd--)
	{
		if (Rbuf_AddOne(pBuf, p))
		{
			p += pBuf->ElementBytes;
			cnt++;
		}
		else
		{
			break;
		}
	}

	return cnt;
}

unsigned char Rbuf_GetOne(Rbuf_Type *pBuf, void *pValue)
{
	unsigned char *p;
	if (Rbuf_IsEmpty(pBuf))
	{
		return 0;
	}

	p = (unsigned char *)pBuf->Buff;
	memcpy(pValue, p + pBuf->Head * pBuf->ElementBytes, pBuf->ElementBytes);

	pBuf->Head++;
	if (pBuf->Head >= pBuf->Depth)
	{
		pBuf->Head = 0;
	}
	pBuf->Counter--;

	return 1;
}

unsigned int Rbuf_Get(Rbuf_Type *pBuf, void *pValues, unsigned int bytesToRead)
{
	unsigned int cnt = 0;
	unsigned char *p;

	p = pValues;
	while (bytesToRead--)
	{
		if (Rbuf_GetOne(pBuf, p))
		{
			p += pBuf->ElementBytes;
			cnt++;
		}
		else
		{
			break;
		}
	}

	return cnt;
}
