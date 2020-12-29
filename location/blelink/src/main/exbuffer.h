/*************************************************************************
>  File Name: exbuffer.h
>  Author: zxl
>  Mail:
>  Created Time: 2020-12-08 16:25:10
*************************************************************************/

#ifndef _EXBUFFER_H
#define _EXBUFFER_H
#ifdef __cplusplus

extern "C"
{
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

/* extend byte every time */
#define EXTEND_BYTES 512

	enum exbuffer_endian
	{
		EXBUFFER_BIG_ENDIAN,
		EXBUFFER_LITTLE_ENDIAN
	};

	typedef struct exbuffer_value
	{
		unsigned char        headLen; /* headlen：2/4 */
		enum exbuffer_endian endian;
		size_t               readOffset;
		size_t               putOffset;
		size_t               dlen;
		unsigned char *      buffer;
		size_t               bufferlen;
		size_t               packetLen;
		unsigned char *      packet;
		/* read tmp buf */
		unsigned char *headBytes;
		union HeadBytesS {
			unsigned char  bytes[2];
			unsigned short val;
		} headS;

		union HeadBytesL {
			unsigned char bytes[4];
			unsigned long val;
		} headL;

		void (*recvHandle)(unsigned char *, size_t); /* packet handle function */
	} exbuffer_t;

	void   exbuffer_free(exbuffer_t **value);
	void   exbuffer_printHex(unsigned char *bytes, unsigned short len);
	void   exbuffer_dump(exbuffer_t *value, unsigned short len);
	size_t exbuffer_getLen(exbuffer_t *value);

	exbuffer_t *exbuffer_new( );
	void        exbuffer_put(exbuffer_t *value, unsigned char *buffer, size_t offset, size_t len);

#ifdef __cplusplus
}
#endif

#endif
