/*
 * ***********************************************************************
 * File: base64.c
 * Author: zxl
 * Contact: <zxl@gmail.com>
 * Copyright (c) 2020 xxx
 * Created Date: 2020-07-27  11:07:10 am
 * ***********************************************************************
 */

#ifndef BASE46_H
#define BASE46_H

#include <memory.h>
#include <stdlib.h>

/***********************************************
Encodes ASCCI string into base64 format string
@param plain ASCII string to be encoded
@return encoded base64 format string
***********************************************/
char *base64_encode(char *plain); /* must free return pointer memory */

/***********************************************
decodes base64 format string into ASCCI string
@param plain encoded base64 format string
@return ASCII string to be encoded
***********************************************/
char *base64_decode(char *cipher); /* must free return pointer memory */

#endif // BASE46_H
