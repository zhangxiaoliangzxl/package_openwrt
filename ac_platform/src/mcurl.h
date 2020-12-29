#ifndef __MCURL_H__
#define __MCURL_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include "logs.h"

/*
#define USE_BASE64
*/

/* mcurl error code */
#define CURLOK 0
#define CURLERR -1

/* mcurl method code */
#define GET 1
#define POST 2

/* curlerrorstate */
int curl_state;

void my_curl_init();
void my_curl_uninit();

extern int curl_request(const char *url, int method, char *data, char *ret);

#endif
