#ifndef __UPLOAD_H
#define __UPLOAD_H

/* mcurl error code */
#define CURLOK	0
#define CURLERR -1


/* mcurl method code */
#define GET 	1
#define POST	2 

int curl_request(const char *url, char *data, char *ret);
int udp_request(const char *ipaddr, int port, const char *data);
int tcp_request(const char *ipaddr, int port, const char *data);

#endif
