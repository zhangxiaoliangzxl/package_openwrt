#ifndef __SEND_H__
#define __SEND_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

int send_data(int sock, struct sockaddr_in *clien, char *buff, int len);
int TCP_clien(char *, int, struct sockaddr_in *);
int setKeepAlive(int fd, int interval);

#endif
