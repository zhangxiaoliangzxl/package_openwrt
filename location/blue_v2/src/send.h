#ifndef __SEND_H__
#define __SEND_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

/*
#define TCP_SEND
 */

int tcp_send_data(int sock, char *buff, int len);
int tcp_client(char *ip, int prot, struct sockaddr_in *server);
int setKeepAlive(int fd, int interval);
int udp_send_data(int sock, char *buff, int len);
int udp_client(char *ip, int prot, struct sockaddr_in *addr);

#endif
