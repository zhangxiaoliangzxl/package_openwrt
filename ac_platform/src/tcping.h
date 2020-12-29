#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#ifndef TCP_H_DEFINED
#define TCP_H_DEFINED
// int lookup(char *host, char *portnr, struct addrinfo **res);
// int connect_to(struct addrinfo *addr, struct timeval *rtt, int timeout);
int tcping(const char *hostname, const char *portnr, int count, int wait, int timeout, int quiet);
#endif /* TCP_H_DEFINED */
