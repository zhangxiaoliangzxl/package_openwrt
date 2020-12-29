#include <errno.h>

#include "elog.h"
#include "send.h"
#include "util.h"

#if 0
int get_tcp_state(int sock)
{
	int ret = 0;

	if (sock < 0)
	{
		return ret;
	}

	struct tcp_info info;
	int len = sizeof(info);

	getsockopt(sock, IPPROTO_TCP, TCP_INFO, &info, (socklen_t *)&len);
	if ((info.tcpi_state == TCP_ESTABLISHED))
	{
		ret = 1;
	}

	return ret;
}
#endif

int TCP_clien(char *ip, int port, struct sockaddr_in *server)
{
	int sock_clien, result;

	sock_clien = 0, result = 0;
	server->sin_family      = AF_INET;
	server->sin_addr.s_addr = inet_addr(ip);
	server->sin_port        = htons(port);

	sock_clien = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_clien < 0)
	{
		log_e("tcp socket error");
		close(sock_clien);
		return -1;
	}

	return sock_clien;
}

int setKeepAlive(int fd, int interval)
{
	int val = 1;

	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) == -1)
	{
		printf("setsockopt SO_KEEPALIVE: %s", strerror(errno));
		return -1;
	}

	/* Send first probe after `interval' seconds. */
	val = interval;
	if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof(val)) < 0)
	{
		printf("setsockopt TCP_KEEPIDLE: %s\n", strerror(errno));
		return -1;
	}

	/* Send next probes after the specified interval. Note that we set the
	 * delay as interval / 3, as we send three probes before detecting
	 * an error (see the next setsockopt call). */
	val = interval / 3;
	if (val == 0)
		val = 1;
	if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &val, sizeof(val)) < 0)
	{
		printf("setsockopt TCP_KEEPINTVL: %s\n", strerror(errno));
		return -1;
	}

	/* Consider the socket in error state after three we send three ACK
	 * probes without getting a reply. */
	val = 3;
	if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &val, sizeof(val)) < 0)
	{
		printf("setsockopt TCP_KEEPCNT: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int tcp_send(int sock, char *buff, int len)
{
	int ret = 0;

	ret = write(sock, buff, len);
	if (unlikely(ret < 0))
	{
		log_e("tcp write data error");
		log_e("write fail (%s)", strerror(errno));
		return -1;
	}
	/*
	else if (ret == 0)
	{
		log_w("tcp kernel buffer full");
	}
	*/

	return 0;
}

int udp_client(char *ip, int prot, struct sockaddr_in *addr)
{
	int sockfd;
	memset(addr, 0, sizeof(struct sockaddr_in));
	addr->sin_family      = AF_INET;
	addr->sin_addr.s_addr = inet_addr(ip);
	addr->sin_port        = htons(prot);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		log_e("udp sock error!");
		return -1;
	}
	return sockfd;
}

int udp_send(int sock, char *buff, int len)
{
	int            ret;
	fd_set         fds;
	struct timeval timeout = {10, 0};

	ret = 0;

	while (TRUE)
	{
		timeout.tv_sec = 1;
		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		ret = select(sock + 1, NULL, &fds, NULL, &timeout);
		if (ret < 0)
		{
			log_e("udp select error");
			return -1;
		}
		else if (ret == 0)
		{
			log_e("udp select timeout !");
			return -1;
		}
		else if (ret == 1)
		{
			if (FD_ISSET(sock, &fds))
			{
				ret = write(sock, buff, len);
				if (ret < 0)
				{
					log_e("udp send data error");

					return -1;
				}
				else
				{
					// log_i("udp write data succes");
				}
			}
		}
		else /* select 0 */
		{
			log_e("udp select error !");
			log_e("select fail (%s)", strerror(errno));
			return -1;
		}

		break;
	}

	return 0;
}
