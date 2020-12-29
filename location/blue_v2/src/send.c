#include <errno.h>
#include <unistd.h>

#include "log.h"
#include "send.h"
#include "util.h"

int tcp_client(char *ip, int prot, struct sockaddr_in *server)
{
	int sock_client, result;

	sock_client = 0, result = 0;
	server->sin_family = AF_INET;
	server->sin_addr.s_addr = inet_addr(ip);
	server->sin_port = htons(prot);

	sock_client = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_client < 0)
	{
		LOG_LOG("tcp socket error");
		close(sock_client);
		return -1;
	}

	return sock_client;
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

int tcp_send_data(int sock, char *buff, int len)
{
	int ret;
	fd_set fds;
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
			LOG_LOG("tcp select error");
			return -1;
		}
		else if (ret == 0)
		{
			LOG_LOG("tcp select timeout !");
			return -1;
		}
		else if (ret == 1)
		{
			if (FD_ISSET(sock, &fds))
			{
				ret = write(sock, buff, len);
				if (ret < 0)
				{
					LOG_LOG("tcp send data error");
					LOG_LOG("write fail (%s)", strerror(errno));
					return -1;
				}
				else
				{
					// LOG_LOG("tcp write data succes");
				}
			}
		}
		else /* select 0 */
		{
			LOG_LOG("tcp select error !");
			LOG_LOG("select fail (%s)", strerror(errno));
			return -1;
		}

		break;
	}

	return 0;
}

int udp_client(char *ip, int prot, struct sockaddr_in *addr)
{
	int sockfd;
	memset(addr, 0, sizeof(struct sockaddr_in));
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr(ip);
	addr->sin_port = htons(prot);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		LOG_LOG("udp sock error!");
		return -1;
	}
	return sockfd;
}

int udp_send_data(int sock, char *buff, int len)
{
	int ret;
	fd_set fds;
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
			LOG_LOG("udp select error");
			return -1;
		}
		else if (ret == 0)
		{
			LOG_LOG("udp select timeout !");
			return -1;
		}
		else if (ret == 1)
		{
			if (FD_ISSET(sock, &fds))
			{
				ret = write(sock, buff, len);
				if (ret < 0)
				{
					LOG_LOG("udp send data error");
#ifdef DEBUG
					printf("write fail (%s)\n", strerror(errno));
#endif
					return -1;
				}
				else
				{
					// LOG_LOG("udp write data succes");
				}
			}
		}
		else /* select 0 */
		{
			LOG_LOG("udp select error !");
			LOG_LOG("select fail (%s)", strerror(errno));
			return -1;
		}

		break;
	}

	return 0;
}

