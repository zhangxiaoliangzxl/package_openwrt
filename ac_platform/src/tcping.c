#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include "elog/elog.h"
#include "tcping.h"

#define abs(x) ((x) < 0 ? -(x) : (x))

int static lookup(char *host, char *portnr, struct addrinfo **res)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;
	hints.ai_protocol = 0;

	return getaddrinfo(host, portnr, &hints, res);
}

int static connect_to(struct addrinfo *addr, struct timeval *rtt, int timeout)
{
	int fd;
	struct timeval start;
	int connect_result;
	const int on = 1;
	struct timeval tm;
	fd_set set;
	int flags;
	int ret;
	/* int flags; */
	int rv = 0;

	/* try to connect for each of the entries: */
	while (addr != NULL)
	{
		/* create socket */
		if ((fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol)) == -1)
			goto next_addr0;
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
			goto next_addr1;

		if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
			goto next_addr1;
		if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
			goto next_addr1;

		if (gettimeofday(&start, NULL) == -1)
			goto next_addr1;

		/* connect to peer */
		connect_result = connect(fd, addr->ai_addr, addr->ai_addrlen);
		if (connect_result == -1 && errno != EINPROGRESS)
		{
			goto next_addr1;
		}

		tm.tv_sec = timeout;
		tm.tv_usec = 0;

		FD_ZERO(&set);
		FD_SET(fd, &set);
		ret = select(fd + 1, NULL, &set, NULL, &tm);
		switch (ret)
		{
			case 0: /* timeout */
			case -1:
				goto next_addr1;
				break;
			default:					/* Connection ok or refused*/
				ret = write(fd, "", 0); /* only test, no data send */
				if (ret < 0)
					goto next_addr1;
				break;
		}

		if (gettimeofday(rtt, NULL) == -1)
			goto next_addr1;
		rtt->tv_sec = rtt->tv_sec - start.tv_sec;
		rtt->tv_usec = rtt->tv_usec - start.tv_usec;
		close(fd);
		return 0;

	next_addr1:
		close(fd);
	next_addr0:
		addr = addr->ai_next;
	}

	rv = rv ? rv : -errno;
	return rv;
}

int tcping(const char *hostname, const char *portnr, int count, int wait, int timeout, int quiet)
{
	int stop = 0;
	int curncount = 0;
	int ok = 0, err = 0;
	double min = 999999999999999.0, avg = 0.0, max = 0.0;
	struct addrinfo *resolved;
	int errcode;
	int seen_addrnotavail;

	if ((errcode = lookup(hostname, portnr, &resolved)) != 0)
	{
		log_e("tcping lookup return %s", gai_strerror(errcode));
		return 2;
	}

	if (!quiet)
		log_w("TCPING %s:%s", hostname, portnr);

	while ((curncount < count || count == -1) && stop == 0)
	{
		double ms;
		struct timeval rtt;

		if ((errcode = connect_to(resolved, &rtt, timeout)) != 0)
		{
			if (errcode != -EADDRNOTAVAIL)
			{
				if (-errcode == EINPROGRESS)
				{
					log_e("error connecting to host (%d): %s [Timeout]", -errcode, strerror(-errcode));
				}
				else
				{
					log_e("error connecting to host (%d): %s", -errcode, strerror(-errcode));
				}
				err++;
			}
			else
			{
				if (seen_addrnotavail)
				{
					log_w(".");
					// fflush(stdout);
				}
				else
				{
					log_e("error connecting to host (%d): %s\n", -errcode, strerror(-errcode));
				}
				seen_addrnotavail = 1;
			}
		}
		else
		{
			seen_addrnotavail = 0;
			ok++;

			ms = ((double)rtt.tv_sec * 1000.0) + ((double)rtt.tv_usec / 1000.0);
			avg += ms;
			min = min > ms ? ms : min;
			max = max < ms ? ms : max;

			log_w("response from %s:%s, seq=%d time=%.2f ms", hostname, portnr, curncount, ms);
			if (ms > 500)
				break; /* Stop the test on the first long connect() */
		}

		curncount++;

		if (curncount != count)
			sleep(wait);
	}

	if (!quiet)
	{
		log_w("--- %s:%s tcping statistics ---", hostname, portnr);
		log_w("%d responses, %d ok, %3.2f%% failed", curncount, ok, (((double)err) / abs(((double)count)) * 100.0));
		log_w("round-trip min/avg/max = %.1f/%.1f/%.1f ms", min, avg / (double)ok, max);
	}

	freeaddrinfo(resolved);
	if (ok)
		return 0;
	else
		return 127;
}
