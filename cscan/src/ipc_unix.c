#include "main.h"
#include "ipc_unix.h"
#include "upload.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static const char *unix_path="/tmp/cscan/cov_ipc_srv";
static fd_set accept_fds;
static count = 0;

/* 数据接收超时次数 */
static unsigned int rx_timeout_n = 0;

int ipc_ServerInit()
{
	int fd, len;
	struct sockaddr_un un;
	pid_t ppid;

	ppid = getppid();
	if(ppid == 1)
	{
		exit(-1);
	}

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("socket error");
		exit(-1);
	}

	unlink(unix_path);
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, unix_path);

	len = offsetof(struct sockaddr_un, sun_path) + strlen(unix_path);

	if (bind(fd, (struct sockaddr *) &un, len) < 0) {
		perror("bind error");
		exit(-1);
	}
    if (listen(fd, 32) < 0) {
        perror("listen error");
        exit(-1);
    }
	return fd;
}

int ipc_accept(int ipc_fd)
{
	FD_ZERO(&accept_fds);
	FD_SET(ipc_fd, &accept_fds);

	struct timeval accept_t;
	accept_t.tv_usec = 0;
	accept_t.tv_sec = 1;

	int ret = select(ipc_fd+1, &accept_fds, NULL, NULL, &accept_t);

	if (ret == -1) /* interrupted */
	{
		printlog("select -1\n");
		sleep(1);
		return 0;
	}
	/* timeout */
	if (ret == 0) 
	{ 
		/* 采集模块不判断 */
		if(rx_timeout_n++ > 5)
		{
			printlog("rx_timeout_n full getout!\n");
			exit(-1);
		}
		if(getppid() == 1)
		{
			printlog("ipc child game over!\n");
			exit(-1);
		}
		else
		{
			printlog("ipc child accept timeout:%d!\n", rx_timeout_n);
			return 0;
		}
	}
	else
	{
		rx_timeout_n = 0;
	}
	return accept(ipc_fd, NULL, NULL);
}

int ipc_ClientInit()
{
	int fd;
	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)    /* create a UNIX domain stream socket */
	{
		perror("ipc_client socket create:");
		return(-1);
	}
	int len;
	struct sockaddr_un un;
	memset(&un, 0, sizeof(un));            /* fill socket address structure with our address */
	/* fill socket address structure with server's address */
	un.sun_family = AF_UNIX;
	sprintf(un.sun_path, "/tmp/cscan/cov_ipc_cli");
	unlink(un.sun_path);               /* in case it already exists */
	len = offsetof(struct sockaddr_un, sun_path) + strlen(un.sun_path);

	if (bind(fd, (struct sockaddr *)&un, len) < 0)
	{
		perror("unix client bind error:");
		exit(EXIT_FAILURE);
	}

	memset(&un, 0, sizeof(un));            /* fill socket address structure with our address */
	/* fill socket address structure with server's address */
	un.sun_family = AF_UNIX;
	strcpy(un.sun_path, unix_path);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(unix_path);

	if (connect(fd, (struct sockaddr *)&un, len) < 0)
	{
		printlog("ipc client connect error!\n");
		return -1;
	}
	else
	{
		return (fd);
	}
}

/****************************************************************
 * function: parent process trigger this to send msg to child
 * @ipc_send: ipc message include <cmd, len, value:json>
 * @return: trigger ok(1) or not(-1)
 ***************************************************************/
int ipc_trigger(IPC ipc_send, int fd)
{
	if(fd <= 0)return -1;
	switch(ipc_send.cmd)
	{
		case IPC_SEND_CLIENTS:
//			/*log the msg*/
//			if(conf.debug)
//			{
			write_to_file_debug(1, (char*)ipc_send.value);
//			}
			if(ipc_send.len == write(fd, (char*)ipc_send.value, ipc_send.len))
			{
				return 1;
			}
			else
			{
				printlog("write error:%s,%d\n", __FILE__,__LINE__);
				return -1;
			}
		case IPC_GET_SENDS:
			break;
		default:
			break;
	}
	return -1;
}

/****************************************************************
 * function: chile process will be triggered
 * @return: trigger ok(1) or not(-1)
 ***************************************************************/
void ipc_recieve(int conn)
{
	char msg[MSG_LEN];
	char rstate[17];
	int size = 0;
	memset(msg, 0x00, MSG_LEN);
	size = read(conn, msg, MSG_LEN);
	if(size > 0)
	{
		switch(conf.upmode)
		{
			case UDP:
				udp_request(conf.sip, conf.sport, &msg[5]);
				break;
			case TCP:
				tcp_request(conf.sip, conf.sport, &msg[5]);
				break;
			case HTTP:
				curl_request(conf.surl, msg, rstate);
				break;
			case HTTPS:
				break;
			default:
				break;
		}
	}
	else if(size < 0)
	{
		perror("ipc child unix server recv error:");
	}
}
