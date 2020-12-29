/*************************************************************************
>  File Name: main.c
>  Author: zxl
>  Mail:
>  Created Time: 2020-09-18 17:16:59
*************************************************************************/

#include <asm/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>

#define MAX_PAYLOAD 16
#define NETLINK_NOTIFY 25

int main(int argc, char *argv[])
{
	int ret = 0;
	struct sockaddr_nl src_addr, dest_addr;
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	struct msghdr msg;
	int sock_fd, retval;
	char cmdbuf[128] = {0};

	/* Create a socket */
	sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NOTIFY);
	if (sock_fd == -1)
	{
		printf(" create netlink error !\n");
		return -1;
	}

	/* binding */
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = 100;
	src_addr.nl_groups = 0;

	retval = bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));
	if (retval < 0)
	{
		printf("bind failed: %s", strerror(errno));
		ret = -1;
		goto ERROR;
	}

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	if (!nlh)
	{
		printf("nlmsghdr mem malloc error!\n");
		ret = -1;
		goto ERROR;
	}

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;
	dest_addr.nl_groups = 0;
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = 100;
	nlh->nlmsg_flags = 0;

	/* hello msg */
	strcpy(NLMSG_DATA(nlh), "netlink_notify");
	iov.iov_base = (void *)nlh;
	iov.iov_len = NLMSG_SPACE(MAX_PAYLOAD);

	/* Create mssage */
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* send message */
	ret = sendmsg(sock_fd, &msg, 0);
	if (ret == -1)
	{
		printf("send message to kmod error !\n");
	}

	/* receive message */
	printf("waiting receive msg ......\n");
	while (1)
	{
		memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
		ret = recvmsg(sock_fd, &msg, 0);
		if (ret < 0)
		{
			printf("recvmsg return error !");
		}

		printf("Received kmod message: %s\n", (char *)NLMSG_DATA(nlh));

		/* call user shell script */
		memset(cmdbuf, 0, sizeof(cmdbuf));
		snprintf(cmdbuf, sizeof(cmdbuf), "/usr/sbin/netlink_notify.sh %s", (char *)NLMSG_DATA(nlh));
		system(cmdbuf);
	}

	ret = 0;

ERROR:
	close(sock_fd);
	return ret;
}
