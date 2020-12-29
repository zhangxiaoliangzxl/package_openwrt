/*************************************************************************
>  File Name: utils.c
>  Author: zxl
>  Mail:
>  Created Time: Wed 18 Sep 2019 11:52:23 AM CST
*************************************************************************/
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "utils.h"

int pox_system(const char *cmd_line)
{
	int ret = 0;
	sighandler_t old_handler;

	old_handler = signal(SIGCHLD, SIG_DFL);
	ret = system(cmd_line);
	signal(SIGCHLD, old_handler);

	return ret;
}

int vfork_exec(const char *cmd)
{
	pid_t pid;
	if (-1 == (pid = vfork()))
	{
		return 1;
	}

	if (0 == pid)
	{
		execl("/bin/sh", "sh", "-c", cmd, (char *)0);
		return 0;
	}
	else
	{
		wait(&pid);
	}
	return 0;
}

int system_call(const char *cmd)
{
	int ret = -1;
	if (cmd == NULL)
	{
		return -1;
	}

	ret = vfork_exec(cmd);
	if (0 != ret)
	{
		printf("execute cmd [%s] failed! ret = %d\n", cmd, ret);
		return -1;
	}
	return 0;
}

