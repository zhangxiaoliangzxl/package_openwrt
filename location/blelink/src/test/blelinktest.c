/*************************************************************************
>  File Name: send.c
>  Author: zxl
>  Mail:
>  Created Time: 2020-11-18 14:15:10
*************************************************************************/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/msg.h>
#include "ipcmsg.h"

int main(int argc, char **argv)
{
	int           ipcmsgid = -1;
	struct msg_st msgdata;
	char          buffer[128] = {0};

	/* init ipc msg */
	key_t ipcmsgkey = ftok(IPC_PATHNAME, IPC_PROJECTID);
	ipcmsgid        = msgget(ipcmsgkey, 0666 | IPC_CREAT);
	if (ipcmsgid == -1)
	{
		printf("msgget failed width error: %d\n", errno);
		exit(EXIT_FAILURE);
	}

	while (1)
	{
		printf("Enter cmd: \n");
		fgets(buffer, 128, stdin);

		/* put blelink msglist */
		memset(&msgdata, 0, sizeof(struct msg_st));
		msgdata.msg_type     = MSG_TYPE_BLE;
		msgdata.msg_data.len = strlen(buffer) - 1;
		memcpy(msgdata.msg_data.data, buffer, msgdata.msg_data.len);

		if (msgsnd(ipcmsgid, ( void * )&msgdata, sizeof(struct ipcmsg_t), IPC_NOWAIT) < 0)
		{
			printf("msgsnd to ble msglist fail !\n");
		}

		if (strncmp(buffer, "exit", 4) == 0)
		{
			break;
		}
	}

	exit(EXIT_SUCCESS);
}
