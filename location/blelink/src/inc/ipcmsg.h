/*************************************************************************
>  File Name: ipcmsg.h
>  Author: zxl
>  Mail:
>  Created Time: 2020-11-18 14:36:46
*************************************************************************/

#ifndef _IPCMSG_H
#define _IPCMSG_H

#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>

#define MAX_IPCMSG_LEN 128
#define IPC_PATHNAME "/usr/sbin/"
#define IPC_PROJECTID 3

#define MSG_TYPE_ALL 0
#define MSG_TYPE_UWB 1
#define MSG_TYPE_BLE 2

/* init ipc msg
key_t ipcmsgkey = ftok(IPC_PATHNAME, IPC_PROJECTID);
ipcmsgid = msgget(ipcmsgkey, 0666 | IPC_CREAT);
if (ipcmsgid == -1)
{
	MYLOG("msgget failed width error: %d", errno);
	exit(EXIT_FAILURE);
}
*/

struct ipcmsg_t
{
	int  len;
	char data[MAX_IPCMSG_LEN];
};

struct msg_st
{
	long int        msg_type;
	struct ipcmsg_t msg_data;
};

key_t LOCAL_KEY(void);

#endif
