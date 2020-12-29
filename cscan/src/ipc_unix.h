#ifndef __IPC_UNIX_H
#define __IPC_UNIX_H

#define MSG_LEN		8192

int ipc_ServerInit();
int ipc_ClientInit();
int ipc_trigger(IPC ipc_send, int fd);
void ipc_recieve(int conn);
int ipc_accept(int ipc_fd);

#endif
