#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>

// UDP包
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "elog/elog.h"
#include "func.h"
#include "logs.h"

#define OK 0
#define ERROR -1

#define PORT_UDP 7003
#define CMDSIZE 256
#define MAXDATASIZE 64
#define MAC 17
#define KEYSIZE 32
#define NOCLIENT 10

#define GKEY "airocov178"
#define CLIENT "/tmp/clients"

time_t lasttime;

int getCmd(char *dest, char *cmd, int n)
{
	memset(dest, 0, n);
	FILE *fp = popen(cmd, "r");
	if (NULL == fp)
	{
		log_e("popen error!");
		return ERROR;
	}
	fread(dest, 1, n, fp);
	pclose(fp);
	return OK;
}

int getkey(const char *data, char *key)
{
	strncpy(key, data + MAC + 1, KEYSIZE);
	return OK;
}

int generate_key(char *key, const char *data)
{
	int ret;
	char cmd[CMDSIZE] = {0};
	sprintf(cmd,
			"echo %s | md5sum \
            | awk '{printf(\"%%s\", $1)}'",
			data);
	ret = getCmd(key, cmd, KEYSIZE);
	if (ret != OK)
	{
		return ERROR;
	}
	return OK;
}

int check_mkey(const char *key)
{
	char mkey[MAXDATASIZE] = {0};
	generate_key(mkey, GKEY);
	if (strncmp(key, mkey, KEYSIZE))
	{
		return ERROR;
	}
	return OK;
}

int getFilesize(char *file, size_t *size)
{
	struct stat f_st;
	int ret = stat(file, &f_st);
	if (ret < 0)
	{
		return ERROR;
	}
	*size = f_st.st_size;
	return OK;
}

int getmClients(char **maclist)
{
	system("acscript cmdclients2");
	size_t fsize;
	getFilesize("/tmp/test", &fsize);
	if (fsize == 0)
	{
		*maclist = (char *)malloc(NOCLIENT);
		strncpy(*maclist, "no client", NOCLIENT);
		return OK;
	}
	*maclist = (char *)malloc(fsize);
	memset(*maclist, 0, fsize);
	FILE *fp = fopen("/tmp/test", "r");
	if (fp == NULL)
	{
		free(maclist);
		return ERROR;
	}

	fread(*maclist, 1, fsize, fp);
	fclose(fp);
	(*maclist)[fsize - 1] = '\0';
	return OK;
}

int findClient(const char *mac, char *maclist)
{
	char rmac[MAC + 1] = {0};
	strncpy(rmac, mac, MAC);
	if (strstr(maclist, rmac) == NULL)
	{
		free(maclist);
		return ERROR;
	}
	free(maclist);
	return OK;
}

int mcheckclient(const char *climac)
{
	char *maclist = NULL;
	getmClients(&maclist);
	if (findClient(climac, maclist) == OK)
		return OK;
	return ERROR;
}

int dealdata(const char *data, const int n, const char *apmac, struct sockaddr_in *my_addr, int socfd)
{
	char key[MAXDATASIZE], *maclist = NULL, *sdata = NULL;
	getkey(data, key);
	if (check_mkey(key))
	{
		return ERROR;
	}

	getmClients(&maclist);
	sdata = (char *)malloc(strlen(maclist) + 20);
	sprintf(sdata, "%s\n%s", apmac, maclist);
	free(maclist);
	maclist = NULL;
	sendto(socfd, sdata, strlen(sdata), 0, (struct sockaddr *)my_addr, sizeof(struct sockaddr));
	lasttime = time(NULL);
	free(sdata);
	sdata = NULL;
	/*
	 * 接受到一个mac地址，并判断mac地址，如mac地址是本ap的mac就将其连接的所有客户端信息发送回去
	 * 若mac是其连接下的客户端，就将本机mac发送回去
	if (strncmp(data, apmac, MAC))
	{
		if(mcheckclient(data) == OK)
		{
			sendto(socfd, apmac, strlen(apmac), 0, (struct sockaddr *)my_addr, sizeof(struct sockaddr));
		}
	}
	else
	{
		getmClients(&maclist);
		sendto(socfd, maclist, strlen(maclist), 0, (struct sockaddr *)my_addr, sizeof(struct sockaddr));
		free(maclist);
	}
	*/
	return OK;
}

/**
 * 循环向网关发送一次本机的连接信息
 * @ arg 是指向本机的网关
 **/
void *subthread(void *arg)
{
	struct sockaddr_in gw;
	char *maclist = NULL;
	char *sdata = NULL;
	int socket_udp;
	gw.sin_family = AF_INET;
	gw.sin_port = htons(PORT_UDP);
	gw.sin_addr.s_addr = htonl(inet_addr((char *)arg));

	/* 创建套接字 */
	if ((socket_udp = (socket(AF_INET, SOCK_DGRAM, 0))) == -1)
	{
		perror("socket");
		exit(1);
	}

	/* 循环发送 */
	while (1)
	{
		/* 判断上次发送广播时间，若小于10则不执行 */
		if ((time(NULL) - lasttime) < 10)
		{
			continue;
		}
		getmClients(&maclist);
		sdata = (char *)malloc(strlen(maclist) + 20);
		sprintf(sdata, "%s\n%s", apmac, maclist);
		free(maclist);
		maclist = NULL;
		sendto(socket_udp, sdata, strlen(sdata), 0, (struct sockaddr *)&gw, sizeof(struct sockaddr));
		lasttime = time(NULL);
		log_i("\nsenddata:%s", sdata);
		free(sdata);
		sdata = NULL;
		sleep(10);
	}
	return NULL;
}

/***************************************************
 *广播，UDP广播，搜索此路由器,回发IP
 ***************************************************/
void *searchclient(void *arg)
{
	char bufr[MAXDATASIZE];
	char apmac[MAC + 1] = {0};
	char gateway[20] = {0};
	int len;
	int socket_udp;
	struct sockaddr_in my_addr, user_addr;
	socklen_t size;

	/* 获得本机ip */
	getCmd(apmac,
		   "ifconfig br-lan | grep HWaddr \
			| awk \'{printf(\"%s\", $5)}\'",
		   sizeof(apmac));
	getCmd(gateway, "route -n | awk '{if(NR>2 && $2!=\"0.0.0.0\"){printf(\"%s\", $2)}}'", sizeof(gateway));

	log_i("gateway:%s", gateway);
	pthread_t thread;
	int ret = pthread_create(&thread, 0, subthread, gateway);
	if (ret < 0)
	{
		log_e("create the subthread error.");
	}
	pthread_detach(thread);

	/*发送地址相关设置*/
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(PORT_UDP);
	bzero(&(my_addr.sin_zero), 8);

	/*接受端要绑定*/
	user_addr.sin_family = AF_INET;
	user_addr.sin_port = htons(PORT_UDP);
	user_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	bzero(&(user_addr.sin_zero), 8);
	if ((socket_udp = (socket(AF_INET, SOCK_DGRAM, 0))) == -1)
	{
		perror("socket");
		exit(1);
	}
	// setsockopt(socket_udp,SOL_SOCKET,SO_BROADCAST,&so_broadcast,sizeof(so_broadcast));
	if ((bind(socket_udp, (struct sockaddr *)&user_addr, sizeof(struct sockaddr))) == -1)
	{
		perror("bind");
		exit(1);
	}

	size = sizeof(user_addr);
	while (1)
	{
		memset(bufr, 0, sizeof(bufr));
		len = recvfrom(socket_udp, bufr, MAXDATASIZE, 0, (struct sockaddr *)&user_addr, &size);
		my_addr.sin_addr.s_addr = inet_addr(inet_ntoa(user_addr.sin_addr)); //单播回去
		bufr[MAC + KEYSIZE + 1] = '\0';

		dealdata(bufr, len, apmac, &my_addr, socket_udp);
	}
}

