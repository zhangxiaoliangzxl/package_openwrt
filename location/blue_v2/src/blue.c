/*************************************************************************
>  File Name: blue.c
>  Author: zxl
>  Mail:
>  Created Time: Fri 08 Nov 2019 01:49:53 PM CST
*************************************************************************/
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <linux/serial.h>

#include "blue.h"
#include "log.h"

int config_init(config *con)
{
	FILE *file = NULL;
	int len = 0;
	char serverhost[20], serverport[20], mac[20], tty[20];
	char cmd_resault[128] = {0};

	memset(serverhost, 0, sizeof(serverhost));
	memset(serverport, 0, sizeof(serverport));
	memset(mac, 0, sizeof(mac));

	con->baudrate = 921600;

	file = popen(SERVERHOST, "r");
	if (file)
	{
		fgets(serverhost, 20, file);
	}
	pclose(file);

	file = popen(SERVERPORT, "r");
	if (file)
	{
		fgets(serverport, 20, file);
	}
	pclose(file);

	file = popen(TTY, "r");
	if (file)
	{
		fgets(tty, 20, file);
	}
	pclose(file);

	file = popen(MAC, "r");
	if (file)
	{
		fgets(mac, 20, file);
	}
	pclose(file);

	len = strlen(serverhost);
	if (len < 2)
	{
		LOG_LOG("%s", "get serverhost error");
		return -1;
	}

	len = strlen(serverport);
	if (len < 2)
	{
		LOG_LOG("%s", "get serverport error");
		return -1;
	}

	len = strlen(tty);
	if (len < 5)
	{
		LOG_LOG("%s", "get tty error");
		return -1;
	}

	/*print_enable*/
	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(PRINT_ENABLE, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			if (strlen(cmd_resault) > 0)
			{
				con->print_enable = atoi(cmd_resault);
			}
		}
		else
		{
			con->print_enable = 0;
		}
	}
	pclose(file);

	/* baudrate */
	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(BAUDRATE, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			if (strlen(cmd_resault) > 0)
			{
				con->baudrate = atoi(cmd_resault);
			}
		}
		else
		{
			con->baudrate = 921600;
		}
	}
	pclose(file);

#ifdef TCP_SEND
	/*tcp_nagle*/
	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(TCP_NAGLE, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			if (strlen(cmd_resault) > 0)
			{
				con->tcp_nagle = atoi(cmd_resault);
			}
		}
		else
		{
			con->tcp_nagle = 0;
		}
	}
	pclose(file);
#endif

	strcpy(con->serverhost, serverhost);
	con->serverport = atoi(serverport);
	strcpy(con->devmac, mac);
	strcpy(con->tty, tty);

	LOG_LOG("################config info#################");
	LOG_LOG("\t serveraddr    : %s:%d", con->serverhost, con->serverport);
	LOG_LOG("\t printdata     : %d", con->print_enable);
#ifdef TCP_SEND
	LOG_LOG("\t tcp_nagle     : %d", con->tcp_nagle);
#endif
	LOG_LOG("\t tty           : %s", con->tty);
	LOG_LOG("\t baudrate      : %d", con->baudrate);
	LOG_LOG("\t apmac         : %s", con->devmac);
	LOG_LOG("############################################");

	return 0;
}

static void serial_setspeed(struct termios *opt, int speed)
{
	switch (speed)
	{
		case 9600:
			cfsetispeed(opt, B9600);
			cfsetospeed(opt, B9600);
			break;
		case 115200:
			cfsetispeed(opt, B115200);
			cfsetospeed(opt, B115200);
			break;
		case 230400:
			cfsetispeed(opt, B230400);
			cfsetospeed(opt, B230400);
			break;
		case 460800:
			cfsetispeed(opt, B460800);
			cfsetospeed(opt, B460800);
			break;
		case 576000:
			cfsetispeed(opt, B576000);
			cfsetospeed(opt, B576000);
			break;
		case 921600:
			cfsetispeed(opt, B921600);
			cfsetospeed(opt, B921600);
			break;
		default:
			cfsetispeed(opt, B115200);
			cfsetospeed(opt, B115200);
			break;
	}
}

int open_ttydev(config *con)
{
	int fd;
	char error[30] = "0";
	char buff[10] = "0";

	memset(buff, 0, sizeof(buff));
	// strcpy(buff, con->interface);
	fd = open(con->tty, O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (fd < 0)
	{
		return -1;
	}

#if 1
	struct serial_struct serial;
	ioctl(fd, TIOCGSERIAL, &serial);
	/*
	#if TEST_LOW_LATENCY
		serial.flags |= ASYNC_LOW_LATENCY;
	#else
		serial.flags &= ~ASYNC_LOW_LATENCY;
	#endif
	*/
	serial.xmit_fifo_size = 1024 * 2048;
	ioctl(fd, TIOCSSERIAL, &serial);
#endif

	struct termios opt;
	tcgetattr(fd, &opt);

	serial_setspeed(&opt, con->baudrate);

	opt.c_cflag &= ~PARENB;
	opt.c_iflag &= ~INPCK;
	// opt.c_iflag &= ~(INPCK | IXON | IXOFF | IXANY);
	// opt.c_iflag |= (IGNCR);

	opt.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
	opt.c_oflag &= ~OPOST;

	// opt.c_cc[VMIN]  = 0;  //read min byte will return
	// opt.c_cc[VTIME] = 10; //read 10*100ms will return, no block
	tcflush(fd, TCIOFLUSH);
	if (tcsetattr(fd, TCSANOW, &opt) != 0)
	{
		LOG_LOG("set Serial port error");
		return -1;
	}

	return fd;
}

int init_tty(char *ttydev, int baudrate, int ttyinit)
{
	int fd;
	char error[30] = {0};
	char buff[10] = {0};

	memset(buff, 0, sizeof(buff));
	fd = open(ttydev, O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (fd < 0)
	{
		syslog(LOG_ERR, "open %s error !", ttydev);
		return -1;
	}

	if (ttyinit > 0)
	{
		struct termios opt;
		tcgetattr(fd, &opt);

		serial_setspeed(&opt, baudrate);

		opt.c_cflag &= ~PARENB;
		opt.c_iflag &= ~INPCK;
		opt.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
		opt.c_oflag &= ~OPOST;
		// opt.c_cc[VMIN]  = 0;  //read min byte will return
		// opt.c_cc[VTIME] = 10; //read 10*100ms will return, no block
		tcflush(fd, TCIOFLUSH);
		if (tcsetattr(fd, TCSANOW, &opt) != 0)
		{
			syslog(LOG_ERR, "set Serial port error !");
			return -1;
		}
	}
	return fd;
}

/* func: recevice data from tty */
int recevice_from_tty(int fd, Thread_data *ttyread_buffer)
{
	int ret = 0;
	char readbuff[READSIZE + 1] = {0};
	int epid;
	int recv_len;

	Ttyread_data *read_data = NULL;
	read_data = (Ttyread_data *)malloc(sizeof(Ttyread_data));

	/* epoll init */
	epid = epoll_create(1);
	struct epoll_event event_tty;
	// event_tty.events = EPOLLIN | EPOLLET; // ET mode
	event_tty.events = EPOLLIN; // LT mode

	event_tty.data.fd = fd;
	ret = epoll_ctl(epid, EPOLL_CTL_ADD, fd, &event_tty);
	if (ret != 0)
	{
		LOG_LOG("set epoll error!");
	}

	memset(readbuff, 0, READSIZE + 1);

	while (TRUE)
	{
		/* wait epoll event */
		ret = epoll_wait(epid, &event_tty, 1, 100);
		if (ret > 0)
		{
			if (event_tty.events & EPOLLIN)
			{
				/* read until buffer is empty */
				while (TRUE)
				{
					memset(readbuff, 0, READSIZE);
					recv_len = read(event_tty.data.fd, readbuff, READSIZE);

					if (recv_len > 0)
					{
						readbuff[recv_len] = '\0';
						/* add to string_buffer */
						memset(read_data, 0, sizeof(Ttyread_data));
						memcpy(read_data->data, readbuff, recv_len);
						read_data->len = recv_len;
#ifndef USE_SEM
						pthread_mutex_lock(&ttyread_buffer->mutex);
#endif
						if (0 == Rbuf_AddOne(ttyread_buffer->ring_buffer, read_data))
						{
							LOG_LOG("ttyread ring buffer is full");
						}
#ifndef USE_SEM
						pthread_cond_signal(&ttyread_buffer->cond);
						pthread_mutex_unlock(&ttyread_buffer->mutex);
#else
						sem_post(&ttyread_buffer->sem);
#endif
						/* add to string_buffer end */

						if (recv_len < READSIZE)
						{
							/* buffer is empty, should break while */
							break;
						}
					}
					else if (recv_len == 0)
					{
						/* buffer is empty, should break while */
						// printf("no data read from tty, errorid %d %s !\n", errno, strerror(errno));

						if (errno == EINVAL)
						{
							// printf("read from tty error, maybe tty is error !\n");
							LOG_LOG("read from tty error, errorid %d %s !\n", errno, strerror(errno));
							close(epid);
							free(read_data);
							return -2;
						}
						else
						{
							break;
						}
					}
					else if (recv_len < 0)
					{
						/* read from tty error , maybe need return */
						if (errno == EAGAIN)
						{
							// printf("tty buffer is empty, errorid %d %s !\n", errno, strerror(errno));
							break;
						}
						else
						{
							// printf("read from tty error, errorid %d %s !\n", errno, strerror(errno));
							LOG_LOG("read from tty error, errorid %d %s !", errno, strerror(errno));
							close(epid);
							free(read_data);
							return -2;
						}
					}
				}
			}
			else if (event_tty.events & EPOLLERR || event_tty.events & EPOLLHUP || (!event_tty.events & EPOLLIN))
			{
				LOG_LOG("epoll_wait return error event , maybe tty is error!\n");
				/* close epoll id */
				close(epid);
				free(read_data);
				return -2;
			}
		}
		else if (ret <= 0)
		{
			/* */
		}
	}

	close(epid);
	free(read_data);
	return 0;
}

static char *get_value_by_name(char *pNext, const char *name, cJSON *root)
{
	char *ret = NULL;
	char *pStart = NULL;

	if (pNext == NULL || name == NULL || root == NULL)
	{
		return ret;
	}

	pStart = strstr(pNext, name);
	if (pStart != NULL)
	{
		pStart = pStart + strlen(name) + 1; // such as "MAC:"
		pNext = strchr(pStart, SPLIT_DELIMITER);
	}
	else
	{
		return ret;
	}

	if (pNext != NULL)
	{
		*pNext = ENDCHAR;
		pNext++;
		cJSON_AddStringToObject(root, name, pStart);
	}

	ret = pNext;
	return ret;
}

static char *parse_blue_data(char *data, config *conf)
{
	char *pStart = NULL, *pNext = NULL;
	cJSON *root = NULL;
	char *out = NULL;

	data_type_t data_type;

	static struct timeval cur_time;
	static char sys_time[20] = {0};

	/* get sys_time */
	gettimeofday(&cur_time, NULL);
	memset(sys_time, 0, sizeof(sys_time));
	JSONDATA_TIME(&cur_time, sys_time);

	/* get value and json data */
	root = cJSON_CreateObject();
	cJSON_AddStringToObject(root, "time", sys_time);
	cJSON_AddStringToObject(root, "devmac", conf->devmac);

	/* check blue data */
	if (pNext = strstr(data, TYPE_BLUE0))
	{
		pNext = pNext + strlen(TYPE_BLUE0);
		data_type = _BLUE0;
	}
	else if (pNext = strstr(data, TYPE_BLUE1))
	{
		pNext = pNext + strlen(TYPE_BLUE1);
		data_type = _BLUE1;
	}
	else if (pNext = strstr(data, TYPE_BLUE2))
	{
		pNext = pNext + strlen(TYPE_BLUE2);
		data_type = _BLUE2;
	}
	else if (pNext = strstr(data, TYPE_BLUE3))
	{
		pNext = pNext + strlen(TYPE_BLUE3);
		data_type = _BLUE3;
	}
	else if (pNext = strstr(data, TYPE_BLUE4))
	{
		pNext = pNext + strlen(TYPE_BLUE4);
		data_type = _BLUE4;
	}
	else
		goto ERROR;

	switch (data_type)
	{
		case _BLUE0:
		{
			/* TYPE */
			cJSON_AddStringToObject(root, "TYPE", "0");

			/* ADDR */
			pStart = pNext;
			if (pStart != NULL)
			{
				pNext = strchr(pStart, SPLIT_DELIMITER);
			}
			else
				goto ERROR;

			if (pNext != NULL)
			{
				*pNext = ENDCHAR;
				pNext++;
				cJSON_AddStringToObject(root, "ADDR", pStart);
			}

			/* UUID */
			if (NULL == (pNext = get_value_by_name(pNext, "UUID", root)))
			{
				goto ERROR;
			}

			/* MAJOR */
			if (NULL == (pNext = get_value_by_name(pNext, "MAJOR", root)))
			{
				goto ERROR;
			}

			/* MINOR */
			if (NULL == (pNext = get_value_by_name(pNext, "MINOR", root)))
			{
				goto ERROR;
			}

			/* RSSI */
			if (NULL == (pNext = get_value_by_name(pNext, "RSSI", root)))
			{
				goto ERROR;
			}

			/* R2OM */
			pStart = strstr(pNext, "R2OM:");
			if (pStart != NULL)
			{
				pStart = pStart + strlen("R2OM:");
				pNext = strchr(pStart, ';');
			}
			else
				goto ERROR;

			if (pNext != NULL)
			{
				*pNext = ENDCHAR;
				cJSON_AddStringToObject(root, "R2OM", pStart);
			}
		}
		break;
		case _BLUE1:
		{
			/* TYPE */
			cJSON_AddStringToObject(root, "TYPE", "1");

			/* IDSN */
			pStart = pNext;
			if (pStart != NULL)
			{
				pNext = strchr(pStart, SPLIT_DELIMITER);
			}
			else
				goto ERROR;

			if (pNext != NULL)
			{
				*pNext = ENDCHAR;
				pNext++;
				cJSON_AddStringToObject(root, "IDSN", pStart);
			}

			/* MAC */
			if (NULL == (pNext = get_value_by_name(pNext, "MAC", root)))
			{
				goto ERROR;
			}

			/* TH */
			if (NULL == (pNext = get_value_by_name(pNext, "TH", root)))
			{
				goto ERROR;
			}

			/* TE */
			if (NULL == (pNext = get_value_by_name(pNext, "TE", root)))
			{
				goto ERROR;
			}

			/* WS */
			if (NULL == (pNext = get_value_by_name(pNext, "WS", root)))
			{
				goto ERROR;
			}

			/* RSSI */
			pStart = strstr(pNext, "RSSI:");
			if (pStart != NULL)
			{
				pStart = pStart + strlen("RSSI:");
				pNext = strchr(pStart, ';');
			}
			else
				goto ERROR;

			if (pNext != NULL)
			{
				*pNext = ENDCHAR;
				cJSON_AddStringToObject(root, "RSSI", pStart);
			}
		}
		break;
		case _BLUE2:
		{
			/* TYPE */
			cJSON_AddStringToObject(root, "TYPE", "2");

			/* RDL52B1 */
			pStart = pNext;
			if (pStart != NULL)
			{
				pNext = strchr(pStart, SPLIT_DELIMITER);
			}
			else
				goto ERROR;

			if (pNext != NULL)
			{
				*pNext = ENDCHAR;
				pNext++;
				cJSON_AddStringToObject(root, "RDL52B1", pStart);
			}

			/* RDLT */
			if (NULL == (pNext = get_value_by_name(pNext, "RDLT", root)))
			{
				goto ERROR;
			}

			/* RDLH */
			if (NULL == (pNext = get_value_by_name(pNext, "RDLH", root)))
			{
				goto ERROR;
			}

			/* RSSI */
			if (NULL == (pNext = get_value_by_name(pNext, "RSSI", root)))
			{
				goto ERROR;
			}

			/* GX */
			if (NULL == (pNext = get_value_by_name(pNext, "GX", root)))
			{
				goto ERROR;
			}

			/* GY */
			if (NULL == (pNext = get_value_by_name(pNext, "GY", root)))
			{
				goto ERROR;
			}

			/* GZ */
			pStart = strstr(pNext, "GZ:");
			if (pStart != NULL)
			{
				pStart = pStart + strlen("GZ:");
				pNext = strchr(pStart, ';');
			}
			else
				goto ERROR;

			if (pNext != NULL)
			{
				*pNext = ENDCHAR;
				cJSON_AddStringToObject(root, "GZ", pStart);
			}
		}
		break;
		case _BLUE3:
		{
			/* TYPE */
			cJSON_AddStringToObject(root, "TYPE", "3");

			/* RDL52B2 */
			pStart = pNext;
			if (pStart != NULL)
			{
				pNext = strchr(pStart, SPLIT_DELIMITER);
			}
			else
				goto ERROR;

			if (pNext != NULL)
			{
				*pNext = ENDCHAR;
				pNext++;
				cJSON_AddStringToObject(root, "RDL52B2", pStart);
			}

			/* MAJOR */
			if (NULL == (pNext = get_value_by_name(pNext, "MAJOR", root)))
			{
				goto ERROR;
			}

			/* MINOR */
			if (NULL == (pNext = get_value_by_name(pNext, "MINOR", root)))
			{
				goto ERROR;
			}

			/* TXP */
			if (NULL == (pNext = get_value_by_name(pNext, "TXP", root)))
			{
				goto ERROR;
			}

			/* BCI */
			if (NULL == (pNext = get_value_by_name(pNext, "BCI", root)))
			{
				goto ERROR;
			}

			/* BAT */
			if (NULL == (pNext = get_value_by_name(pNext, "BAT", root)))
			{
				goto ERROR;
			}

			/* RSSI */
			pStart = strstr(pNext, "RSSI:");
			if (pStart != NULL)
			{
				pStart = pStart + strlen("RSSI:");
				pNext = strchr(pStart, ';');
			}
			else
				goto ERROR;

			if (pNext != NULL)
			{
				*pNext = ENDCHAR;
				cJSON_AddStringToObject(root, "RSSI", pStart);
			}
		}
		break;
		case _BLUE4:
		{
			/* TYPE */
			cJSON_AddStringToObject(root, "TYPE", "4");

			/* AOAMAC */
			pStart = pNext;
			if (pStart != NULL)
			{
				pNext = strchr(pStart, SPLIT_DELIMITER);
			}
			else
				goto ERROR;

			if (pNext != NULL)
			{
				*pNext = ENDCHAR;
				pNext++;
				cJSON_AddStringToObject(root, "ADDR", pStart);
			}

			/* SEQ */
			if (NULL == (pNext = get_value_by_name(pNext, "SEQ", root)))
			{
				goto ERROR;
			}

			/* AOA */
			if (NULL == (pNext = get_value_by_name(pNext, "AOA", root)))
			{
				goto ERROR;
			}

			/* RSSI */
			if (NULL == (pNext = get_value_by_name(pNext, "RSSI", root)))
			{
				goto ERROR;
			}

			/* CH */
			if (NULL == (pNext = get_value_by_name(pNext, "CH", root)))
			{
				goto ERROR;
			}

			/* ANT */
			pStart = strstr(pNext, "ANT:");
			if (pStart != NULL)
			{
				pStart = pStart + strlen("ANT:");
				pNext = strchr(pStart, ';');
			}
			else
				goto ERROR;

			if (pNext != NULL)
			{
				*pNext = ENDCHAR;
				cJSON_AddStringToObject(root, "ANT", pStart);
			}
		}
		break;
		default:

			goto ERROR;
	}

	out = cJSON_PrintUnformatted(root);
	if (1 == conf->print_enable)
	{
		printdata(out);
	}

ERROR:
	cJSON_Delete(root);
	return out;
}

/* blue_parse_thread func: read frome tty buffer and parse to blue data, send to parse thread */
void *blue_parse_thread_func(void *indata)
{
	int ret, framelen;
	char readbuff[READSIZE] = {0};
	char tempbuff[READSIZE * 2] = {0};
	char *pdata = NULL;
	char *json = NULL;

	char last_buff[MAXFRAMELEN * 2] = {0};
	int last_len = 0;
	int locked = 0;
	int wait_ret = 0;

	char frame_data[MAXFRAMELEN];

	ret = 0, framelen = 0;

	int data_len = 0;
	char *pSTART = NULL;
	char *pEND = NULL;
	char *p = NULL;

#ifndef USE_SEM
	struct timespec tv;
#endif

	Frame_data *data = (Frame_data *)indata;

	Ttyread_data *tmp_data = (Ttyread_data *)malloc(sizeof(Ttyread_data));
	Send_data *blue_data = (Send_data *)malloc(sizeof(Send_data));

	/* read data from tty read buffer */
	while (TRUE)
	{
		memset(tmp_data, 0, sizeof(Ttyread_data));
		ret = Rbuf_GetOne(data->frame_buffer->ring_buffer, tmp_data);

		if (ret <= 0)
		{
#ifdef USE_SEM
			sem_wait(&(data->frame_buffer->sem));
#else
			pthread_mutex_lock(&(data->frame_buffer->mutex));
			locked = 1;

			clock_gettime(CLOCK_MONOTONIC, &tv);
			tv.tv_sec += 3;

			// pthread_cond_wait(&(data->frame_buffer->cond), &(data->frame_buffer->mutex));
			wait_ret = pthread_cond_timedwait(&(data->frame_buffer->cond), &(data->frame_buffer->mutex), &tv);
			if (wait_ret != 0)
			{
				if (locked)
				{
					pthread_mutex_unlock(&(data->frame_buffer->mutex));
					locked = 0;
				}
				LOG_LOG("blue parse worker timedwait timeout !");
			}
#endif
		}
		else
		{
#ifndef USE_SEM
			if (locked)
			{
				pthread_mutex_unlock(&(data->frame_buffer->mutex));
				locked = 0;
			}
#endif
			/* strcat data */
			memset(readbuff, 0, READSIZE);
			memcpy(readbuff, tmp_data->data, tmp_data->len);
			data_len = tmp_data->len;

#ifdef DEBUG
			printf("read: %d [%s]\n", data_len, readbuff);
#endif
			/* add last data */
			memset(tempbuff, 0, READSIZE * 2);
			if (last_len > 0)
			{
				/*last buff*/

				/* check blue data index */
				if (unlikely(NULL == (pSTART = strstr(readbuff, TYPE_BLUE0))))
				{
					if (NULL == (pSTART = strstr(readbuff, TYPE_BLUE1)))
					{
						if (NULL == (pSTART = strstr(readbuff, TYPE_BLUE2)))
						{
							if (NULL == (pSTART = strstr(readbuff, TYPE_BLUE3)))
								pSTART = strstr(readbuff, TYPE_BLUE4);
						}
					}
				}

#ifdef DEBUG
				printf("last data %d [%s]\n", last_len, last_buff);
#endif
				if (pSTART == readbuff)
				{
					// LOG_LOG("last data %d [%s]", last_len, last_buff);
					memcpy(tempbuff, readbuff, data_len);
				}
				else
				{
					memcpy(tempbuff, last_buff, last_len);
					memcpy(&tempbuff[last_len], readbuff, data_len);
					data_len = data_len + last_len;
				}

				memset(last_buff, 0, 256);
				last_len = 0;
			}
			else
			{
				memcpy(tempbuff, readbuff, data_len);
			}

#ifdef DEBUG
			printf("full data %d [%s]\n", data_len, tempbuff);
#endif
			pdata = tempbuff;

			/* analyze data */
			while (TRUE)
			{
				pEND = strchr(pdata, ';');

				if (pEND != NULL)
				{
					memset(frame_data, 0, MAXFRAMELEN);
					framelen = abs(pEND - pdata) + 1;

					pdata = pdata + framelen;
					data_len = data_len - framelen;

					if (framelen > MAXFRAMELEN)
					{
						LOG_LOG("error data %d:[%s]", framelen, frame_data);
					}
					else if (framelen > 0)
					{
						memcpy(frame_data, (pdata - framelen), framelen);
						/* parse and json data */
						json = NULL;
#ifdef DEBUG
						printf("frame_data[%s]\n", frame_data);
#endif
						json = parse_blue_data(frame_data, data->send_buffer->con);

						/* add json data to send buffer */
						if (NULL != json)
						{
#ifdef DEBUG
							printf("json[%s]\n", json);
#endif
							memset(blue_data, 0, sizeof(Send_data));

							/* fill data */
							framelen = strlen(json);
							blue_data->length = framelen;
							memcpy(blue_data->data, json, blue_data->length);
							/* free json mem */
							free(json);
#ifndef USE_SEM
							pthread_mutex_lock(&data->send_buffer->mutex);
#endif
							if (0 == Rbuf_AddOne(data->send_buffer->ring_buffer, blue_data))
							{
								LOG_LOG("send buffer is full");
							}

#ifndef USE_SEM
							pthread_cond_signal(&data->send_buffer->cond);
							pthread_mutex_unlock(&data->send_buffer->mutex);
#else

							sem_post(&data->send_buffer->sem);
#endif
						}
						/* add to send buffer end */
					}

					if (data_len > 0)
					{
						continue;
					}
					else
					{
						break;
					}
				}
				else
				{
					/*save to last_buff*/
					if (data_len < MAXFRAMELEN)
					{
						memset(last_buff, 0, 256);
						memcpy(last_buff, pdata, data_len);
						last_len = data_len;
#ifdef DEBUG
						printf("end data %d :[%s]\n", last_len, last_buff);
#endif
					}
					else
					{
						LOG_LOG("end data error %d, drop[%s]", data_len, pdata);
					}

					break;
				}
			}
		}
	}

	free(tmp_data);
	free(blue_data);
	return NULL;
}

/* thread func: send data to server */
void *send_thread_func(void *indata)
{
	int blue_sock = 0;
	int result = 0, len = 0, error_time = 0;
	struct sockaddr_in server;
	int locked = 0;
	int wait_ret = 0;

#ifndef USE_SEM
	struct timespec tv;
#endif

	Thread_data *data = (Thread_data *)indata;
	Send_data *sendbuffer = malloc(sizeof(Send_data));

	LOG_LOG("blue server is %s, port is %d", data->con->serverhost, data->con->serverport);

	/*ignore SIGPIPE*/
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGPIPE);
	if (pthread_sigmask(SIG_BLOCK, &signal_mask, NULL) == -1)
	{
		printf("pthread_sigmask SIG_PIPE error\n");
	}
#ifndef TCP_SEND
	/* udp socket init */
UDP_RETRY:
	LOG_LOG("++++++++++++++++send_status :  udp init++++++++++++++++");
	if (blue_sock > 0)
	{
		close(blue_sock);
	}
	blue_sock = udp_client(data->con->serverhost, data->con->serverport, &server);
	result = connect(blue_sock, (struct sockaddr *)&server, sizeof(server));
	if (result == -1)
	{
		LOG_LOG("blue server udp connect error !");
		sleep(5);
		goto UDP_RETRY;
	}

	LOG_LOG("++++++++++++++++send_status : send data++++++++++++++++");
	error_time = 0;
	while (TRUE)
	{
		memset(sendbuffer, 0, sizeof(Send_data));
		len = Rbuf_GetOne(data->ring_buffer, sendbuffer);

		if (len <= 0)
		{
#ifdef USE_SEM
			sem_wait(&data->sem);
#else

			pthread_mutex_lock(&data->mutex);
			locked = 1;

			clock_gettime(CLOCK_MONOTONIC, &tv);
			tv.tv_sec += 10;

			// pthread_cond_wait(&data->cond, &data->mutex);
			wait_ret = pthread_cond_timedwait(&data->cond, &data->mutex, &tv);
			if (wait_ret != 0)
			{
				if (locked)
				{
					pthread_mutex_unlock(&data->mutex);
					locked = 0;
				}
				LOG_LOG("blue send worker timedwait timeout !");
			}
#endif
		}
		else
		{
#ifndef USE_SEM
			if (locked)
			{
				pthread_mutex_unlock(&data->mutex);
				locked = 0;
			}
#endif

			*(sendbuffer->data + sendbuffer->length + 1) = '\n';
			//*(sendbuffer->data + sendbuffer->length + 2) = '\n';

			result = udp_send_data(blue_sock, sendbuffer->data, sendbuffer->length + 1);

			if (result == -1)
			{
				error_time++;
				if (error_time >= 3)
				{
					LOG_LOG("send error long time, maybe server error");
					error_time = 0;
				}
			}
			else
			{
				error_time = 0;
			}
		}
	}
#else
	/* FSM */
	int keepalive = 1;
	int keepidle = 600;
	int keepinterval = 3;
	int keepcount = 3;
	int tcp_nodelay = 0;
	sendstat blue_sendstat = sendstat_start;
	while (TRUE)
	{
		switch (blue_sendstat)
		{
			case sendstat_start:
				LOG_LOG("++++++++++++++++send_status : start  init++++++++++++++++");
				{
					/* do something */
				}
				blue_sendstat = sendstat_creat;
				break;
			case sendstat_creat:
				LOG_LOG("++++++++++++++++send_status : creat tcp  ++++++++++++++++");
				{
					if (blue_sock > 0)
					{
						close(blue_sock);
					}

					blue_sock = tcp_client(data->con->serverhost, data->con->serverport, &server);

					/*set keepalive*/
					setsockopt(blue_sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
					setsockopt(blue_sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
					setsockopt(blue_sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepinterval, sizeof(keepinterval));
					setsockopt(blue_sock, IPPROTO_TCP, TCP_KEEPCNT, &keepcount, sizeof(keepcount));

					/* TCP NAGLE */
					tcp_nodelay = data->con->tcp_nagle;
					// setsockopt(blue_sock, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(tcp_nodelay));
					setsockopt(blue_sock, IPPROTO_TCP, TCP_CORK, &tcp_nodelay, sizeof(tcp_nodelay));

					result = connect(blue_sock, (struct sockaddr *)&server, sizeof(server));
					if (result == -1)
					{
						LOG_LOG("blue server tcp connect error, wait for reconnect !");
						close(blue_sock);
						blue_sock = 0;
						/*next status*/
						blue_sendstat = sendstat_creat;
						sleep(3);
					}
					else
					{
						LOG_LOG("blue server tcp connect sucess!");
						/*clear old buffer data*/
#ifndef USE_SEM
						pthread_mutex_lock(&data->mutex);
#endif
						/*
						if (Rbuf_IsFull(data->ring_buffer))
						{
							Rbuf_Clear(data->ring_buffer);
						}
						*/
						Rbuf_Clear(data->ring_buffer);
#ifndef USE_SEM
						pthread_mutex_unlock(&data->mutex);
#endif

						blue_sendstat = sendstat_send;
					}
				}
				break;
			case sendstat_send:
				LOG_LOG("++++++++++++++++send_status : send data  ++++++++++++++++");
				{
					error_time = 0;
					while (TRUE)
					{
						memset(sendbuffer, 0, sizeof(Send_data));
						len = Rbuf_GetOne(data->ring_buffer, sendbuffer);

						if (len <= 0)
						{
#ifdef USE_SEM
							sem_wait(&data->sem);
#else

							pthread_mutex_lock(&data->mutex);
							locked = 1;

							clock_gettime(CLOCK_MONOTONIC, &tv);
							tv.tv_sec += 10;

							// pthread_cond_wait(&data->cond, &data->mutex);
							wait_ret = pthread_cond_timedwait(&data->cond, &data->mutex, &tv);
							if (wait_ret != 0)
							{
								if (locked)
								{
									pthread_mutex_unlock(&data->mutex);
									locked = 0;
								}
								LOG_LOG("blue send worker timedwait timeout !");
							}
#endif
						}
						else
						{
#ifndef USE_SEM
							if (locked)
							{
								pthread_mutex_unlock(&data->mutex);
								locked = 0;
							}
#endif
							*(sendbuffer->data + sendbuffer->length + 1) = '\n';
							//*(sendbuffer->data + sendbuffer->length + 2) = '\n';

							result = tcp_send_data(blue_sock, sendbuffer->data, sendbuffer->length + 1);

							if (result == -1)
							{
								error_time++;
								if (error_time >= 5)
								{
									LOG_LOG("send error long time, maybe server error");
									blue_sendstat = sendstat_creat;

									break;
								}
							}
							else
							{
								error_time = 0;
							}
						}
					}
				}

				break;
			case sendstat_end:
			default:
				LOG_LOG("++++++++++++++++send_status :     end++++++++++++++++");
				goto END;
		}
	}
#endif

END:
	if (blue_sock > 0)
	{
		close(blue_sock);
	}
	free(sendbuffer);

	return NULL;
}
