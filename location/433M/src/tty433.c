/*************************************************************************
>  File Name: tty_ppp.c
>  Author: zxl
>  Mail:
>  Created Time: Wed 20 Mar 2019 02:33:03 PM CST
*************************************************************************/
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>

#include <sys/epoll.h>
#include <sys/stat.h>

#include "elog.h"
#include "init.h"
#include "send.h"
#include "tty433.h"

#include <cjson/cJSON.h>

extern FILE *fp_jiffies;
extern config *config_433;

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

static void printdata(char *buff)
{
	dataLOG(buff);
}

int TTY_OPEN(char *ttydev)
{
	int fd;
	char error[30] = "0";
	char buff[10] = "0";

	memset(buff, 0, sizeof(buff));
	// strcpy(buff, con->interface);
	fd = open(ttydev, O_RDWR | O_NOCTTY | O_NONBLOCK);
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
	serial.xmit_fifo_size = 1024 * 2048; // 2M
	ioctl(fd, TIOCSSERIAL, &serial);
#endif

	struct termios opt;
	tcgetattr(fd, &opt);
	cfsetispeed(&opt, B921600);
	cfsetospeed(&opt, B921600);

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
		log_e("set Serial port error");
		return -1;
	}

	return fd;
}

int init_tty(char *ttydev, int ttyinit)
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
		cfsetispeed(&opt, B921600);
		cfsetospeed(&opt, B921600);
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

int recevice_from_tty(int fd, Thread_data *ttyread_buffer)
{
	int ret = 0;
	char readbuff[READSIZE + 1] = {0};
	int epid;
	int recv_len;

	ttyread_data *read_data = NULL;
	read_data = (ttyread_data *)malloc(sizeof(ttyread_data));

	/* epoll init */
	epid = epoll_create(1);
	struct epoll_event event_tty;
	// event_tty.events = EPOLLIN | EPOLLET; // ET mode
	event_tty.events = EPOLLIN; // LT mode
	event_tty.data.fd = fd;
	ret = epoll_ctl(epid, EPOLL_CTL_ADD, fd, &event_tty);
	if (ret != 0)
	{
		log_e("set epoll error!");
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
						/* add to read_buffer */
						memset(read_data, 0, sizeof(ttyread_data));
						memcpy(read_data->data, readbuff, recv_len);
						read_data->len = recv_len;

						pthread_mutex_lock(&ttyread_buffer->mutex);
						if (0 == Rbuf_AddOne(ttyread_buffer->ring_buffer, read_data))
						{
							log_w("ttyread ring buffer is full");
						}
						pthread_cond_signal(&ttyread_buffer->cond);
						pthread_mutex_unlock(&ttyread_buffer->mutex);
						/* add to ttyread_buffer end */

						if (recv_len < READSIZE)
						{
							/* buffer no other data, should break while, do next read */
							break;
						}
					}
					else if (recv_len == 0)
					{
						/* buffer is empty, should break while */

						if (errno == EINVAL)
						{
							log_e("read from tty error, errorid %d %s !\n", errno, strerror(errno));
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
							break;
						}
						else
						{
							log_e("read from tty error, errorid %d %s !", errno, strerror(errno));
							close(epid);
							free(read_data);
							return -2;
						}
					}
				}
			}
			else if (event_tty.events & EPOLLERR || event_tty.events & EPOLLHUP || (!event_tty.events & EPOLLIN))
			{
				log_e("epoll_wait return error event , maybe tty is error!\n");
				/* close epoll id */
				close(epid);
				free(read_data);
				return -2;
			}
		}
		else if (ret < 0)
		{
			if (errno != EINTR)
			{
				log_e("epoll_wait return error, errorid %d %s !", errno, strerror(errno));
				close(epid);
				free(read_data);
				return -2;
			}
		}
		/* ret = 0 , epoll_wait timeout */
	}

	close(epid);
	free(read_data);
	return 0;
}

static char *parse_433_data(char *data, config *conf)
{
	char *pNext = NULL, *pStart = NULL;
	cJSON *root = NULL, *dataArray = NULL, *datatemp = NULL;
	char *out = NULL;
	int num = 0, i = 0;

	static struct timeval cur_time;
	static char sys_time[20] = {0};

	/* data example
	 * RF433M[-30]{AID:65535,TID:1,SEQ:62,NUM:6,DATA:{[0,0,0,-68,96],[0,0,4690,-77,96],[0,0,4694,-85,96],[0,0,4602,-84,96],[0,0,4689,-86,96],[0,0,4690,-76,96]}};
	 */

	/* get sys_time */
	gettimeofday(&cur_time, NULL);
	memset(sys_time, 0, sizeof(sys_time));
	JSONDATA_TIME(&cur_time, sys_time);

	/* init json root */
	root = cJSON_CreateObject();
	cJSON_AddStringToObject(root, "devmac", conf->mac);
	cJSON_AddStringToObject(root, "time", sys_time);
	cJSON_AddStringToObject(root, "type", "433");

	/* BS Rssi */
	pNext = data;
	pStart = strstr(pNext, "RF433M[");
	if (pStart != NULL)
	{
		pStart = pStart + strlen("RF433M[");
		pNext = strchr(pStart, ']');
	}
	else
		goto ERROR;

	if (pNext != NULL)
	{
		*pNext = ENDCHAR;
		pNext++;
		cJSON_AddStringToObject(root, "BSRSSI", pStart);
	}

	/* AID */
	pStart = strstr(pNext, "AID:");
	if (pStart != NULL)
	{
		pStart = pStart + strlen("AID:");
		pNext = strchr(pStart, ',');
	}
	else
		goto ERROR;

	if (pNext != NULL)
	{
		*pNext = ENDCHAR;
		pNext++;
		cJSON_AddStringToObject(root, "AID", pStart);
	}

	/* TID */
	pStart = strstr(pNext, "TID:");
	if (pStart != NULL)
	{
		pStart = pStart + strlen("TID:");
		pNext = strchr(pStart, ',');
	}
	else
		goto ERROR;

	if (pNext != NULL)
	{
		*pNext = ENDCHAR;
		pNext++;
		cJSON_AddStringToObject(root, "TID", pStart);
	}

	/* SEQ */
	pStart = strstr(pNext, "SEQ:");
	if (pStart != NULL)
	{
		pStart = pStart + strlen("SEQ:");
		pNext = strchr(pStart, ',');
	}
	else
		goto ERROR;

	if (pNext != NULL)
	{
		*pNext = ENDCHAR;
		pNext++;
		cJSON_AddStringToObject(root, "SEQ", pStart);
	}

	/* NUM */
	pStart = strstr(pNext, "NUM:");
	if (pStart != NULL)
	{
		pStart = pStart + strlen("NUM:");
		pNext = strchr(pStart, ',');
	}
	else
		goto ERROR;

	if (pNext != NULL)
	{
		*pNext = ENDCHAR;
		pNext++;
		num = atoi(pStart);
	}

	if (num > 6)
	{
		log_e("data num %d over maxnum !", num);
		goto ERROR;
	}

	/* DATA */
	pStart = strstr(pNext, "DATA:{");
	if (pStart != NULL)
	{
		pStart = pStart + strlen("DATA:{");
		pNext = pStart;
	}
	else
		goto ERROR;

	dataArray = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "DATA", dataArray);

	if (pNext != NULL)
	{
		for (i = 0; i < num; i++)
		{
			cJSON_AddItemToArray(dataArray, datatemp = cJSON_CreateObject());

			/* TICK */
			pStart = strchr(pNext, '[');
			if (pStart != NULL)
			{
				pStart++;
				pNext = strchr(pStart, ',');
			}
			else
				goto ERROR;

			if (pNext != NULL)
			{
				*pNext = ENDCHAR;
				pNext++;
				cJSON_AddItemToObject(datatemp, "TICK", cJSON_CreateString(pStart));
			}

			/* MAJOR */
			pStart = pNext;
			if (pStart != NULL)
			{
				pNext = strchr(pStart, ',');
			}
			else
				goto ERROR;

			if (pNext != NULL)
			{
				*pNext = ENDCHAR;
				pNext++;
				cJSON_AddItemToObject(datatemp, "MAJOR", cJSON_CreateString(pStart));
			}

			/* MINOR */
			pStart = pNext;
			if (pStart != NULL)
			{
				pNext = strchr(pStart, ',');
			}
			else
				goto ERROR;

			if (pNext != NULL)
			{
				*pNext = ENDCHAR;
				pNext++;
				cJSON_AddItemToObject(datatemp, "MINOR", cJSON_CreateString(pStart));
			}

			/* RSSI */
			pStart = pNext;
			if (pStart != NULL)
			{
				pNext = strchr(pStart, ',');
			}
			else
				goto ERROR;

			if (pNext != NULL)
			{
				*pNext = ENDCHAR;
				pNext++;
				cJSON_AddItemToObject(datatemp, "RSSI", cJSON_CreateString(pStart));
			}

			/* BAT */
			pStart = pNext;
			if (pStart != NULL)
			{
				pNext = strchr(pStart, ']');
			}
			else
				goto ERROR;

			if (pNext != NULL)
			{
				*pNext = ENDCHAR;
				pNext++;
				cJSON_AddItemToObject(datatemp, "BAT", cJSON_CreateString(pStart));
			}
		}
	}

	/* no format json data */
	out = cJSON_PrintUnformatted(root);

	/* debug data */
	if (1 == conf->print_enable)
	{
		printdata(out);
	}

ERROR:
	cJSON_Delete(root);

	return out;
}

/* parse_thread func: read frome tty buffer and parse 433 data to json data, send to send thread */
void *parse_thread_func(void *indata)
{
	int ret = 0, framelen = 0;
	char readbuff[READSIZE] = {0};
	char tempbuff[READSIZE * 2] = {0};
	char *pdata = NULL;
	char *json = NULL;

	char last_buff[MAXFRAMELEN * 2] = {0};
	int last_len = 0;

	char frame_data[MAXFRAMELEN];

	int data_len = 0;
	char *pSTART = NULL;
	char *pEND = NULL;
	char *p = NULL;

	int locked = 0;
	struct timespec tv;
	int wait_ret = 0;

	Thread_indata *data = (Thread_indata *)indata;

	ttyread_data *tmp_data = (ttyread_data *)malloc(sizeof(ttyread_data));
	send_data *data_433 = (send_data *)malloc(sizeof(send_data));

	/* read data from tty read buffer */
	while (TRUE)
	{
		memset(tmp_data, 0, sizeof(ttyread_data));
		ret = Rbuf_GetOne(data->in_buffer->ring_buffer, tmp_data);

		if (ret <= 0)
		{
			/* no data read from ttyread buffer */

			/* wait */
			pthread_mutex_lock(&(data->in_buffer->mutex));
			locked = 1;

			clock_gettime(CLOCK_MONOTONIC, &tv);
			tv.tv_sec += 15;

			wait_ret = pthread_cond_timedwait(&(data->in_buffer->cond), &(data->in_buffer->mutex), &tv);
			if (wait_ret != 0)
			{
				if (locked)
				{
					pthread_mutex_unlock(&(data->in_buffer->mutex));
					locked = 0;
				}
				log_w("parse worker timedwait timeout !");
			}
		}
		else
		{
			if (locked)
			{
				pthread_mutex_unlock(&(data->in_buffer->mutex));
				locked = 0;
			}

			/* strcat data */

			memset(readbuff, 0, READSIZE);
			memcpy(readbuff, tmp_data->data, tmp_data->len);
			data_len = tmp_data->len;

			/* add last data */
			memset(tempbuff, 0, READSIZE * 2);
			if (last_len > 0)
			{
				/*last buff*/
				pSTART = strstr(readbuff, "RF433M");

				if (pSTART == readbuff)
				{
					memcpy(tempbuff, readbuff, data_len);
				}
				else
				{
					memcpy(tempbuff, last_buff, last_len);
					memcpy(&tempbuff[last_len], readbuff, data_len);
					data_len = data_len + last_len;
				}

				memset(last_buff, 0, MAXFRAMELEN * 2);
				last_len = 0;
			}
			else
			{
				memcpy(tempbuff, readbuff, data_len);
			}

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
						log_w("error data %d:[%s]", framelen, frame_data);
					}
					else if (framelen > 0)
					{
						memcpy(frame_data, (pdata - framelen), framelen);
						/* parse and json data */
						json = NULL;

						json = parse_433_data(frame_data, data->out_buffer->con);

						/* add json data to send buffer */
						if (NULL != json)
						{
							memset(data_433, 0, sizeof(send_data));

							/* fill data */
							framelen = strlen(json);
							data_433->length = framelen;
							memcpy(data_433->data, json, data_433->length);
							/* free json mem */
							free(json);

							pthread_mutex_lock(&data->out_buffer->mutex);
							if (0 == Rbuf_AddOne(data->out_buffer->ring_buffer, data_433))
							{
								log_w("send buffer is full");
							}

							pthread_cond_signal(&data->out_buffer->cond);
							pthread_mutex_unlock(&data->out_buffer->mutex);
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
						memset(last_buff, 0, MAXFRAMELEN * 2);
						memcpy(last_buff, pdata, data_len);
						last_len = data_len;
					}
					else
					{
						log_w("end data error %d, drop[%s]", data_len, pdata);
					}

					break;
				}
			}
		}
	}

	free(tmp_data);
	free(data_433);
	return NULL;
}

/* send thread func: send data to server */
void *send_thread_func(void *indata)
{
	int send_sock = 0;
	int result = 0, len = 0, error_time = 0;
	struct sockaddr_in server;

	int locked = 0;
	int wait_ret = 0;
	struct timespec tv;

	Thread_data *data = (Thread_data *)indata;
	send_data *sendbuffer = malloc(sizeof(send_data));

	log_i("server is %s, port is %d", data->con->serverhost, data->con->serverport);

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
	log_i("++++++++++++++++send_status :  udp init++++++++++++++++");
	if (send_sock > 0)
	{
		close(send_sock);
	}
	send_sock = udp_client(data->con->serverhost, data->con->serverport, &server);
	result = connect(send_sock, (struct sockaddr *)&server, sizeof(server));
	if (result == -1)
	{
		log_e("server udp connect error !");
		sleep(3);
		goto UDP_RETRY;
	}

	log_i("++++++++++++++++send_status : send data++++++++++++++++");
	error_time = 0;
	while (TRUE)
	{
		memset(sendbuffer, 0, sizeof(send_data));
		len = Rbuf_GetOne(data->ring_buffer, sendbuffer);

		if (len <= 0)
		{
			pthread_mutex_lock(&data->mutex);
			locked = 1;

			clock_gettime(CLOCK_MONOTONIC, &tv);
			tv.tv_sec += 15;

			wait_ret = pthread_cond_timedwait(&data->cond, &data->mutex, &tv);
			if (wait_ret != 0)
			{
				if (locked)
				{
					pthread_mutex_unlock(&data->mutex);
					locked = 0;
				}
				log_w("send worker timedwait timeout !");
			}
		}
		else
		{
			if (locked)
			{
				pthread_mutex_unlock(&data->mutex);
				locked = 0;
			}

			*(sendbuffer->data + sendbuffer->length + 1) = '\n';

			result = udp_send_data(send_sock, sendbuffer->data, sendbuffer->length + 1);

			if (result == -1)
			{
				error_time++;
				if (error_time >= 5)
				{
					log_e("send error long time, maybe network or server error");
					error_time = 0;
					goto UDP_RETRY;
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
	sendstat 433_sendstat = sendstat_start;
	while (TRUE)
	{
		switch (433_sendstat)
		{
			case sendstat_start:
				log_i("++++++++++++++++send_status : start  init++++++++++++++++");
				{
					/* do something */
				}
				433_sendstat = sendstat_creat;
				break;
			case sendstat_creat:
				log_i("++++++++++++++++send_status : creat tcp  ++++++++++++++++");
				{
					if (send_sock > 0)
					{
						close(send_sock);
					}

					send_sock = tcp_client(data->con->serverhost, data->con->serverport, &server);

					/*set keepalive*/
					setsockopt(send_sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
					setsockopt(send_sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
					setsockopt(send_sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepinterval, sizeof(keepinterval));
					setsockopt(send_sock, IPPROTO_TCP, TCP_KEEPCNT, &keepcount, sizeof(keepcount));

					/* TCP NAGLE */
					tcp_nodelay = data->con->tcp_nagle;
					// setsockopt(blue_sock, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(tcp_nodelay));
					setsockopt(send_sock, IPPROTO_TCP, TCP_CORK, &tcp_nodelay, sizeof(tcp_nodelay));

					result = connect(send_sock, (struct sockaddr *)&server, sizeof(server));
					if (result == -1)
					{
						log_i("blue server tcp connect error, wait for reconnect !");
						close(send_sock);
						send_sock = 0;
						/*next status*/
						433_sendstat = sendstat_creat;
						sleep(3);
					}
					else
					{
						log_i("blue server tcp connect sucess!");
						/*clear old buffer data*/
						pthread_mutex_lock(&data->mutex);
						/*
						if (Rbuf_IsFull(data->ring_buffer))
						{
							Rbuf_Clear(data->ring_buffer);
						}
						*/
						Rbuf_Clear(data->ring_buffer);
						pthread_mutex_unlock(&data->mutex);

						433_sendstat = sendstat_send;
					}
				}
				break;
			case sendstat_send:
				log_i("++++++++++++++++send_status : send data  ++++++++++++++++");
				{
					error_time = 0;
					while (TRUE)
					{
						memset(sendbuffer, 0, sizeof(Send_data));
						len = Rbuf_GetOne(data->ring_buffer, sendbuffer);

						if (len <= 0)
						{
							pthread_mutex_lock(&data->mutex);
							locked = 1;

							clock_gettime(CLOCK_MONOTONIC, &tv);
							tv.tv_sec += 15;

							wait_ret = pthread_cond_timedwait(&data->cond, &data->mutex, &tv);
							if (wait_ret != 0)
							{
								if (locked)
								{
									pthread_mutex_unlock(&data->mutex);
									locked = 0;
								}
								log_w("send worker timedwait timeout !");
							}
						}
						else
						{
							if (locked)
							{
								pthread_mutex_unlock(&data->mutex);
								locked = 0;
							}

							*(sendbuffer->data + sendbuffer->length + 1) = '\n';

							result = tcp_send_data(send_sock, sendbuffer->data, sendbuffer->length + 1);

							if (result == -1)
							{
								error_time++;
								if (error_time >= 5)
								{
									log_i("send error long time, maybe server error");
									433_sendstat = sendstat_creat;
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
				log_i("++++++++++++++++send_status :     end++++++++++++++++");
				goto END;
		}
	}
#endif

END:
	if (send_sock > 0)
	{
		close(send_sock);
	}
	free(sendbuffer);

	return NULL;
}
