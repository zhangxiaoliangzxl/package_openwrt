#include <signal.h>

#include "fast2date.h"
#include "main.h"

/* uwd fd */
int uwb_fd = 0;

/* program run status */
runstats run_status = start;
/* thread run status */
uwbstats uwb_status = uwb_start;
FILE *fp_jiffies = NULL;
config *uwbconfig = NULL;

static void sigpipe_handler()
{
	LOG_LOG("tcp socket from server is closed!");
}

/* func: set cmd to uwb */
int set_uwb_cmd(int fd, char *cmd)
{
	char cmd_str[256] = {0};
	int ret = 0;
	if (NULL == cmd || fd <= 0)
	{
		return -1;
	}

	sprintf(cmd_str, "%s\n", cmd);
	ret = write(fd, cmd_str, strlen(cmd_str));
	if (ret < 0)
	{
		syslog(LOG_ERR, "write to uwb error !");
	}

	return ret;
}

int uwb_cmd(char *cmd)
{
	int uwb_fd = 0;
	FILE *file = NULL;
	char uwbtty[20] = {0};

	if (NULL == cmd || strlen(cmd) < 1)
	{
		syslog(LOG_ERR, "cmd is null !");
		return -1;
	}
	else
	{
		// printf("cmd is : %s \n", cmd);
	}

	/* open and init tty devices */
	file = popen(TTY, "r");
	if (file)
	{
		fgets(uwbtty, sizeof(uwbtty), file);
	}
	pclose(file);

	if (NULL != strstr(cmd, "ttyinit"))
	{
		uwb_fd = init_tty(uwbtty, 1);
		syslog(LOG_INFO, "tty init ok!");
	}
	else if (NULL != strstr(cmd, "version"))
	{
		uwb_fd = init_tty(uwbtty, 1);
		printf("Version:1.1\n");
	}
	else
	{
		uwb_fd = init_tty(uwbtty, 0);
		/* set to uwb */
		set_uwb_cmd(uwb_fd, cmd);
	}

	close(uwb_fd);
	return 0;
}

/* thread func: uwb server tcp and send */
void *tcpsend_thread_func(void *indata)
{
	int uwb_sock = 0, result = 0, len = 0, error_time = 0;
	struct sockaddr_in uwb_server;
	int sendlen = 0;
	char *tcp_send_data = NULL;

	int keepalive = 1;
	int keepidle = 600;
	int keepinterval = 3;
	int keepcount = 3;
	int tcp_nodelay = 0;

#ifdef TLV_SEND
	TLV_data *tlvdata;
#else
	int jsonlen = 0;
#endif

	Thread_data *data = (Thread_data *)indata;
	char *tmp_data = malloc(1024);

	/* FSM */
	while (TRUE)
	{
		switch (uwb_status)
		{
			case uwb_start:
				LOG_LOG("++++++++++++++++tcpsend_status : start  init++++++++++++++++");
				{
					LOG_LOG("uwb tcp server is %s, port is %d", data->con->ip, data->con->port);

					/*ignore SIGPIPE*/
					sigset_t signal_mask;
					sigemptyset(&signal_mask);
					sigaddset(&signal_mask, SIGPIPE);
					if (pthread_sigmask(SIG_BLOCK, &signal_mask, NULL) == -1)
					{
						printf("pthread_sigmask SIG_PIPE error\n");
					}
				}
				uwb_status = uwb_creat;
				break;
			case uwb_creat:
				LOG_LOG("++++++++++++++++tcpsend_status : creat tcp++++++++++++++++");
				{
					// LOG_LOG("start debug server tcp connect !");
					if (uwb_sock > 0)
					{
						close(uwb_sock);
					}
					LOG_LOG("tcp connect to uwb server %s:%d", data->con->ip, data->con->port);

					uwb_sock = TCP_clien(data->con->ip, data->con->port, &uwb_server);

					/*set keepalive*/
					setsockopt(uwb_sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
					setsockopt(uwb_sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
					setsockopt(uwb_sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepinterval, sizeof(keepinterval));
					setsockopt(uwb_sock, IPPROTO_TCP, TCP_KEEPCNT, &keepcount, sizeof(keepcount));

					/* TCP NAGLE */
					tcp_nodelay = data->con->tcp_nagle;
					// setsockopt(uwb_sock, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(tcp_nodelay));
					setsockopt(uwb_sock, IPPROTO_TCP, TCP_CORK, &tcp_nodelay, sizeof(tcp_nodelay));

					result = connect(uwb_sock, (struct sockaddr *)&uwb_server, sizeof(uwb_server));
					if (result == -1)
					{
						LOG_LOG("uwb server tcp connect error, wait for reconnect !");
						close(uwb_sock);
						uwb_sock = 0;
						/*next status*/
						uwb_status = uwb_creat;
						sleep(3);
					}
					else
					{
						LOG_LOG("uwb server tcp connect sucess!");
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

						uwb_status = uwb_send;
					}
					/*creat timer for keepalive*/
				}
				break;
			case uwb_send:
				LOG_LOG("++++++++++++++++tcpsend_status : send data++++++++++++++++");
				{
					error_time = 0;
					while (TRUE)
					{
						pthread_mutex_lock(&data->mutex);

						memset(tmp_data, 0, 1024);
						len = Rbuf_GetOne(data->ring_buffer, tmp_data);

						if (len <= 0)
						{
							// usleep(5000);
							pthread_cond_wait(&data->cond, &data->mutex);
						}
						else
						{
#ifdef TLV_SEND
							tlvdata = (TLV_data *)tmp_data;

							tcp_send_data = tlvdata->data;
							sendlen = tlvdata->length;

							/* for test
							printf("send len %d\n", sendlen);
							printf_hex("tcp send data", tcp_send_data, sendlen);
							*/
#else
							jsonlen = strlen(tmp_data);
							strcpy(&tmp_data[jsonlen], "\r\n");
							sendlen = jsonlen + 2;
							tcp_send_data = tmp_data;
#endif

							result = send_data(uwb_sock, &uwb_server, tcp_send_data, sendlen);

							if (result == -1)
							{
								error_time++;
								if (error_time >= 3)
								{
									LOG_LOG("send error long time, maybe tcp error");
									uwb_status = uwb_creat;

									pthread_mutex_unlock(&data->mutex);
									break;
								}
							}
							else
							{
								error_time = 0;
							}
						}

						pthread_mutex_unlock(&data->mutex);
					}
				}

				break;
			case uwb_end:
			default:
				LOG_LOG("++++++++++++++++tcpsend_status :     end++++++++++++++++");
				goto END;
		}
	}

END:
	close(uwb_sock);
	free(tmp_data);

	return NULL;
}

/* main func */
int main(int argc, char *argv[])
{
	FILE *file;
	char disabled[2], pint[2];
	int disabled_int;

	/*********************** uwb cmd process *********************/
	int ret_exit = 0;
	if (argc >= 2)
	{
		int cmd_num;
		char cmd_buff[256] = {0};
		char tmp_buff[128] = {0};

		openlog("UWBCMD", LOG_CONS | LOG_PID, LOG_USER);
		syslog(LOG_INFO, "##############UWB CMD############");
		for (cmd_num = 0; cmd_num < argc; cmd_num++)
		{
			if (cmd_num > 0)
			{
				memset(tmp_buff, 0, sizeof(tmp_buff));
				sprintf(tmp_buff, "%s ", argv[cmd_num]);
				strcat(cmd_buff, tmp_buff);
			}
		}
		if (strlen(cmd_buff) > 0)
		{
			syslog(LOG_INFO, "cmd: %s", cmd_buff);

			/* send cmd to main process */
			ret_exit = uwb_cmd(cmd_buff);
		}

		syslog(LOG_INFO, "###########UWB CMD END###########");

		closelog();
		exit(ret_exit);
	}

	/*********************** main process ************************/
	my_time_init();

	/* init logfile */
	system("rm /tmp/uwb -rf");
	system("mkdir /tmp/uwb");

	int ret, result;
	ret = 0;

	struct timeval now_time;
	char jiffies_buf[20] = {0};

	Thread_data tcpsend_buffer_threadData;   // for tcpsend
	Thread_data uwb_prase_buffer_threadData; // for uwb_prase
	Thread_data ppp_frame_buffer_threadData; // for ppp_frame

	Prase_data uwb_prase_thread_indata; // for tcpsend_thread
	Frame_data ppp_frame_thread_indata; // for uwb_prase_thread

	pthread_t thread_tcpsend;
	pthread_t thread_uwb_parse;
	pthread_t thread_ppp_frame;

	/* ignore the SIGPIPE when tcp socket is closed, if not process will exit */
	/* tcp server socket closed func */
	signal(SIGPIPE, sigpipe_handler);

	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGPIPE);
	int rc = pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
	if (rc != 0)
	{
		LOG_LOG("block sigpipe error!");
	}

	while (TRUE)
	{
		/* FSM */
		switch (run_status)
		{
			case start:
				LOG_LOG("----------------run_status : start  init---------------");
				{
					LOG_LOG("init uwb info!");

					uwbconfig = (config *)malloc(sizeof(config));

					/* config init */
					ret = init(uwbconfig);
					if (ret < 0)
					{
						LOG_LOG("init error, exit!");
						return -1;
					}

					LOG_LOG("print_enable %d", uwbconfig->print_enable);

					if (uwbconfig->print_enable == 1)
					{
						uwbconfig->print_buff = malloc(PRINT_BUFF_SIZE);
					}

					/* recode first time for ac */
					fp_jiffies = fopen(DATA_JIFFIES, "w+");
					if (NULL == fp_jiffies)
					{
						LOG_LOG("DATA_JIFFIES open error !");
						return -1;
					}
					gettimeofday(&now_time, NULL);
					memset(jiffies_buf, 0, sizeof(jiffies_buf));
					JSONDATA_TIME(&now_time, jiffies_buf);
					write_jiffies(fp_jiffies, jiffies_buf);

					/* creat tcpsend thread to tcp send data */
					{
						tcpsend_buffer_threadData.con = uwbconfig;
						tcpsend_buffer_threadData.ring_buffer = malloc(sizeof(struct ring_buffer_t));

						char *tcpsend_buffer = malloc(4 * 1024 * MAXLENGTH_JSONDATA);
						Rbuf_Init(tcpsend_buffer_threadData.ring_buffer, tcpsend_buffer, MAXLENGTH_JSONDATA,
								  4 * 1024); // 4 * 1024 * 512 = 4 * 512kbyte , json data  < 512byte  2m
						Rbuf_Clear(tcpsend_buffer_threadData.ring_buffer);
						pthread_mutex_init(&tcpsend_buffer_threadData.mutex, NULL);
						pthread_cond_init(&tcpsend_buffer_threadData.cond, NULL);

						ret = pthread_create(&thread_tcpsend, NULL, tcpsend_thread_func,
											 (void *)(&tcpsend_buffer_threadData));
						if (ret != 0)
						{
							LOG_LOG("tcpsend thread create failed!");
						}
						pthread_detach(thread_tcpsend);
					}

					/* init ppp_frame_buffer_threadData && uwb_prase_buffer_threadData and creat thread */
					{
						/* ppp_frame_buffer */
						ppp_frame_buffer_threadData.ring_buffer = malloc(sizeof(struct ring_buffer_t));

						char *tty_read_buffer = malloc(8 * 1024 * (sizeof(ttyread_data))); // 4*1024*260 byte
						Rbuf_Init(ppp_frame_buffer_threadData.ring_buffer, tty_read_buffer, (sizeof(ttyread_data)),
								  8 * 1024); // 8 * 1024 * (256+4)  2m
						Rbuf_Clear(ppp_frame_buffer_threadData.ring_buffer);
						pthread_mutex_init(&ppp_frame_buffer_threadData.mutex, NULL);
						pthread_cond_init(&ppp_frame_buffer_threadData.cond, NULL);

						/* uwb_parse_buffer */
						uwb_prase_buffer_threadData.con = uwbconfig;
						uwb_prase_buffer_threadData.ring_buffer = malloc(sizeof(struct ring_buffer_t));

						char *uwb_prase_buffer = malloc(16 * 1024 * (sizeof(ppp_frame_data)));
						Rbuf_Init(uwb_prase_buffer_threadData.ring_buffer, uwb_prase_buffer, (sizeof(ppp_frame_data)),
								  16 * 1024); // 2*8*1024*(8+2+MAXLENGTH_HEX_UWB) 2m
						Rbuf_Clear(uwb_prase_buffer_threadData.ring_buffer);
						pthread_mutex_init(&uwb_prase_buffer_threadData.mutex, NULL);
						pthread_cond_init(&uwb_prase_buffer_threadData.cond, NULL);

						uwb_prase_thread_indata.pppframe_buffer = &uwb_prase_buffer_threadData;
						uwb_prase_thread_indata.tcpsend_buffer = &tcpsend_buffer_threadData;

						ppp_frame_thread_indata.ttyread_buffer = &ppp_frame_buffer_threadData;
						ppp_frame_thread_indata.pppframe_buffer = &uwb_prase_buffer_threadData;

						/* creat ppp_frame thread */
						ret = pthread_create(&thread_ppp_frame, NULL, ppp_frame_thread_func,
											 (void *)(&ppp_frame_thread_indata));
						if (ret != 0)
						{
							LOG_LOG("string thread create failed!");
						}
						pthread_detach(thread_ppp_frame);

						/* creat uwb_parse thread */
						ret = pthread_create(&thread_uwb_parse, NULL, uwb_parse_thread_func,
											 (void *)(&uwb_prase_thread_indata));
						if (ret != 0)
						{
							LOG_LOG("parse thread create failed!");
						}
						pthread_detach(thread_uwb_parse);
					}
				}
				run_status = serail;
				break;
			case serail:
				LOG_LOG("----------------run_status : open serail---------------");
				{
					if (uwb_fd > 0)
					{
						close(uwb_fd);
					}
					uwb_fd = DEV_FILE(uwbconfig->tty);
					if (uwb_fd < 0)
					{
						LOG_LOG("open %s error, retry after 3s!", uwbconfig->tty);
						sleep(3);
						run_status = serail;
					}
					else
					{
						LOG_LOG("open %s sucess!", uwbconfig->tty);

						run_status = readdata;
					}
				}
				break;
			case readdata:
				LOG_LOG("----------------run_status : readdata---------------");
				{
					/*read data from serail port to read_data buffer*/
					while (TRUE)
					{
						ret = recevice_from_tty(uwb_fd, &ppp_frame_buffer_threadData);
						// ret = read_data(uwb_fd, &ppp_frame_buffer_threadData);

						if (ret < 0)
						{
							if (ret < -1)
							{
								LOG_LOG("maybe serail is error, reopen serail !");
								run_status = serail;
								break; // break while
							}
							continue;
						}
					}
				}
				break;
			case end:
			default:
				LOG_LOG("----------------run_status :     end---------------");
				goto END;
				// break;
		}
	}

END:
	fclose(fp_jiffies);
	close(uwb_fd);
	if (NULL != uwbconfig->print_buff)
	{
		free(uwbconfig->print_buff);
	}
	free(uwbconfig);

	/* cancel parse thread */
	Free_Thread_data(uwb_prase_buffer_threadData);
	ret = -1;
	do
	{
		ret = pthread_cancel(thread_uwb_parse);
	} while (ret != 0);

	/* cancel string thread */
	Free_Thread_data(ppp_frame_buffer_threadData);
	ret = -1;
	do
	{
		ret = pthread_cancel(thread_ppp_frame);
	} while (ret != 0);

	/* cancel main thread */
	Free_Thread_data(tcpsend_buffer_threadData);
	ret = -1;
	do
	{
		ret = pthread_cancel(thread_tcpsend);
	} while (ret != 0);

	LOG_LOG("----------------run_status is end, exit program---------------");

	return 0;
}

void Free_Thread_data(Thread_data data)
{
	pthread_mutex_destroy(&data.mutex);
	pthread_cond_destroy(&data.cond);
	Rbuf_Free(data.ring_buffer);
	free(data.ring_buffer);
}

