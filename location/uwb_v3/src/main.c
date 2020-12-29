#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <syslog.h>
#include <sys/stat.h>

#include "elog.h"
#include "main.h"
#include "send.h"

/* uwd fd */
int uwb_fd = 0;

TcpStatus tcp_status = TCP_start;
/* program run status */
runstats run_status = start;
/* thread run status */
uwbstats uwb_status = uwb_start;
FILE *fp_jiffies = NULL;
config *uwbconfig = NULL;

static void setThreadHighPriority(pthread_t setthread, bool value)
{
	// Start out with a standard, low-priority setup for the sched params.
	struct sched_param sp;
	bzero((void *)&sp, sizeof(sp));
	int policy = SCHED_OTHER;

	// If desired, set up high-priority sched params structure.
	if (value)
	{
		// FIFO scheduler, ranked above default SCHED_OTHER queue
		policy = SCHED_FIFO;
		// The priority only compares us to other SCHED_FIFO threads, so we
		// just pick a random priority halfway between min & max.
		const int priority = (sched_get_priority_max(policy) + sched_get_priority_min(policy)) / 2;

		sp.sched_priority = priority;
	}

	// Actually set the sched params for the current thread.
	if (0 == pthread_setschedparam(setthread, policy, &sp))
	{
		log_i("Thread #%d using high-priority scheduler!", setthread);
	}
}

static void logger_init(void)
{
	/* elog sys time init */
	elog_time_init();

	/* close printf buffer */
	setbuf(stdout, NULL);
	/* initialize EasyLogger */
	ElogFileCfg cfg;
	cfg.name = LOGFILE_NAME;
	cfg.max_size = 1 * 1024 * 1024;
	cfg.max_rotate = 0;

	elog_init(&cfg);

	elog_set_fmt(ELOG_LVL_ASSERT, ELOG_FMT_ALL & ~ELOG_FMT_TAG);
	elog_set_fmt(ELOG_LVL_VERBOSE, ELOG_FMT_ALL & ~ELOG_FMT_TAG);
	elog_set_fmt(ELOG_LVL_ERROR, ELOG_FMT_TIME);
	elog_set_fmt(ELOG_LVL_WARN, ELOG_FMT_TIME);
	elog_set_fmt(ELOG_LVL_INFO, ELOG_FMT_TIME);
	elog_set_fmt(ELOG_LVL_DEBUG, ELOG_FMT_TIME);
#ifdef ELOG_COLOR_ENABLE
	elog_set_text_color_enabled(true);
#endif
	/* start EasyLogger */
	elog_start();

	/* dynamic set enable or disable for output logs (true or false) */
	elog_set_output_enabled(true);
	/* dynamic set enable or disable for output stdout (true or false) */
#ifdef DEBUG_STDOUT
	elog_set_stdout_enabled(true);
#else
	elog_set_stdout_enabled(false);
#endif
	/* dynamic set output logs's level (from ELOG_LVL_ASSERT to ELOG_LVL_VERBOSE) */
	elog_set_filter_lvl(ELOG_LVL_DEBUG);

	/* dynamic set output logs's filter for tag */
	// elog_set_filter_tag("main");
	/* dynamic set output logs's filter for keyword */
	// elog_set_filter_kw("Hello");
}

static void sigpipe_handler()
{
	log_w("tcp socket from server is closed!");
}

/* func: send uwb cmd to main process */
static int uwb_cmd_send(char *cmd)
{
	int uwbset_fd;
	int ret;
	int unix_mode = 0;
	static struct sockaddr_un srv_addr;

	if (NULL == cmd || strlen(cmd) < 1)
	{
		printf("cmd is null !\n");
		return -1;
	}
	else
	{
		// printf("uwb cmd is : %s \n", cmd);
	}

	/* use unix socket or direct mode */
	if (access(UNIX_DOMAIN_CMD, F_OK) == 0)
	{
		/* creat unix socket */
		uwbset_fd = socket(PF_UNIX, SOCK_STREAM, 0);
		if (uwbset_fd < 0)
		{
			syslog(LOG_INFO, "cannot creat unix socket !");
			return -1;
		}

		srv_addr.sun_family = AF_UNIX;
		strcpy(srv_addr.sun_path, UNIX_DOMAIN_CMD);

		/* connect main process server */
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		setsockopt(uwbset_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

		ret = connect(uwbset_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
		if (ret < 0)
		{
			syslog(LOG_INFO, "cannot connect main process !");
			close(uwbset_fd);
			return -1;
		}
		else
		{
			unix_mode = 1;
		}
	}

	if (unix_mode == 0)
	{
		FILE *file = NULL;
		char uwbtty[20] = {0};
		/* open and init tty devices */
		file = popen(TTY, "r");
		if (file)
		{
			fgets(uwbtty, sizeof(uwbtty), file);
		}
		pclose(file);

		if (NULL != strstr(cmd, "ttyinit"))
		{
			uwbset_fd = init_tty(uwbtty, 1);
			syslog(LOG_INFO, "tty init ok!");
		}
		else
		{
			if (access(UWB_TTYINIT, F_OK) == 0)
			{
				uwbset_fd = init_tty(uwbtty, 0);
			}
			else
			{
				uwbset_fd = init_tty(uwbtty, 1);
			}
		}
	}

	/* write uwb cmd */
	ret = write(uwbset_fd, cmd, strlen(cmd));
	close(uwbset_fd);

	if (ret > 1)
	{
		ret = 1;
	}
	else if (ret < 0)
	{
		syslog(LOG_INFO, "write uwb cmd error !");
	}

	return ret;
}

static int set_uwb_cmd(char *cmdbuf, int len)
{
	int ret = -1;
	if (uwb_fd > 0)
	{
		ret = write(uwb_fd, cmdbuf, len);
	}

	return ret;
}

/* thread func: read cmd from client process */
static void *uwb_cmd_thread()
{
	socklen_t clt_addr_len;
	int listen_fd;
	int accept_fd;
	int ret;
	char rcv_buff[1024];
	int len;
	struct sockaddr_un clt_addr;
	struct sockaddr_un srv_addr;

	listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (listen_fd < 0)
	{
		log_e("can not creat communication socket !");
	}

	/* set srv_addr param */
	srv_addr.sun_family = AF_UNIX;
	strncpy(srv_addr.sun_path, UNIX_DOMAIN_CMD, sizeof(srv_addr.sun_path) - 1);
	unlink(UNIX_DOMAIN_CMD);

	/* bind sockfd&addr */
	ret = bind(listen_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
	if (ret < 0)
	{
		log_e("cannot bind unix socket !");
		close(listen_fd);
		unlink(UNIX_DOMAIN_CMD);
		return NULL;
	}

	/* listen sockfd */
	ret = listen(listen_fd, 1);
	if (ret < 0)
	{
		log_e("cannot listen sockfd !");
		close(listen_fd);
		unlink(UNIX_DOMAIN_CMD);
		return NULL;
	}

	/* wait for read cmd from client process */
	int num = 0;
	while (TRUE)
	{
		/* have connect requst use accept */
		len = sizeof(clt_addr);
		accept_fd = accept(listen_fd, (struct sockaddr *)&clt_addr, &len);
		/* blocked, not into here */
		if (accept_fd < 0)
		{
			log_d("no accept requst !");
			sleep(1);
			continue;
		}

		/* read cmd */
		memset(rcv_buff, 0, sizeof(rcv_buff));
		num = read(accept_fd, rcv_buff, sizeof(rcv_buff));

		/* set cmd to uwb */
		if (num > 0)
		{
			log_d("message from cmd process : %s", rcv_buff);
			if (set_uwb_cmd(rcv_buff, num) < 0)
			{
				log_w("set cmd to uwb fail !");
			}
		}
		else
		{
			log_d("no message recv from cmd process !");
		}

		close(accept_fd);
		accept_fd = 0;
	}

	close(listen_fd);
	unlink(UNIX_DOMAIN_CMD);
	return NULL;
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

	struct timeval timeout = {2, 0}; // 2s
	struct timespec tv;

	int nSendBuf = 1024 * 1024;

	int locked = 0;
	int wait_ret = 0;

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
				log_i("++++++++++++++++tcpsend_status : start  init++++++++++++++++");
				{
					log_i("uwb tcp server is %s, port is %d", data->con->ip, data->con->port);

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
				log_i("++++++++++++++++tcpsend_status : creat tcp++++++++++++++++");
				{
					// log_i("start debug server tcp connect !");
					if (uwb_sock > 0)
					{
						close(uwb_sock);
					}
					log_i("tcp connect to uwb server %s:%d", data->con->ip, data->con->port);

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

					/* send timeout */
					setsockopt(uwb_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

					/* SO_SNDBUF */
					setsockopt(uwb_sock, SOL_SOCKET, SO_SNDBUF, (const char *)&nSendBuf, sizeof(int));

					result = connect(uwb_sock, (struct sockaddr *)&uwb_server, sizeof(uwb_server));
					if (result == -1)
					{
						log_w("uwb server tcp connect error, wait for reconnect !");
						close(uwb_sock);
						uwb_sock = 0;
						/*next status*/
						uwb_status = uwb_creat;
						sleep(3);
					}
					else
					{
						log_w("uwb server tcp connect sucess!");
						
						timeout.tv_sec = 1;
						timeout.tv_usec = 0;
						/* send timeout */
						setsockopt(uwb_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
						
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

						tcp_status = TCP_connected;
						uwb_status = uwb_send;
					}
					/*creat timer for keepalive*/
				}
				break;
			case uwb_send:
				log_i("++++++++++++++++tcpsend_status : send data++++++++++++++++");
				{
					error_time = 0;
					while (TRUE)
					{
						memset(tmp_data, 0, 1024);
						len = Rbuf_GetOne(data->ring_buffer, tmp_data);

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
								log_w("tcpsend worker timedwait timeout !");
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
#ifdef TLV_SEND
							tlvdata = (TLV_data *)tmp_data;

							tcp_send_data = tlvdata->data;
							sendlen = tlvdata->length;

							/* for test */
#ifdef DEBUG_TEST
							printf("send len %d\n", sendlen);
							printf_hex("tcp send data", tcp_send_data, sendlen);
#endif
#else
							jsonlen = strlen(tmp_data);
							strcpy(&tmp_data[jsonlen], "\r\n");
							sendlen = jsonlen + 2;
							tcp_send_data = tmp_data;
#endif

							result = send_data(uwb_sock, tcp_send_data, sendlen);

							if (result == -1)
							{
								error_time++;
								if (error_time >= 3)
								{
									log_e("send error long time, maybe tcp server is error");
									uwb_status = uwb_creat;
									tcp_status = TCP_disconnected;

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
			case uwb_end:
			default:
				log_i("++++++++++++++++tcpsend_status :     end++++++++++++++++");
				goto END;
		}
	}

END:
	close(uwb_sock);
	free(tmp_data);

	return NULL;
}

/* thread func: uwb server udp and send */
void *udpsend_thread_func(void *indata)
{
	int send_sock = 0, result = 0, len = 0, error_time = 0;
	struct sockaddr_in server;
	int sendlen = 0;
	char *udp_senddata = NULL;

	struct timespec tv;

	int locked = 0;
	int wait_ret = 0;

#ifdef TLV_SEND
	TLV_data *tlvdata;
#else
	int jsonlen = 0;
#endif

	Thread_data *data = (Thread_data *)indata;
	char *tmp_data = malloc(1024);

	log_i("server is %s, port is %d", data->con->ip, data->con->port);

	/*ignore SIGPIPE*/
	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGPIPE);
	if (pthread_sigmask(SIG_BLOCK, &signal_mask, NULL) == -1)
	{
		printf("pthread_sigmask SIG_PIPE error\n");
	}

	/* udp socket init */
UDP_RETRY:
	log_i("++++++++++++++++send_status :  udp init++++++++++++++++");
	if (send_sock > 0)
	{
		close(send_sock);
	}
	send_sock = udp_client(data->con->ip, data->con->port, &server);
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
		memset(tmp_data, 0, 1024);
		len = Rbuf_GetOne(data->ring_buffer, tmp_data);

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
				log_w("send worker timedwait timeout !");
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

#ifdef TLV_SEND
			tlvdata = (TLV_data *)tmp_data;

			udp_senddata = tlvdata->data;
			sendlen = tlvdata->length;

			/* for test */
#ifdef DEBUG_TEST
			printf("send len %d\n", sendlen);
			printf_hex("send data", udp_senddata, sendlen);
#endif
#else
			jsonlen = strlen(tmp_data);
			strcpy(&tmp_data[jsonlen], "\n");
			sendlen = jsonlen + 1;
			udp_senddata = tmp_data;
#endif

			result = udp_send(send_sock, udp_senddata, sendlen);

			if (result == -1)
			{
				error_time++;
				if (error_time >= 3)
				{
					log_e("send error long time, maybe server network is error");
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

END:
	if (send_sock > 0)
	{
		close(send_sock);
	}
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
		char cmd_buff[512] = {0};
		char tmp_buff[256] = {0};

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

			cmd_buff[strlen(cmd_buff)] = '\n';
			/* send cmd to main process */
			ret_exit = uwb_cmd_send(cmd_buff);
		}

		syslog(LOG_INFO, "###########UWB CMD END###########");

		closelog();
		exit(ret_exit);
	}

	/*********************** main process ************************/

	/* init logfile */
	system("rm /tmp/uwb -rf");
	system("mkdir /tmp/uwb");

	/* logger init */
	logger_init();

	int ret, result;
	ret = 0;

	struct timeval now_time;
	char jiffies_buf[20] = {0};

	pthread_t thread_uwbcmd;

	Thread_data send_buffer_threadData; // for tcp or udp send
	// Thread_data uwb_prase_buffer_threadData; // for uwb_prase
	Thread_data ppp_frame_buffer_threadData; // for ppp_frame

	// Prase_data uwb_prase_thread_indata; // for send_thread
	Frame_data ppp_frame_thread_indata; // for uwb_prase_thread

	pthread_t thread_send;
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
		log_e("block sigpipe error!");
	}

	while (TRUE)
	{
		/* FSM */
		switch (run_status)
		{
			case start:
				log_i("----------------run_status : start  init---------------");
				{
					log_i("init uwb info!");

					uwbconfig = (config *)malloc(sizeof(config));

					/* config init */
					ret = init(uwbconfig);
					if (ret < 0)
					{
						log_e("init error, exit!");
						return -1;
					}
					if (uwbconfig->socktype == SOCK_UDP)
					{
						log_i("sock type udp !");
					}
					else
					{
						log_i("sock type tcp !");
					}

					if (uwbconfig->print_enable == 1 || uwbconfig->stm32hexdebug == 1)
					{
						uwbconfig->print_buff = malloc(PRINT_BUFF_SIZE);
					}

					/* recode first time for ac */
					fp_jiffies = fopen(DATA_JIFFIES, "w+");
					if (NULL == fp_jiffies)
					{
						log_e("DATA_JIFFIES open error !");
						return -1;
					}
					gettimeofday(&now_time, NULL);
					memset(jiffies_buf, 0, sizeof(jiffies_buf));
					JSONDATA_TIME(&now_time, jiffies_buf);
					write_jiffies(fp_jiffies, jiffies_buf);

					/* init uwbcmd thread */
					ret = pthread_create(&thread_uwbcmd, NULL, uwb_cmd_thread, NULL);
					if (ret != 0)
					{
						log_e("uwbcmd pthread create failed!");
					}
					pthread_detach(thread_uwbcmd);

					/* creat send thread to send data */
					{
						send_buffer_threadData.con = uwbconfig;
						send_buffer_threadData.ring_buffer = malloc(sizeof(struct ring_buffer_t));

						char *send_ringbuffer = malloc(4 * 1024 * MAXLENGTH_JSONDATA);
						Rbuf_Init(send_buffer_threadData.ring_buffer, send_ringbuffer, MAXLENGTH_JSONDATA,
								  4 * 1024); // 4 * 1024 * 512 = 4 * 512kbyte , json data  < 512byte  2m
						Rbuf_Clear(send_buffer_threadData.ring_buffer);
#ifdef USE_SEM
						sem_init(&send_buffer_threadData.sem, 0, 0);
#else
						pthread_mutex_init(&send_buffer_threadData.mutex, NULL);
						pthread_condattr_init(&send_buffer_threadData.conda);
						pthread_condattr_setclock(&send_buffer_threadData.conda, CLOCK_MONOTONIC);
						pthread_cond_init(&send_buffer_threadData.cond, &send_buffer_threadData.conda);
#endif
						if (uwbconfig->socktype == SOCK_UDP)
						{
							ret = pthread_create(&thread_send, NULL, udpsend_thread_func,
												 (void *)(&send_buffer_threadData));
						}
						else
						{
							ret = pthread_create(&thread_send, NULL, tcpsend_thread_func,
												 (void *)(&send_buffer_threadData));
						}

						if (ret != 0)
						{
							log_e("send thread create failed!");
						}
						pthread_detach(thread_send);
					}

					/* init ppp_frame_buffer_threadData */
					{
						/* ppp_frame_buffer */
						ppp_frame_buffer_threadData.ring_buffer = malloc(sizeof(struct ring_buffer_t));

						char *tty_read_ringbuffer = malloc(16 * 1024 * (sizeof(ttyread_data)));
						Rbuf_Init(ppp_frame_buffer_threadData.ring_buffer, tty_read_ringbuffer, (sizeof(ttyread_data)),
								  16 * 1024); // 8 * 1024 * (256+4)  2m
						Rbuf_Clear(ppp_frame_buffer_threadData.ring_buffer);

#ifdef USE_SEM
						sem_init(&ppp_frame_buffer_threadData.sem, 0, 0);
#else
						pthread_mutex_init(&ppp_frame_buffer_threadData.mutex, NULL);
						pthread_condattr_init(&ppp_frame_buffer_threadData.conda);
						pthread_condattr_setclock(&ppp_frame_buffer_threadData.conda, CLOCK_MONOTONIC);
						pthread_cond_init(&ppp_frame_buffer_threadData.cond, &ppp_frame_buffer_threadData.conda);
#endif

						ppp_frame_thread_indata.ttyread_buffer = &ppp_frame_buffer_threadData;
						ppp_frame_thread_indata.send_buffer = &send_buffer_threadData;

						/* creat ppp_frame thread */
						ret = pthread_create(&thread_ppp_frame, NULL, ppp_frame_thread_func,
											 (void *)(&ppp_frame_thread_indata));

						/* Thread High Priority */
						setThreadHighPriority(thread_ppp_frame, 1);

						if (ret != 0)
						{
							log_e("string thread create failed!");
						}
						pthread_detach(thread_ppp_frame);
					}
				}
				run_status = serail;
				break;
			case serail:
				log_i("----------------run_status : open serail---------------");
				{
					if (uwb_fd > 0)
					{
						close(uwb_fd);
						uwb_fd = 0;
					}
					uwb_fd = DEV_FILE(uwbconfig->tty);
					if (uwb_fd < 0)
					{
						log_w("open %s error, retry after 3s!", uwbconfig->tty);
						sleep(3);
						run_status = serail;
					}
					else
					{
						log_i("open %s sucess!", uwbconfig->tty);

						run_status = readdata;
					}
				}
				break;
			case readdata:
				log_i("----------------run_status : readdata---------------");
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
								log_w("maybe serail is error, reopen serail !");
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
				log_i("----------------run_status :     end---------------");
				goto END;
				// break;
		}
	}

END:
	fclose(fp_jiffies);
	close(uwb_fd);
	uwb_fd = 0;
	if (NULL != uwbconfig->print_buff)
	{
		free(uwbconfig->print_buff);
	}
	free(uwbconfig);

	/* cancel string thread */
	Free_Thread_data(ppp_frame_buffer_threadData);
	ret = -1;
	do
	{
		ret = pthread_cancel(thread_ppp_frame);
	} while (ret != 0);

	/* cancel main thread */
	Free_Thread_data(send_buffer_threadData);
	ret = -1;
	do
	{
		ret = pthread_cancel(thread_send);
	} while (ret != 0);

	do
	{
		ret = pthread_cancel(thread_uwbcmd);
	} while (ret != 0);

	log_i("----------------run_status is end, exit program---------------");

	return 0;
}

void Free_Thread_data(Thread_data data)
{
#ifdef USE_SEM
	sem_destroy(&data.sem);
#else
	pthread_mutex_destroy(&data.mutex);
	pthread_cond_destroy(&data.cond);
	pthread_condattr_destroy(&data.conda);
#endif

	Rbuf_Free(data.ring_buffer);
	free(data.ring_buffer);
}
