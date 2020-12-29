#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <syslog.h>
#include <sys/stat.h>

#include "ble.h"
#include "elog.h"
#include "ipcmsg.h"
#include "send.h"
#include "util.h"

int tty_fd       = 0;
int ipcmsgid     = -1;
int server_state = 0;
int server_sock  = 0;

runstats       RunStatus;
config *       bleconfig = NULL;
TCPthread_data tcp_thread_data;

static void logger_init(void)
{
	/* elog sys time init */
	elog_time_init( );

	/* close printf buffer */
	setbuf(stdout, NULL);
	/* initialize EasyLogger */
	ElogFileCfg cfg;
	cfg.name       = LOGFILE_NAME;
	cfg.max_size   = 1 * 1024 * 1024;
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
	elog_start( );

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

/* set advisory lock on file */
static int lockfile(int fd)
{
	struct flock fl;

	fl.l_type   = F_WRLCK; /* write lock */
	fl.l_start  = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len    = 0; // lock the whole file

	return (fcntl(fd, F_SETLK, &fl));
}

static int already_running_check(const char *filename)
{
	int  fd;
	char buf[16];

	fd = open(filename, O_RDWR | O_CREAT, (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));
	if (fd < 0)
	{
		printf("can't open %s: %m\n", filename);
		return FAIL;
	}

	if (lockfile(fd) == -1)
	{
		if (errno == EACCES || errno == EAGAIN)
		{
			printf("file: %s already locked\n", filename);
			close(fd);
			return FAIL;
		}
		printf("can't lock %s: %m\n", filename);
		return FAIL;
	}

	ftruncate(fd, 0);
	sprintf(buf, "%ld\n", ( long )getpid( ));
	write(fd, buf, strlen(buf) + 1);
	return SUCCESS;
}

static void sigpipe_handler( )
{
	// log_w("tcp socket from server is closed!");
	pthread_mutex_lock(&(tcp_thread_data.mutex));
	server_state = 0;
	pthread_mutex_unlock(&(tcp_thread_data.mutex));
}

/* main func */
int main(int argc, char *argv[])
{
	int ret = 0;

	/*********************** cmd process *********************/
	if (argc >= 2)
	{
		int  cmd_num;
		char cmd_buff[512] = {0};
		char tmp_buff[256] = {0};

		openlog("BLELINK", LOG_CONS | LOG_PID, LOG_USER);
		syslog(LOG_INFO, "##############BLELINK############");
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

			cmd_buff[strlen(cmd_buff)] = ';';

			ret = ble_cmd_write(cmd_buff);
		}

		syslog(LOG_INFO, "##############BLELINK############");

		closelog( );
		exit(ret);
	}

	/*********************** main process ************************/
	if (already_running_check(LOCKFILE) != SUCCESS)
	{
		printf("already_running_check fail, exit !\n");
		exit(0);
	}

	pthread_t thread_blemsg;
	pthread_t thread_recv;

	/* tcp */
	struct sockaddr_in server;
	int                keepalive    = 1;
	int                keepidle     = 60;
	int                keepinterval = 3;
	int                keepcount    = 3;
	int                tcp_nodelay  = 0;
	int                sendbufsize  = 1024 * 1024;
	struct timeval     timeout      = {1, 0}; // 1s
	struct itimerval   new_value, old_value;

	/* logger init */
	logger_init( );

	/* ignore the SIGPIPE when tcp socket is closed, if not process will exit */
	/* tcp server socket closed func */
	signal(SIGPIPE, sigpipe_handler);

	/* init ipc msg */
	key_t ipcmsgkey = ftok(IPC_PATHNAME, IPC_PROJECTID);
	ipcmsgid        = msgget(ipcmsgkey, 0666 | IPC_CREAT);
	if (ipcmsgid == -1)
	{
		log_e("msgget failed width error: %d", errno);
		exit(EXIT_FAILURE);
	}

	RunStatus    = Run_start;
	server_state = 0;
	while (TRUE)
	{
		/* FSM */
		switch (RunStatus)
		{
		case Run_start:
			log_i("----------------RunStatus : start  init---------------");
			{
				log_i("init blelink info!");

				bleconfig = ( config * )malloc(sizeof(config));

				/* config init */
				ret = configinit(bleconfig);
				if (ret < 0)
				{
					log_e("init error, exit!");
					goto END;
				}

				/* init blelink msg queue thread */
				ret = pthread_create(&thread_blemsg, NULL, thread_func_blelinkmsg, NULL);
				if (ret != 0)
				{
					log_e("blelinkmsg thread create failed!");
					goto END;
				}
				pthread_detach(thread_blemsg);

				/* init tcp recv thread */
				tcp_thread_data.con = bleconfig;
				pthread_mutex_init(&tcp_thread_data.mutex, NULL);
				pthread_cond_init(&tcp_thread_data.cond, NULL);

				ret = pthread_create(&thread_recv, NULL, thread_func_tcprecv, ( void * )(&tcp_thread_data));
				if (ret != 0)
				{
					log_e("tcprecv thread create failed!");
					goto END;
				}
				pthread_detach(thread_recv);
			}
			RunStatus = Run_serail;
			break;
		case Run_serail:
			log_i("----------------RunStatus : open tty------------------");
			{
				if (tty_fd > 0)
				{
					close(tty_fd);
					tty_fd = 0;
				}
				tty_fd = init_tty(bleconfig->tty, bleconfig->baudrate, 1);
				if (tty_fd < 0)
				{
					log_w("open %s error, retry after 3s!", bleconfig->tty);
					sleep(3);
					RunStatus = Run_serail;
				}
				else
				{
					log_i("open %s sucess!", bleconfig->tty);
					if (server_state == 0)
					{
						RunStatus = Run_tcp;
					}
					else
					{
						RunStatus = Run_forward;
					}
				}
			}
			break;
		case Run_tcp:
			log_i("----------------RunStatus : tcp connectting-----------");
			{
				log_i("connect to server %s:%d", bleconfig->serverhost, bleconfig->serverport);
				if (server_sock > 0)
				{
					close(server_sock);

					pthread_mutex_lock(&(tcp_thread_data.mutex));
					server_sock = 0;
					pthread_mutex_unlock(&(tcp_thread_data.mutex));
				}

				server_sock = TCP_clien(bleconfig->serverhost, bleconfig->serverport, &server);

				/*set keepalive*/
				setsockopt(server_sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
				setsockopt(server_sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
				setsockopt(server_sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepinterval, sizeof(keepinterval));
				setsockopt(server_sock, IPPROTO_TCP, TCP_KEEPCNT, &keepcount, sizeof(keepcount));
				/* TCP NAGLE */
				tcp_nodelay = bleconfig->tcp_nagle;
				// setsockopt(server_sock, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(tcp_nodelay));
				setsockopt(server_sock, IPPROTO_TCP, TCP_CORK, &tcp_nodelay, sizeof(tcp_nodelay));
				/* send timeout */
				setsockopt(server_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
				/* SO_SNDBUF */
				setsockopt(server_sock, SOL_SOCKET, SO_SNDBUF, ( const char * )&sendbufsize, sizeof(int));

				ret = connect(server_sock, ( struct sockaddr * )&server, sizeof(server));
				if (ret == -1)
				{
					log_w("connect server error, wait for reconnect !");
					close(server_sock);

					pthread_mutex_lock(&(tcp_thread_data.mutex));
					server_sock = 0;
					pthread_mutex_unlock(&(tcp_thread_data.mutex));

					RunStatus = Run_tcp;
					sleep(3);
				}
				else
				{
					log_w("connect server sucess!");
					timeout.tv_sec  = 0;
					timeout.tv_usec = 100 * 1000; // 100ms
					/* send timeout */
					setsockopt(server_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
					setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

					pthread_mutex_lock(&(tcp_thread_data.mutex));
					server_state = 1;
					pthread_cond_signal(&tcp_thread_data.cond);
					pthread_mutex_unlock(&(tcp_thread_data.mutex));
					log_w("tcprecv thread will wakeup !");

					RunStatus = Run_forward;
					dev_addr_send(server_sock, bleconfig->mac, 0);
				}
			}
			break;
		case Run_forward:
			log_i("----------------RunStatus : Run_forward--------------");
			{
				/* clear tty buffer */
				clear_ttybuf(tty_fd);
				/*read data from tty and send to tcp server */
				while (TRUE)
				{
					ret = forward_data(tty_fd, server_sock);

					if (ret < 0)
					{
						if (ret == -2)
						{
							log_e("server is error or closed, reconnect !");

							pthread_mutex_lock(&(tcp_thread_data.mutex));
							server_state = 0;
							pthread_mutex_unlock(&(tcp_thread_data.mutex));

							RunStatus = Run_tcp;
							break; // break while
						}
						else
						{
							/* tty error */
							log_e("maybe tty error, reopen!");
							RunStatus = Run_serail;
							break; // break while
						}
					}
				}
			}
			break;
		case Run_end:
		default:
			log_i("----------------RunStatus :     end---------------");
			goto END;
			// break;
		}
	}

END:
	close(tty_fd);
	if (NULL != bleconfig->print_buff)
	{
		free(bleconfig->print_buff);
	}
	free(bleconfig);

	do
	{
		ret = pthread_cancel(thread_blemsg);
	} while (ret != 0);

	pthread_mutex_destroy(&tcp_thread_data.mutex);
	pthread_cond_destroy(&tcp_thread_data.cond);
	do
	{
		ret = pthread_cancel(thread_recv);
	} while (ret != 0);

	log_i("----------------RunStatus is end, exit program---------------");

	return 0;
}
