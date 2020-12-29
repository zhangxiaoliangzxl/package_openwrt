#include <signal.h>
#include <syslog.h>
#include <sys/stat.h>

#include "main.h"

/* 443 fd */
int fd_433 = 0;

/* program run status */
runstats run_status = start;

FILE *fp_jiffies = NULL;

config *config_433 = NULL;

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

/* func: send cmd to main process */
static int cmd_433_send(char *cmd)
{
	int set_fd_433;
	int ret;
	int unix_mode = 0;

	if (NULL == cmd || strlen(cmd) < 1)
	{
		printf("cmd is null !\n");
		return -1;
	}

	if (unix_mode == 0)
	{
		FILE *file = NULL;
		char tty433[20] = {0};
		/* open and init tty devices */
		file = popen(TTY, "r");
		if (file)
		{
			fgets(tty433, sizeof(tty433), file);
		}
		pclose(file);

		if (NULL != strstr(cmd, "ttyinit"))
		{
			set_fd_433 = init_tty(tty433, 1);
			syslog(LOG_INFO, "tty init ok!");
			ret = 1;
		}
		else
		{
			// set_fd_433 = init_tty(tty433, 0);
			syslog(LOG_INFO, "unkown cmd!");
			ret = -1;
		}
	}

	close(set_fd_433);

	return ret;
}

static void sigpipe_handler()
{
	log_w("socket from server is closed!");
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

		openlog("433M", LOG_CONS | LOG_PID, LOG_USER);
		syslog(LOG_INFO, "##############433M CMD############");
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
			ret_exit = cmd_433_send(cmd_buff);
		}

		syslog(LOG_INFO, "###########433M CMD END###########");

		closelog();
		exit(ret_exit);
	}

	/*********************** main process ************************/

	/* init logfile */
	system("rm /tmp/433M -rf");
	system("mkdir /tmp/433M");

	/* logger init */
	logger_init();

	int ret, result;
	ret = 0;

	struct timeval now_time;
	char jiffies_buf[20] = {0};

	pthread_t thread_parse;
	pthread_t thread_send;

	Thread_data parse_buffer_threadData; // for parse tty buffer
	Thread_data send_buffer_threadData;  // for send buffer
	Thread_indata parse_thread_indata;   // for parse_thread fucn indata

	/* ignore the SIGPIPE when socket is closed, if not process will exit */
	/* server socket closed func */
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
					log_i("init 433M info!");

					config_433 = (config *)malloc(sizeof(config));

					/* config init */
					ret = init(config_433);
					if (ret < 0)
					{
						log_e("init error, exit!");
						return -1;
					}

					log_i("print_enable %d", config_433->print_enable);

					if (config_433->print_enable == 1)
					{
						config_433->print_buff = malloc(PRINT_BUFF_SIZE);
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

					/* send buffer */
					{
						send_buffer_threadData.con = config_433;
						send_buffer_threadData.ring_buffer = malloc(sizeof(struct ring_buffer_t));

						char *send_buffer = malloc(1 * 1024 * MAXLENGTH_JSONDATA);
						Rbuf_Init(send_buffer_threadData.ring_buffer, send_buffer, MAXLENGTH_JSONDATA,
								  1 * 1024); // 1 * 1024 * 512 = 1 * 512kbyte , json data  < 512byte  512k
						Rbuf_Clear(send_buffer_threadData.ring_buffer);
						pthread_mutex_init(&send_buffer_threadData.mutex, NULL);

						pthread_condattr_init(&send_buffer_threadData.conda);
						pthread_condattr_setclock(&send_buffer_threadData.conda, CLOCK_MONOTONIC);
						pthread_cond_init(&send_buffer_threadData.cond, &send_buffer_threadData.conda);

						/* create send thread */
						ret = pthread_create(&thread_send, NULL, send_thread_func, (void *)(&send_buffer_threadData));
						if (ret != 0)
						{
							log_e("send thread create failed!");
						}
						pthread_detach(thread_send);
					}

					/* init parse_buffer_threadData */
					{
						/* parse_buffer */
						parse_buffer_threadData.ring_buffer = malloc(sizeof(struct ring_buffer_t));

						char *tty_read_buffer = malloc(4 * 1024 * (sizeof(ttyread_data)));
						Rbuf_Init(parse_buffer_threadData.ring_buffer, tty_read_buffer, (sizeof(ttyread_data)),
								  4 * 1024); // 2 * 1024 * (256+4)  520k
						Rbuf_Clear(parse_buffer_threadData.ring_buffer);
						pthread_mutex_init(&parse_buffer_threadData.mutex, NULL);

						pthread_condattr_init(&parse_buffer_threadData.conda);
						pthread_condattr_setclock(&parse_buffer_threadData.conda, CLOCK_MONOTONIC);
						pthread_cond_init(&parse_buffer_threadData.cond, &parse_buffer_threadData.conda);

						parse_thread_indata.in_buffer = &parse_buffer_threadData;
						parse_thread_indata.out_buffer = &send_buffer_threadData;

						/* creat parse thread */
						ret = pthread_create(&thread_parse, NULL, parse_thread_func, (void *)(&parse_thread_indata));
						if (ret != 0)
						{
							log_e("parse thread create failed!");
						}
						pthread_detach(thread_parse);
					}
				}
				run_status = serail;
				break;
			case serail:
				log_i("----------------run_status : open serail---------------");
				{
					if (fd_433 > 0)
					{
						close(fd_433);
						fd_433 = 0;
					}
					fd_433 = TTY_OPEN(config_433->tty);
					if (fd_433 < 0)
					{
						log_w("open %s error, retry after 3s!", config_433->tty);
						sleep(3);
						run_status = serail;
					}
					else
					{
						log_i("open %s sucess!", config_433->tty);

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
						ret = recevice_from_tty(fd_433, &parse_buffer_threadData);

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
	close(fd_433);
	fd_433 = 0;
	if (NULL != config_433->print_buff)
	{
		free(config_433->print_buff);
	}
	free(config_433);

	/* cancel parse thread */
	Free_Thread_data(parse_buffer_threadData);
	ret = -1;
	do
	{
		ret = pthread_cancel(thread_parse);
	} while (ret != 0);

	/* cancel send thread */
	Free_Thread_data(send_buffer_threadData);
	ret = -1;
	do
	{
		ret = pthread_cancel(thread_send);
	} while (ret != 0);

	log_i("----------------run_status is end, exit program---------------");

	return 0;
}

void Free_Thread_data(Thread_data data)
{
	pthread_mutex_destroy(&data.mutex);
	pthread_cond_destroy(&data.cond);
	pthread_condattr_destroy(&data.conda);
	Rbuf_Free(data.ring_buffer);
	free(data.ring_buffer);
}

