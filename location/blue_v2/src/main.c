#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include "blue.h"
#include "fast2date.h"
#include "log.h"
#include "ring_buf.h"
#include "send.h"
#include "util.h"

/* read fd */
int blue_fd = 0;

/* program run status */
runstats run_status = start;

FILE *fp_jiffies = NULL;
config *blueconfig = NULL;

static void sigpipe_handler()
{
	LOG_LOG("blue socket from server is closed!");
}

/* func: set cmd to blue */
static int set_blue_cmd(int fd, char *cmd)
{
#if 0
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
		syslog(LOG_ERR, "write to blue moudle error !");
	}

	return ret;
#else
	syslog(LOG_ERR, "blue moudle not support set !");
	return -1;
#endif
}

static int blue_cmd(char *cmd)
{
	int blue_fd = 0;
	FILE *file = NULL;
	char tty[20] = {0};
	int baudrate = 230400;

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
	file = popen(BAUDRATE, "r");
	if (file)
	{
		if (NULL != fgets(tty, sizeof(tty), file))
		{
			if (strlen(tty) > 0)
			{
				baudrate = atoi(tty);
			}
		}
		else
		{
			baudrate = 230400;
		}
	}
	pclose(file);

	file = popen(TTY, "r");
	if (file)
	{
		memset(tty, 0, sizeof(tty));
		fgets(tty, sizeof(tty), file);
	}
	pclose(file);

	if (NULL != strstr(cmd, "ttyinit"))
	{
		blue_fd = init_tty(tty, baudrate, 1);
		syslog(LOG_INFO, "tty init ok!");
	}
	/*
	else if (NULL != strstr(cmd, "version"))
	{
		blue_fd = init_tty(tty, 1);
		printf("Version:1.0\n");
	}
	*/
	else
	{
		blue_fd = init_tty(tty, baudrate, 0);
		/* set to blue */
		set_blue_cmd(blue_fd, cmd);
	}

	close(blue_fd);
	return 0;
}

static void free_thread_data(Thread_data data)
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

/* set advisory lock on file */
static int lockfile(int fd)
{
	struct flock fl;

	fl.l_type = F_WRLCK; /* write lock */
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0; // lock the whole file

	return (fcntl(fd, F_SETLK, &fl));
}

static int already_running_check(const char *filename)
{
	int fd;
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
	sprintf(buf, "%ld\n", (long)getpid());
	write(fd, buf, strlen(buf) + 1);
	return SUCCESS;
}

/* main func */
int main(int argc, char *argv[])
{
	FILE *file;

	/*********************** cmd process *********************/
	int ret_exit = 0;
	if (argc >= 2)
	{
		int cmd_num;
		char cmd_buff[256] = {0};
		char tmp_buff[128] = {0};

		openlog("BLUECMD", LOG_CONS | LOG_PID, LOG_USER);
		syslog(LOG_INFO, "##############BLUE CMD############");
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
			ret_exit = blue_cmd(cmd_buff);
		}

		syslog(LOG_INFO, "###########BLUECMD END###########");

		closelog();
		exit(ret_exit);
	}

	/*********************** main process ************************/
	if (already_running_check(LOCKFILE) != SUCCESS)
	{
		printf("already_running_check fail, exit !\n");
		exit(0);
	}

	/* init sys time */
	my_time_init();

	/* init logfile */
	if (access("/tmp/blue", F_OK))
	{
		mkdir("/tmp/blue", 0755);
	}

	int ret, result;
	ret = 0;

	struct timeval now_time;
	char jiffies_buf[20] = {0};

	Thread_data send_buffer_threadData;	 // for send
	Thread_data frame_buffer_threadData; // for tty read buffer

	Frame_data blue_parse_thread_indata; // for parse_thread

	pthread_t thread_send;		 // send thread
	pthread_t thread_blue_parse; // blue parse thread

	/* ignore the SIGPIPE when socket is closed, if not process will exit */
	/* server socket closed func */
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
				LOG_LOG("----------------run_status : start init ---------------");
				{
					LOG_LOG("init blue info!");

					blueconfig = (config *)malloc(sizeof(config));

					/* config init */
					ret = config_init(blueconfig);
					if (ret < 0)
					{
						LOG_LOG("config init error, exit!");
						return -1;
					}

					LOG_LOG("print_enable %d", blueconfig->print_enable);

					if (blueconfig->print_enable == 1)
					{
						blueconfig->print_buff = malloc(PRINT_BUFF_SIZE);
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

					/* send buffer */
					send_buffer_threadData.con = blueconfig;
					send_buffer_threadData.ring_buffer = malloc(sizeof(struct ring_buffer_t));

					char *send_buffer = malloc(2 * 1024 * MAXLENGTH_JSONDATA);
					Rbuf_Init(send_buffer_threadData.ring_buffer, send_buffer, MAXLENGTH_JSONDATA,
							  2 * 1024); // 2 * 1024 * 512 = 2 * 512kbyte , json data  < 512byte  1m
					Rbuf_Clear(send_buffer_threadData.ring_buffer);

#ifdef USE_SEM
					sem_init(&send_buffer_threadData.sem, 0, 0);
#else
					pthread_mutex_init(&send_buffer_threadData.mutex, NULL);
					pthread_condattr_init(&send_buffer_threadData.conda);
					pthread_condattr_setclock(&send_buffer_threadData.conda, CLOCK_MONOTONIC);
					pthread_cond_init(&send_buffer_threadData.cond, &send_buffer_threadData.conda);
#endif

					/* tty frame_buffer */
					frame_buffer_threadData.con = blueconfig;
					frame_buffer_threadData.ring_buffer = malloc(sizeof(struct ring_buffer_t));

					char *tty_read_buffer = malloc(4 * 1024 * (sizeof(Ttyread_data))); // 4*1024*260 byte
					Rbuf_Init(frame_buffer_threadData.ring_buffer, tty_read_buffer, (sizeof(Ttyread_data)),
							  4 * 1024); // 4 * 1024 * (256+4)  1m
					Rbuf_Clear(frame_buffer_threadData.ring_buffer);

#ifdef USE_SEM
					sem_init(&frame_buffer_threadData.sem, 0, 0);
#else
					pthread_mutex_init(&frame_buffer_threadData.mutex, NULL);
					pthread_condattr_init(&frame_buffer_threadData.conda);
					pthread_condattr_setclock(&frame_buffer_threadData.conda, CLOCK_MONOTONIC);
					pthread_cond_init(&frame_buffer_threadData.cond, &frame_buffer_threadData.conda);
#endif

					/* create send thread */
					ret = pthread_create(&thread_send, NULL, send_thread_func, (void *)(&send_buffer_threadData));
					if (ret != 0)
					{
						LOG_LOG("send thread create failed!");
					}
					pthread_detach(thread_send);

					/* create blue parse thread */
					blue_parse_thread_indata.frame_buffer = &frame_buffer_threadData;
					blue_parse_thread_indata.send_buffer = &send_buffer_threadData;

					ret = pthread_create(&thread_blue_parse, NULL, blue_parse_thread_func,
										 (void *)(&blue_parse_thread_indata));
					if (ret != 0)
					{
						LOG_LOG("blue parse thread create failed!");
					}
					pthread_detach(thread_blue_parse);
				}

				run_status = serail;
				break;
			case serail:
				LOG_LOG("----------------run_status : open serail---------------");
				{
					if (blue_fd > 0)
					{
						close(blue_fd);
					}
					blue_fd = open_ttydev(blueconfig);
					if (blue_fd < 0)
					{
						LOG_LOG("open %s error, retry after 3s!", blueconfig->tty);
						sleep(3);
						run_status = serail;
					}
					else
					{
						LOG_LOG("open %s sucess!", blueconfig->tty);

						run_status = readdata;
					}
				}
				break;
			case readdata:
				LOG_LOG("----------------run_status : readdata------------------");
				{
					/*read data from serail port to read_data buffer*/
					while (TRUE)
					{
						ret = recevice_from_tty(blue_fd, &frame_buffer_threadData);

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
	/* cancel blue parse thread */
	ret = -1;
	do
	{
		ret = pthread_cancel(thread_blue_parse);
	} while (ret != 0);

	/* cancel send thread */
	ret = -1;
	do
	{
		ret = pthread_cancel(thread_send);
	} while (ret != 0);

	/* free thread buffer data */
	free_thread_data(frame_buffer_threadData);
	free_thread_data(send_buffer_threadData);

	fclose(fp_jiffies);
	close(blue_fd);

	if (NULL != blueconfig->print_buff)
	{
		free(blueconfig->print_buff);
	}
	free(blueconfig);

	LOG_LOG("----------------run_status is end, exit program---------------");

	return 0;
}
