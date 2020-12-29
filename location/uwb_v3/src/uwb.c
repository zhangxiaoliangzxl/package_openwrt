#include <syslog.h>
#include <sys/stat.h>

#include "elog.h"
#include "main.h"
#include "tty_ppp.h"
#include "util.h"
#include "uwb.h"

int DEV_FILE(char *ttydev)
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

	/* creat init file */
	FILE *initfp = fopen(UWB_TTYINIT, "w+");
	if (NULL != initfp)
	{
		fwrite("1", 1, 1, initfp);
		fclose(initfp);
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

		/* creat init file */
		FILE *initfp = fopen(UWB_TTYINIT, "w+");
		if (NULL != initfp)
		{
			fwrite("1", 1, 1, initfp);
			fclose(initfp);
		}
		syslog(LOG_INFO, "first init uwb tty!");
	}
	return fd;
}

int read_data(int fd, Thread_data *ttyread_buffer)
{
	int ret;
	char readbuff[READSIZE] = {0};

	struct readerror last_error;
	struct timeval cur_time;

	ret = 0;
	last_error.stat = 0;
	last_error.num = 0;

	ttyread_data *read_data = NULL;
	read_data = (ttyread_data *)malloc(sizeof(ttyread_data));

	while (TRUE)
	{
		gettimeofday(&cur_time, NULL);

		memset(readbuff, 0, READSIZE);
		ret = read(fd, readbuff, READSIZE);

		if (ret > 0)
		{
			/* record error stat */
			{
				last_error.stat = 0;
				last_error.num = 0;
			}

			/* record data jiffies
			memset(sys_time, 0, sizeof(sys_time));
			JSONDATA_TIME(&cur_time, sys_time);
			write_jiffies(jiffies_fp, sys_time);
			*/

			/* add to ttyread buffer */
			memset(read_data, 0, sizeof(ttyread_data));

			memcpy(read_data->data, readbuff, ret);
			read_data->len = ret;

			if (0 == Rbuf_AddOne(ttyread_buffer->ring_buffer, read_data))
			{
				log_w("ttyread buffer is full");
			}

			/* add to ttyread buffer end */
			// usleep(300);
		}
		else /* read no data or error */
		{
			/* record error */
			if (1 == last_error.stat)
			{
				if ((cur_time.tv_sec - last_error.cur_time.tv_sec) < 1)
				{ // 2s
					/*read error*/
					last_error.num++;
					log_e("read error, error num %d ", last_error.num);
					usleep(3000);
				}
				else
				{
					last_error.num = 0;
				}

				if (last_error.num > 30)
				{
					free(read_data);
					return -2;
				}
			}

			memcpy(&(last_error.cur_time), &cur_time, sizeof(struct timeval));
			last_error.stat = 1;

			// usleep(300);
			continue;
		}
	}

	free(read_data);
	return 0;
}
