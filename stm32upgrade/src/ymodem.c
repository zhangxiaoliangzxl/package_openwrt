#include "ymodem.h"

int fd;
char CrcFlag = 0;
unsigned int FileLen = 0;
unsigned int FileLenBkup = 0;

int init_com(char *device)
{
	struct termios Opt;

	if ((fd = open(device, O_RDWR)) == -1)
		return (COM_OPEN_ERR);

	tcgetattr(fd, &Opt);
	// cfsetispeed(&Opt,B115200);     //115200Bps
	cfsetispeed(&Opt, B921600);
	cfsetospeed(&Opt, B921600);
	Opt.c_lflag &= ~ICANON;
	Opt.c_lflag &= ~IEXTEN;
	Opt.c_lflag &= ~ISIG;
	Opt.c_lflag &= ~ECHO;

	Opt.c_iflag = 0;

	Opt.c_oflag = 0;

	if (tcsetattr(fd, TCSANOW, &Opt) != 0)
	{
		return (COM_SET_ERR);
	}
	close(fd);

	return 0;
}

void delay(int clock_count)
{
	int i;
	for (i = 0; i < clock_count; i++) // delay
	{
	}
}

void get_now_time_date(char *time_data)
{
	time_t rawtime;
	struct tm *timeinfo;
	char buffer[64];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(buffer, sizeof(buffer), "%Y/%m/%d %H:%M:%S", timeinfo);
	sprintf(time_data, "%s", buffer);
	return;
}

void printlog(const char *func, unsigned int line, char *fmt, ...)
{
	char *p = NULL;
	char name[2][40];
	char buff[1024], fmt_buf[512];
	char time_data[32] = {0};
	int num = 0, i = 0;

	memset(name, 0, sizeof(name));
	memset(buff, 0, sizeof(buff));

	va_list ap;
	va_start(ap, fmt);

	vsnprintf(fmt_buf, sizeof(fmt_buf), fmt, ap);
	va_end(ap);

	snprintf(buff, sizeof(buff), "(%s:%d) %s", func, line, fmt_buf);

	FILE *logfile = fopen(ERROR_LOG, "a+");

	if (logfile != NULL)
	{
		fputs(buff, logfile);
		fclose(logfile);
	}
	/*
	else
	{
		printf("%s\n", buff);
	}
	*/
}

void usage(void)
{
	printf("usage: stm32upgrade dev(/dev/ttyS0,/dev/ttyUSB0,...) r \n");
	printf("       stm32upgrade dev(/dev/ttyS0,/dev/ttyUSB0,...) s filename \n");
	printf("       stm32upgrade dev(/dev/ttyS0,/dev/ttyUSB0,...) u filename \n");
}

/* main */
int main(int argc, char *argv[])
{
	int i;
	char bt;
	char *fp;
	int trans_ind;
	int set_ind;
	char *device;

	char time_date[32] = {0};
	enum
	{
		send,
		receive,
		upgrade
	} mode;

	/*init logfile*/
	FILE *logfile = fopen(ERROR_LOG, "w+");
	if (logfile != NULL)
	{
		fclose(logfile);
	}

	/* start time */
	get_now_time_date(time_date);
	LOG_LOG("start in %s \n", time_date);

	if (argc < 3)
	{
		usage();
		goto MAINEND;
	}

	switch (*argv[2])
	{
		case 'r':
			mode = receive;
			break;
		case 's':
			fp = argv[3];
			if (fp == NULL)
			{
				LOG_LOG("please input send file name!\n");
				printf("please input send file name!\n");
				goto MAINEND;
			}

			mode = send;
			break;
		case 'u':
			fp = argv[3];
			if (fp == NULL)
			{
				LOG_LOG("please input upgrade file name!\n");
				printf("please input upgrade file name!\n");
				goto MAINEND;
			}

			mode = upgrade;
			break;
		default:
			usage();
			goto MAINEND;
	}

	device = argv[1];
	set_ind = init_com(device);

	if (set_ind)
	{
		if (set_ind == COM_OPEN_ERR)
			LOG_LOG("sorry,I can't open the serial port!\n");
		else
			LOG_LOG("sorry,error ocurred when set the searial port!\n");

		goto MAINEND;
	}
	else
	{
		LOG_LOG("serial open ok!\n");
	}

	if (mode == receive)
	{
		trans_ind = control_recv(device);
	}
	else if (mode == send)
	{
		trans_ind = control_send(fp, device);
	}
	else if (mode == upgrade)
	{
		trans_ind = control_upgrade(fp, device);
	}

	if (trans_ind)
	{
		if (trans_ind != FILE_TRANS_END)
		{
			LOG_LOG("!!! get error in transmission, ERR ID:[0x%x] \n", trans_ind);
			printf("fail\n");
			printf("ERRORID:[0x%x] \n", trans_ind);
			/* reset stm32 */
			fd = _open(device, _O_RDWR | _O_BINARY);
			tcflush(fd, TCIOFLUSH);
			_write(fd, "a\n", strlen("a\n"));
			_close(fd);
		}
	}

	_close(fd);

MAINEND:
	/*end time*/
	memset(time_date, 0, sizeof(time_date));
	get_now_time_date(time_date);
	LOG_LOG("end in %s \n", time_date);
	return 0;
}
