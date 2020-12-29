#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <syslog.h>
#include <sys/stat.h>

#include "ble.h"
#include "elog.h"
#include "exbuffer.h"
#include "ipcmsg.h"
#include "send.h"
#include "util.h"

extern int     tty_fd;
extern int     ipcmsgid;
extern int     server_state;
extern int     server_sock;
extern config *bleconfig;

static int get_config_value(FILE *file, char *cmd, char *value, int len)
{
	memset(value, 0, len);
	file = popen(cmd, "r");
	if (file)
	{
		fgets(value, len, file);
	}
	pclose(file);

	return strlen(value);
}

static int baudrate_check(int speed)
{
	int ret = 0;
	switch (speed)
	{
	case 9600:
	case 115200:
	case 230400:
	case 460800:
	case 576000:
	case 921600:
		ret = 1;
		break;
	default:
		ret = 0;
		break;
	}

	return ret;
}

int configinit(config *con)
{
	int   len = 0, ret = -1;
	FILE *file     = NULL;
	char  tmp[128] = {0};

	con->baudrate   = 115200;
	con->print_buff = NULL;

	len = get_config_value(file, HOST, tmp, sizeof(tmp));
	if (len > 0)
	{
		strncpy(con->serverhost, tmp, sizeof(con->serverhost));
	}
	else
	{
		log_e("config get serverhost error!");
		goto ERROR;
	}

	len = get_config_value(file, TTY, tmp, sizeof(tmp));
	if (len > 0)
	{
		strncpy(con->tty, tmp, sizeof(con->tty));
	}
	else
	{
		log_e("config get tty error!");
		goto ERROR;
	}

	len = get_config_value(file, DEVMAC, tmp, sizeof(tmp));
	if (len > 0)
	{
		strncpy(con->mac, tmp, sizeof(con->mac));
		/*machex*/
		memset(con->mac16, 0, sizeof(con->mac16));
		if (!mac2hex(MAC_FORMAT_ANY, con->mac, con->mac16))
		{
			log_e("mac2hex failed !");
		}
	}
	else
	{
		log_e("config get devmac error!");
		goto ERROR;
	}

	len = get_config_value(file, PORT, tmp, sizeof(tmp));
	if (len > 0)
	{
		con->serverport = atoi(tmp);
	}
	else
	{
		log_e("config get serverport error!");
		goto ERROR;
	}

	len = get_config_value(file, TCP_NAGLE, tmp, sizeof(tmp));
	if (len > 0)
	{
		con->tcp_nagle = atoi(tmp);
	}
	else
	{
		con->tcp_nagle = 0;
	}

	len = get_config_value(file, BAUDRATE, tmp, sizeof(tmp));
	if (len > 0)
	{
		con->baudrate = atoi(tmp);
		if (!baudrate_check(con->baudrate))
		{
			log_e("config baudrate %s error!", tmp);
			goto ERROR;
		}
	}
	else
	{
		log_e("config baudrate error!");
		goto ERROR;
	}

	len = get_config_value(file, DEBUG, tmp, sizeof(tmp));
	if (len > 0)
	{
		con->debug = atoi(tmp);
	}
	else
	{
		con->debug = 0;
	}

	len = get_config_value(file, DEBUG_MODE, tmp, sizeof(tmp));
	if (len > 0)
	{
		con->debug_mode = atoi(tmp);
	}
	else
	{
		con->debug_mode = 0;
	}

	log_i("################config info#################");
	log_i("\t apmac         : %s", con->mac);
	log_i("\t serveraddr    : %s:%d", con->serverhost, con->serverport);
	log_i("\t tcp_nagle     : %d", con->tcp_nagle);
	log_i("\t tty           : %s", con->tty);
	log_i("\t baudrate      : %d", con->baudrate);
	log_i("############################################");

	ret = 0;

ERROR:
	return ret;
}

static void serial_set_baudrate(struct termios *opt, int speed)
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

int init_tty(char *ttydev, int buadrate, int ttyinit)
{
	int fd = 0;

	if (ttyinit > 0)
	{
		fd = open(ttydev, O_RDWR | O_NOCTTY); // O_NONBLOCK
	}
	else
	{
		fd = open(ttydev, O_WRONLY | O_NOCTTY); // O_NONBLOCK
	}

	if (fd < 0)
	{
		printf("open %s error !\n", ttydev);
		return -1;
	}

	if (ttyinit > 0)
	{
		struct serial_struct serial;
		ioctl(fd, TIOCGSERIAL, &serial);
		serial.xmit_fifo_size = 1024 * 2048; // 2M
		ioctl(fd, TIOCSSERIAL, &serial);

		struct termios opt;
		tcgetattr(fd, &opt);
		serial_set_baudrate(&opt, buadrate);

		opt.c_cflag &= ~PARENB;
		opt.c_iflag &= ~INPCK;
		opt.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
		opt.c_oflag &= ~OPOST;
		opt.c_cc[VMIN]  = 0; // read min byte will return READSIZE
		opt.c_cc[VTIME] = 1; // read 10*100ms will return, no block
		tcflush(fd, TCIOFLUSH);
		if (tcsetattr(fd, TCSANOW, &opt) != 0)
		{
			printf("set serial port error !\n");
			return -1;
		}

		/* creat init file */
		FILE *initfp = fopen(BLELINK_TTYINIT, "w+");
		if (NULL != initfp)
		{
			fwrite("1", 1, 1, initfp);
			fclose(initfp);
		}
		printf("first init blelink tty!\n");
	}

	return fd;
}

void clear_ttybuf(int fd)
{
	if (fd > 0)
	{
		tcflush(fd, TCIFLUSH);
	}
}

/* func: write ble cmd to tty */
int ble_cmd_write(char *cmd)
{
	int   set_fd;
	int   ret = 0, init = 0, ttyinit = 0;
	char  tty[20]  = {0};
	FILE *file     = NULL;
	int   baudrate = 0;

	if (NULL == cmd || strlen(cmd) < 1)
	{
		syslog(LOG_INFO, "cmd is null !");
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
		fgets(tty, sizeof(tty), file);
	}
	pclose(file);

	if (access(BLELINK_TTYINIT, F_OK) == 0)
	{
		init = 1;
	}

	if (NULL != strstr(cmd, "ttyinit"))
	{
		ttyinit = 1;
	}

	if (init == 0 || ttyinit == 1)
	{
		/* get tty baudrate */
		file = popen(BAUDRATE, "r");
		if (file)
		{
			memset(tty, 0, sizeof(tty));
			if (NULL != fgets(tty, sizeof(tty), file))
			{
				if (strlen(tty) > 0)
				{
					baudrate = atoi(tty);
					if (!baudrate_check(baudrate))
					{
						syslog(LOG_INFO, "config baudrate %s is error", tty);
					}
				}
			}
			else
			{
				baudrate = 115200;
			}
		}
		pclose(file);
	}

	/* cmd */
	if (ttyinit == 1)
	{
		set_fd = init_tty(tty, baudrate, 1);
		syslog(LOG_INFO, "tty init ok!");
		ret = 1;
	}
	else
	{
		if (init == 0)
		{
			set_fd = init_tty(tty, baudrate, 1);
		}
		else
		{
			set_fd = init_tty(tty, baudrate, 0);
		}
		/* write cmd to tty */
		ret = write(set_fd, cmd, strlen(cmd));
	}

	close(set_fd);

	if (ret > 1)
	{
		ret = 1;
	}
	else if (ret < 0)
	{
		syslog(LOG_INFO, "write ble cmd error !");
	}

	return ret;
}

/* type: 0 string / 1 hex */
int dev_addr_send(int socket, char *addr, int type)
{
	int  ret = 0, len = 0;
	char macaddr[20] = {0};

	if (type == 1)
	{
		len = MAC_ADDRESS_LEN;
	}
	else
	{
		len = MAC_ADDRESS_STRLEN;
	}

	memcpy(macaddr, addr, len);
	if (type == 0)
	{
		macaddr[MAC_ADDRESS_STRLEN]     = '\r';
		macaddr[MAC_ADDRESS_STRLEN + 1] = '\n';
		len                             = len + 2;
	}

	log_i("first send dev address!");

	do
	{
		ret = tcp_send(socket, macaddr, len);
		if (ret < 0)
		{
			sleep(1);
		}
	} while (ret < 0);

	return 0;
}

static inline int tty_write(int ttyfd, char *buf, int len)
{
	return write(ttyfd, buf, len);
}

static inline int tcp_write(int socket, char *buf, int len)
{
	return write(socket, buf, len);
}

int forward_data(int fd, int socket)
{
	int  len = 0, ret = 0;
	char readbuf[READSIZE] = {0};
	int  send_error        = 0;

	ret = -2;
	while (server_state)
	{
		/* do next read */
		if (likely((len = read(fd, readbuf, READSIZE)) > 0))
		{
			/* forward to network */
			if (unlikely((ret = tcp_write(socket, readbuf, len)) < 0))
			{
				log_e("tcp write fail (%s)", strerror(errno));

				send_error++;
				if (send_error >= 3)
				{
					ret = -2;
					break;
				}
			}
			else
			{
				send_error = 0;
			}
		}
		else
		{
			if (unlikely(len < 0))
			{
				ret = -1;
				break;
			}
			/*
			else read timeout return
			*/
		}
	}

	return ret;
}

void *thread_func_blelinkmsg(void *data)
{
	struct msg_st msgdata;
	int           cnt = 0, ret = 0;

	log_i("blelink_msg thread running!");
	while (TRUE)
	{
		memset(&msgdata, 0, sizeof(struct msg_st));
		/* will block utill recv msg */
		if (msgrcv(ipcmsgid, ( void * )&msgdata, sizeof(struct ipcmsg_t), MSG_TYPE_BLE, 0) == -1)
		{
			log_e("read msg from msg queue error %d!", errno);
		}
		else
		{
			/* send msg to tty */
			if (likely(tty_fd > 0))
			{
				msgdata.msg_data.data[msgdata.msg_data.len] = ';';
#ifdef DEBUGTEST
				ret = tcp_write(server_sock, msgdata.msg_data.data, msgdata.msg_data.len + 1);
#else
				ret = tty_write(tty_fd, msgdata.msg_data.data, msgdata.msg_data.len + 1);
#endif
				log_d("msgrecv && ttysend return %d, %d(%s)", ret, msgdata.msg_data.len + 1, msgdata.msg_data.data);
				cnt = 0;
			}
			else
			{
				cnt++;
				if (cnt == 1)
				{
					log_w("drop the cache msg !");
				}
				else if (cnt > 100)
				{
					cnt = 0;
				}
			}
		}
	}

	return NULL;
}

/* handle one packet */
static void packetHandle(unsigned char *rbuf, size_t len)
{
	int ret = 0;
#ifndef DEBUGTEST
	ret = tty_write(tty_fd, rbuf, len);
#endif
	if (unlikely(bleconfig->debug == 1))
	{
		if (bleconfig->debug_mode == 0)
		{
			log_d("recvdata %d && ttysend return %d", len, ret);
		}
		else
		{
			if ((bleconfig->debug_mode % 2) == 1)
			{
				char *str = malloc(len + 1);
				memset(str, 0, len + 1);
				memcpy(str, rbuf, len);
				log_d("tcprecv && ttysend return %d, %d(%s)", ret, len, str);
				free(str);
			}
			else
			{
				log_d("tcprecv %d && ttysend return %d", len, ret);
				elog_hexdump(":", 16, rbuf, len);
			}
		}
	}
}

void *thread_func_tcprecv(void *data)
{
	TCPthread_data *indata = ( TCPthread_data * )data;

	int  len = 0, ret = 0;
	char readbuf[EXTEND_BYTES] = {0};

	/* exbuffer init */
	exbuffer_t *exvalue = NULL;

	log_i("tcprecv thread running !");

	while (TRUE)
	{
		if (unlikely(!(server_sock > 0 && server_state > 0)))
		{
			if (exvalue != NULL)
			{
				exbuffer_free(&exvalue);
				exvalue = NULL;
			}
			exvalue             = exbuffer_new( );
			exvalue->recvHandle = packetHandle;

			log_w("tcprecv thread wait !");
			pthread_mutex_lock(&(indata->mutex));
			pthread_cond_wait(&indata->cond, &indata->mutex);
			pthread_mutex_unlock(&(indata->mutex));
		}
		else
		{
			memset(readbuf, 0, EXTEND_BYTES);
			if (likely((len = read(server_sock, readbuf, EXTEND_BYTES)) > 0))
			{
				if (unlikely(indata->con->debug == 1 && indata->con->debug_mode > 2))
				{
					log_d("tcprecv %d byte", len);
					elog_hexdump(":", 16, readbuf, len);
				}
				/* put exbuffer */
				exbuffer_put(exvalue, ( unsigned char * )readbuf, 0, len);
			}
			else
			{
				if (unlikely(len != -1))
				{
					/* socket error */
					server_state = 0;
				}
				/* else not read data, timeout */
			}
		}
	}

	if (exvalue != NULL)
	{
		exbuffer_free(&exvalue);
	}
}
