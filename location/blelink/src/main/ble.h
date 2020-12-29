#ifndef __BLE_H__
#define __BLE_H__
#include <pthread.h>
#include "util.h"

/* for test */
//#define DEBUGTEST

#define PRINT_BUFF_SIZE 1024
#define READSIZE 64

#define LOCKFILE "/var/run/blelink.pid"
#define LOGFILE_NAME "/tmp/log/blelink.log"
#define BLELINK_TTYINIT "/tmp/run/blelinktty.init"

/* get config info */
#define DISABLED "uci get blelink.common.disabled | tr -d '\n'"
#define HOST "uci get blelink.common.serverhost 2>/dev/null | tr -d '\n'"
#define PORT "uci get blelink.common.serverport 2>/dev/null | tr -d '\n'"
#define TCP_NAGLE "uci get blelink.common.tcp_nagle 2>/dev/null | tr -d '\n'"
#define DEBUG "uci get blelink.common.debug | tr -d '\n'"
#define DEBUG_MODE "uci get blelink.common.debug_mode | tr -d '\n'"
#define TTY "uci get blelink.common.tty 2>/dev/null | tr -d '\n'"
#define BAUDRATE "uci get blelink.common.baudrate | tr -d '\n'"
#define DEVMAC "cat /sys/class/net/eth0/address 2>/dev/null | tr -d '\n'"

typedef struct config_t
{
	int           serverport;
	int           tcp_nagle;
	unsigned int  baudrate;
	int           debug;
	int           debug_mode;
	char *        print_buff;
	char          serverhost[20];
	char          mac[20];
	unsigned char mac16[MAC_ADDRESS_LEN + 1];
	char          tty[20];
} config;

typedef enum
{
	Run_start = 0,
	Run_serail,
	Run_tcp,
	Run_forward,
	Run_end
} runstats;

typedef struct tcpthread_data_t
{
	config *        con;
	pthread_mutex_t mutex;
	pthread_cond_t  cond;
} TCPthread_data;

int   configinit(config *con);
int   init_tty(char *ttydev, int baudrate, int ttyinit);
void  clear_ttybuf(int fd);
int   ble_cmd_write(char *cmd);
int   dev_addr_send(int socket, char *addr, int type);
int   forward_data(int fd, int socket);
void *thread_func_blelinkmsg(void *data);
void *thread_func_tcprecv(void *data);

#endif
