#ifndef __UWB_H__
#define __UWB_H__

#include <semaphore.h>

#include "ring_buf.h"
#include "util.h"

#include <cjson/cJSON.h>

#define PRINT_BUFF_SIZE 1024
#define READSIZE 512
#define MAXFRAMELEN 128

typedef struct uwb_cfg
{
	char panid[16];
	char ch[16];
	char pcode[16];
	char coarsegain[16];
	char matid[16];
	char localid[16];
	char mode[16];
	char palna[16];
	char finegain[16];
	char role[16];
} UWB_CFG;

enum sock_type
{
	SOCK_TCP = 1,
	SOCK_UDP
};

typedef struct config_t
{
	int port;
	int print_enable;
	int stm32hexdebug;
	int backup;
	int debug_enable;
	int debug_serverport;
	enum sock_type socktype;
	int udp2can;
	int tcp_nagle;
	char ip[20];
	char mac[20];
	unsigned char mac16[MAC_ADDRESS_LEN + 1];
	char tty[20];
	char debug_server[20];
	UWB_CFG uwb_cfg; /*uwb config*/
	char *print_buff;
} config;

typedef struct VERSION
{
	char month[8];
	char day[8];
	char year[8];
	char time[16];
} UWB_VERSION;

typedef enum MONTH
{
	Jan = 1,
	Feb,
	Mar,
	Apr,
	May,
	Jun,
	Jul,
	Aug,
	Sep,
	Oct,
	Nov,
	Dec
} MONTH_TYPE;

typedef enum uwb_type_t
{
	Other = 0,
	Position,	// uwb
	Sync,		// sync
	Status,		// status
	Tof,		// tof
	Zigbee,		// zigbee status
	Syncsta,	// Syncsta
	Tdoag,		// tdoa_g
	Barometer,	// barometer
	Tdoasensor, // tdoa_sensor
	Tdoainfo,	// tdoa_info
	Tdoawarn,	// tdoa_warn
	PdoaV1		// tdoa_warn
} uwb_type;

typedef enum
{
	TCP_start = 0,
	TCP_connected,
	TCP_disconnected
} TcpStatus;

#define ENUM_TO_STR(x) \
	case x:            \
		return (#x);

#define ENUM_UWB_TYPE_CASE(x) \
	case x:                   \
		return (#x);
static inline const char *uwb_type_to_string(uwb_type type)
{
	switch (type)
	{
		ENUM_UWB_TYPE_CASE(Position)
		ENUM_UWB_TYPE_CASE(Sync)
		ENUM_UWB_TYPE_CASE(Status)
		ENUM_UWB_TYPE_CASE(Tof)
		ENUM_UWB_TYPE_CASE(Zigbee)
		ENUM_UWB_TYPE_CASE(Other)
		ENUM_UWB_TYPE_CASE(Syncsta)
		ENUM_UWB_TYPE_CASE(Tdoainfo)
		ENUM_UWB_TYPE_CASE(Tdoawarn)
		ENUM_UWB_TYPE_CASE(Tdoag)
		ENUM_UWB_TYPE_CASE(Tdoasensor)
		ENUM_UWB_TYPE_CASE(Barometer)
		ENUM_UWB_TYPE_CASE(PdoaV1)
	}
	return "Unkown";
}

typedef struct thread_data_t
{
	config *con;
	Rbuf_Type *ring_buffer;
#ifdef USE_SEM
	sem_t sem;
#else
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	pthread_condattr_t conda;
#endif
} Thread_data;

typedef struct prase_data_t
{
	Thread_data *pppframe_buffer;
	Thread_data *send_buffer;
} Prase_data;

typedef struct string_data_t
{
	Thread_data *send_buffer;
	Thread_data *ttyread_buffer;
} Frame_data;

typedef struct tmp_data_t
{
	char sys_time[20];
	char frame_data[MAXFRAMELEN];
} Data_tmp;

struct readerror
{
	int stat;
	int num;
	struct timeval cur_time;
};

int init_tty(char *ttydev, int ttyinit);
int DEV_FILE(char *ttydev);
int read_data(int fd, Thread_data *string_buffer);

#endif
