/*************************************************************************
>  File Name: tty_ppp.h
>  Author: zxl
>  Mail:
>  Created Time: Wed 20 Mar 2019 02:33:12 PM CST
*************************************************************************/

#ifndef _TTY_PPP_H
#define _TTY_PPP_H

#include "util.h"
#include "uwb.h"

/* TLV */
#ifndef TLV_SEND
#define TLV_SEND 1
#endif

#ifndef TLV_ENCODE
#define TLV_ENCODE 1
#endif

#define PPP_FRAME_FLAG (0x7E) /* 标识字符 */
#define PPP_FRAME_ESC (0x7D)  /* 转义字符 */
#define PPP_FRAME_ENC (0x20)  /* 编码字符 */

/* datatype */
#define DATATYPE_CMD 0xa1
#define DATATYPE_CMD1 0xa2
#define DATATYPE_CMD2 0xa3
#define DATATYPE_REPORT 0xa4
#define DATATYPE_ACK 0xa5
#define DATATYPE_FORWARD 0xa6
#define DATATYPE_STROUT 0xa7
#define DATATYPE_ZIGBEE 0xa8
#define ZIGBEE_SET 0xa9
#define PDOA_REPORT 0xaa

/* zigbee datatype */
#define ZIGBEE_TX 0xc1
#define ZIGBEE_RX 0xc2

/*DATATYPE_CMD*/
#define CMD_reset 0xa1
#define CMD_getgain 0xa2
#define CMD_getcomm 0xa3

/*DATATYPE_CMD1*/
#define CMD1_matid 0xa1
#define CMD1_localid 0xa2
#define CMD1_panid 0xa3
#define CMD1_pcode 0xa4
#define CMD1_ch 0xa5
#define CMD1_mode 0xa6
#define CMD1_enpalna 0xa7
#define CMD1_sync 0xa8
#define CMD1_lpf 0xa9
#define CMD1_coarsegain 0xaa
#define CMD1_finegain 0xab
#define CMD1_syshrt 0xac
#define CMD1_extpapower 0xad

/* DATATYPE_CMD2 */
#define CMD2_mrang 0xa1

/* DATATYPE_REPORT */
#define REPORT_TOF 0xa1
#define REPORT_SYNC 0xa2
#define REPORT_TDOA 0xa3
#define REPORT_SYSHRT 0xa4
#define REPORT_SYNC_STA 0xa5
#define REPORT_TDOAG 0xa6
#define REPORT_BAROMETER 0xa7
#define REPORT_TDOASENSOR 0xa8
#define REPORT_TDOAINFO 0xa9
#define REPORT_TDOAWARN 0xaa

/* DATATYPE_ACK */
#define ACK_NORMAL 0xa1
#define ACK_VERCFG 0xa2
#define ACK_GETROLE 0xa3

/* DATATYPE_FORWARD */
#define FORWARD_NORMAL 0xa1

/* DATATYPE_ZIGBEE */
#define ZIGBEE_REPORT 0xa1
#define ZIGBEE_NORMAL 0xa2
#define ZIGBEE_REPORT_V2 0xa3

/* ZIGBEE_SET */
#define ZIGBEE_SET_net 0xa1
#define ZIGBEE_SET_pow 0xa2
#define ZIGBEE_SET_tagfreq 0xa3

/* PDOA_REPORT */
#define PDOA_V1 0xa0

/* role type */
#define ROLE_TYPE_M 0x0001
#define ROLE_TYPE_S 0x0002

typedef enum _ppp_status
{
	pppstatus_defalut,
	pppstatus_start,
	pppstatus_in,
	pppstatus_end
} PPP_STATUS;

typedef struct _ttyread_data_t
{
	int len;
	char data[READSIZE];
} ttyread_data;

#define MAXLENGTH_JSONDATA 512

#define MAXLENGTH_HEX_UWB 256
#define PPP_FRAME_LENGTH (8 + 2 + MAXLENGTH_HEX_UWB)
typedef struct _ppp_frame_t
{
	struct timeval frame_time;
	int ppp_frame_len;
	char ppp_frame[PPP_FRAME_LENGTH];
} ppp_frame_data;

typedef struct _ppp_type_data_t
{
	uint8_t reserve0;
	uint8_t sequence;
	uint8_t datalength;
	uint8_t *data;
	uint16_t crc;
	uint8_t reserve1;
} ppp_type_data;

typedef struct _ppp_uwb_data_t
{
	uint8_t type;
	uint8_t port;
	uint16_t length;
	uint8_t needsend;
	uwb_type uwbtype;
	struct timeval frame_time;
	char *data;
} ppp_uwb_data;

typedef struct _tlv_data_t
{
	unsigned int length;
	char data[PPP_FRAME_LENGTH + 16];
} TLV_data;

/* 2 byte align from stm32 */
#pragma pack(1)

typedef struct _zigbee_report_t
{
	uint64_t zigbeeid;
	uint16_t tid;
	uint8_t freq;
	uint8_t mstate;
	uint8_t battery;
	uint8_t seq;
} zigbee_report_type;

typedef struct _tof_t
{
	uint16_t mid;
	uint16_t uid;
	uint32_t dis;
	float rssi;
} tof_type;

typedef struct _sync_t
{
	uint16_t syncmid;
	uint16_t syncadd;
	uint64_t synctxtim;
	float syncdk;
	uint8_t syncseq;
	uint8_t reserve;
} sync_type;

typedef struct _sync_sta_t
{
	uint16_t syncmid;
	uint16_t syncadd;
	float syncsucc;
	float syncdk;
} sync_sta_type;

typedef struct _tdoa_t
{
	uint16_t aid;
	uint16_t tid;
	uint16_t seq;
	uint64_t arrival;
	uint8_t sn;
	uint8_t sn_1;
	float lueq;
	float mc;
	uint16_t dindex;
	float rssi_all;
	float rssi_fp;
	uint8_t ms_sta;
	uint8_t bp;
} tdoa_type;

typedef struct _tdoag_t
{
	struct _tdoa_t tdoa;
	int16_t axis_x;
	int16_t axis_y;
	int16_t axis_z;
} tdoag_type;

typedef struct _tdoasensor_t
{
	struct _tdoag_t tdoag;
	int16_t gyro_x;
	int16_t gyro_y;
	int16_t gyro_z;
	int16_t mag_x;
	int16_t mag_y;
	int16_t mag_z;
	uint32_t b_baro;
	uint32_t t_baro;
} tdoasensor_type;

typedef struct _tdoainfo_t
{
	struct _tdoa_t tdoa;
	uint8_t temp;
	uint8_t hrs;
	uint8_t mmhgh;
	uint8_t mmhgl;
	uint32_t b_baro;
	uint32_t t_baro;
} tdoainfo_type;

typedef struct _tdoawarn_t
{
	struct _tdoa_t tdoa;
	int8_t warnflag;
	uint8_t warntype;
} tdoawarn_type;

typedef struct _barometer_t
{
	uint16_t aid;
	float temperature;
	float presure;
	uint32_t baro_height;
} barometer_type;

typedef struct _syshrt_t
{
	uint16_t aid;
	uint32_t payload;
	uint32_t runtime;
} syshrt_type;

typedef struct _ack_t
{
	uint8_t ack_sequence;
	uint8_t ack_datatype;
	uint8_t ack_dataport;
	uint8_t ack_reserved;
} ack_type;

typedef struct _uwb_vercfg_t
{
	uint16_t mid;
	uint16_t aid;
	uint16_t panid;
	uint8_t coarsegain;
	uint8_t finegain;
	uint8_t channel;
	uint8_t preamble;
	uint32_t version;
	uint16_t ctrlbit;
} uwb_vercfg_type;

typedef struct _uwb_role_t
{
	uint16_t role;
} uwb_role_type;

typedef struct _pdoa_v1_t
{
	uint16_t tid;
	uint16_t seq;
	float angle;
	int32_t dts;
} pdoa_v1_type;

/*16bit*/
typedef struct _uwbcfg_ctrlbit_t
{
	bool pa : 1;
	bool pwr : 1;
	unsigned reserve0 : 6;
	unsigned reserve1 : 8;
} uwbcfg_ctrlbit_type;

#pragma pack()
/* 2 byte align from stm32 end */

/* 4 byte align */
#pragma pack(4)
typedef struct _zigbee_report_align
{
	uint64_t zigbeeid;
	uint16_t tid;
	uint8_t freq;
	uint8_t mstate;
	uint8_t battery;
	uint8_t seq;
} align_zigbee_report_type;

typedef struct _tof_align
{
	uint16_t mid;
	uint16_t uid;
	uint32_t dis;
	float rssi;
} align_tof_type;

typedef struct _sync_align
{
	uint16_t syncmid;
	uint16_t syncadd;
	uint64_t synctxtim;
	float syncdk;
	uint8_t syncseq;
	uint8_t reserve;
} align_sync_type;

typedef struct _sync_sta_align
{
	uint16_t syncmid;
	uint16_t syncadd;
	float syncsucc;
	float syncdk;
} align_sync_sta_type;

typedef struct _tdoa_align
{
	uint16_t aid;
	uint16_t tid;
	uint16_t seq;
	uint64_t arrival;
	uint8_t sn;
	uint8_t sn_1;
	float lueq;
	float mc;
	uint16_t dindex;
	float rssi_all;
	float rssi_fp;
	uint8_t ms_sta;
	uint8_t bp;
} align_tdoa_type;

typedef struct _tdoag_align
{
	struct _tdoa_t tdoa;
	int16_t axis_x;
	int16_t axis_y;
	int16_t axis_z;
} align_tdoag_type;

typedef struct _tdoasensor_align
{
	struct _tdoag_t tdoag;
	int16_t gyro_x;
	int16_t gyro_y;
	int16_t gyro_z;
	int16_t mag_x;
	int16_t mag_y;
	int16_t mag_z;
	uint32_t b_baro;
	uint32_t t_baro;
} align_tdoasensor_type;

typedef struct _tdoainfo_align
{
	struct _tdoa_t tdoa;
	uint8_t temp;
	uint8_t hrs;
	uint8_t mmhgh;
	uint8_t mmhgl;
	uint32_t b_baro;
	uint32_t t_baro;
} align_tdoainfo_type;

typedef struct _tdoawarn_align
{
	struct _tdoa_t tdoa;
	int8_t warnflag;
	uint8_t warntype;
} align_tdoawarn_type;

typedef struct _barometer_align
{
	uint16_t aid;
	float temperature;
	float presure;
	uint32_t baro_height;
} align_barometer_type;

#pragma pack()
/* 4 byte align end */

char datatype_need_ack(char datatype);
void *ppp_frame_thread_func(void *indata);
int recevice_from_tty(int fd, Thread_data *ttyread_buffer);
void printf_hex(char *title, unsigned char *hex, int n);

#endif
