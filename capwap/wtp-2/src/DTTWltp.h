#ifndef DTTWLTP_H
#define DTTWLTP_H
#define DEBUG_RCV_WLTP_PKT  (1)

#define  WLTP_DATA_PORT_AC    (6969)
#define  WLTP_DATA_PORT_AP    (7070)

#define WLTP_PROTOCOL  0x3838
#define WLTP_TYPE  0x000b
#define WLTP_HEADER_LEN 				16 + 8
#define UDP_HDR_LEN			8
#define IP_HDR_LEN				20
#define ETH_HDR_LEN			14
#define MAC_VLAN_IP_UDP_LENGTH  		46
#define MAC_IP_UDP_LENGTH  			42
#define ALL_HEADER_SPACE_VLAN_WLTP 	(MAC_VLAN_IP_UDP_LENGTH + WLTP_HEADER_LEN)
#define ALL_HEADER_SPACE_WLTP 		(MAC_IP_UDP_LENGTH + WLTP_HEADER_LEN)
#define IP_TUN_TTL 						32
#define MAX_LENGTH_FOR_MAC_WLTP 		(1518 - ALL_HEADER_SPACE_VLAN_WLTP)
#define MAX_FRAGMENT_LENGTH 			1444

#define FIRST_FRAGMENT_FLAG			(1518 + UDP_HDR_LEN + WLTP_HEADER_LEN)//1550
#define SECOND_FRAGMENT_FLAG		 1480

void WltpLocalSocket_init();
void WltpKeepAlive_settimer(CWNetworkLev4Address preferredAddress);
void WltpKeepAlive_stoptimer(void);

CWBool CWNetworkInitSocketClientDataChannel(CWSocket *sockPtr, CWNetworkLev4Address *addrPtr);

typedef unsigned char	  uint8_t;
typedef unsigned short	  uint16_t;
typedef unsigned int	  uint32_t;

typedef struct
{
	uint16_t	protocol;   
	uint16_t	type;	
	uint32_t	seq;			
	uint16_t	length;		
	uint16_t	fragment;						  
	uint32_t	rssi;
	uint8_t	vapIndex;
	uint8_t	pad1;
	uint16_t	configid;
	uint32_t	pad2;
} wltp_header;


#define RES_BUSY_8					(0x80)
#define RES_BUSY_16					(0x8000)
#define RES_BUSY_32					(0x80000000)
#define WLTP_PKT_BUFFER_LENGTH		(1800)
#define WLTP_FRAGMENT_BUFFER_NUM	(100)

typedef struct
{
	uint16_t	buno;   
	uint16_t	length;   
	uint8_t		wltp_pkt_data[WLTP_PKT_BUFFER_LENGTH];
} wltp_fragment_buffer_t;

#define WLTP_TRANSFER_PKT_TO_AP  "/tmp/wltp_ap_sock"  //del wltp header
#define WLTP_TRANSFER_PKT_TO_AC  "/tmp/wltp_ac_sock"  //add wltp header

//本地连接握手，通知对方进程已经启动
#define WLTP_CONNECT 4
#define WLTP_CONNECT_R 5

extern unsigned int gTemplateID;

#endif /*DTTWLTP_H*/

