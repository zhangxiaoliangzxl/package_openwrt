#ifndef CLOUD_WLAN_PUB_H_
#define CLOUD_WLAN_PUB_H_

#define CWLAN_OK 0
#define CWLAN_FAIL 1


#define PROTO_DNS 53
#define PROTO_DHCP67 67
#define PROTO_DHCP68 68
#define PROTO_SNMP1 161
#define PROTO_SNMP2 162
#define PROTO_HTTP 80
#define PROTO_HTTP2 8080
#define PROTO_HTTPS 443
#define PROTO_SSH 22

#define PROTO_CAPWAP_C 5246
#define PROTO_CAPWAP_D 5247

extern u32 g_cloud_wlan_debug;
extern u32 g_cloud_wlan_nlmsg_pid;
extern u8 APWanIfname[16];
extern u8 APMac[6];
extern u8 ACMAC[6];
extern u32 ACPort;
extern u32 ACAddr;
extern u32 APAddr;
extern int gTemplateID_1;
extern int gTemplateID_2;

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

#define FIRST_FRAGMENT_FLAG			1550//(1518 + UDP_HDR_LEN + WLTP_HEADER_LEN)
#define SECOND_FRAGMENT_FLAG		 1480


#define RES_BUSY_8					(0x80)
#define RES_BUSY_16					(0x8000)
#define RES_BUSY_32					(0x80000000)
#define WLTP_PKT_BUFFER_LENGTH		(1800)
#define WLTP_FRAGMENT_BUFFER_NUM	(100)

#define WLTP_DEAL_SUCCESS			0/*< 分片WLTP报文，且组包成功*/
#define WLTP_DEAL_WAIT				1
#define WLTP_DEAL_FAIL				2
#define WLTP_PKG_NOT_BURST			3/*< 未分片的WLTP报文*/


#define PROTO_DHCP67 67
#define PROTO_DHCP68 68

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02X:%02X:%02X:%02X:%02X:%02X"

/*< 限速标记从10开始，5.8G从18开始,wltp隧道中vap index也使用这个值*/
#define SSID_LIMIT_BANDWIDTH_CLASSID_OFFSET		10

/*< DHCP option*/
#define DHCP_BOOT_REQUEST				1
#define DHCP_BOOT_REPLY					2

#define DHCP_MSG_TYPE_DISCOVER			1
#define DHCP_MSG_TYPE_OFFER				2
#define DHCP_MSG_TYPE_REQUEST			3
#define DHCP_MSG_TYPE_ACK				5

#define DHCP_MSG_TYPE					53
#define DHCP_VENDOR_SPECIFIC_INFO		43


#define SSID_LIMTI_MARK_VLAN_OFFSET				16
#define SSID_LIMTI_MARK_CLASSID_OFFSET			6
#define SSID_LIMTI_MARK_VAP_OFFSET				2
#define SSID_LIMTI_MARK_WLANCARD_OFFSET			0


typedef struct
{
	uint16_t	buno;   
	uint16_t	length;   
	uint8_t		wltp_pkt_data[WLTP_PKT_BUFFER_LENGTH];
} wltp_fragment_buffer_t;


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

typedef struct
{
	uint8_t	msgType;
	uint8_t	hardwareType;
	uint8_t	hdAddrLen;
	uint8_t	hops;
	uint32_t transactionID;
	uint16_t secondElapsed;
	uint16_t bootpFlags;
	uint32_t clientIP;
	uint32_t yourIP;
	uint32_t nextServerIP;
	uint32_t relayAgentIP;
	uint8_t clientMac[6];
	uint8_t clientHdPadding[10];
	uint8_t serverHostName[64];
	uint8_t bootFileName[128];
	uint32_t magicCookie;
	/*< 考虑字节对齐，所以，ACK通过偏移来匹配*/
//	uint8_t dhcpMsgType[3];
//	uint8_t maximumMsgSize[4];
//	uint8_t paramReqList[9];
//	uint8_t vendorClassID[12];
//	uint8_t endOption;
//	uint8_t padding[29];
} dhcp_cfg;

typedef struct{
	uint8_t id;
	uint8_t len;
	uint8_t ip[4];
}option43_ip_cfg;

typedef struct{
	uint8_t res1;
	uint8_t res2;
	option43_ip_cfg ipInfo[4];
}option43_cfg;

extern u32 g_option43_flag;
extern option43_cfg g_option43_info;


typedef struct{
	int ret;		/*<组包结果*/
	int addBytes;	/*< 若组包成功，此位代表此数据包所新增的数据字节数，若组包失败，此位代表数据包需要扩充的字节数*/
}wltp_deal_info;

#define VLANID_LENGH 4

#define WLTP_HEADER_LENGTH 24

#define MAC_MACADDR_LENGTH 14
#define MAC_NETWORK_HEAD_LENGTH 20
#define MAC_TRANSPORT_HEAD_LENGTH 8

#define WLTP_HEARD_OFFSET 28//MAC_NETWORK_HEAD_LENGTH+MAC_TRANSPORT_HEAD_LENGTH
#define WLTP_DATA_OFFSET 52//MAC_NETWORK_HEAD_LENGTH+MAC_TRANSPORT_HEAD_LENGTH+WLTP_HEADER_LENGTH

//g_cloud_wlan_debug
#define CLOUD_WLAN_DEBUG(str, args...)  \
{\
	if(g_cloud_wlan_debug)\
	{\
		printk(str, ##args);\
	}\
}
extern s32 cloud_wlan_sendto_umod(s32 type, s8 *buff, u32 datalen);


#endif

