#ifndef __CAPWAP_DTTConfigUp_HEADER__
#define __CAPWAP_DTTConfigUp_HEADER__

/************************************************************************************************
 * Copyright (c) DTT																			*
 *																								*
 * -------------------------------------------------------------------------------------------- *
 * Project:  DTT Capwap																			*
 *																								*
 * Authors : Suhongbo (suhongbo@datang.com)
 *
 ************************************************************************************************/
	
#define MAX_VAP		8

#define UCI_CMD_LENGTH	255

#define SSID_LIMIT_BANDWIDTH_CLASSID_OFFSET		10
#define STA_LIMIT_BANDWIDTH_CLASSID_OFFSET		32

#define WIRELESSMODE_11A        0x0001
#define WIRELESSMODE_11B        0x0002
#define WIRELESSMODE_11G        0x0004
#define WIRELESSMODE_11AN       0x0008
#define WIRELESSMODE_11BGN      0x0010
#define WIRELESSMODE_11AC       0x0020

#define UCI_COMMIT					"uci commit"
#define UCI_COMMIT_SYSTEM			"uci commit system"
#define UCI_COMMIT_NETWORK			"uci commit network"
#define UCI_COMMIT_WIRELESS			"uci commit wireless"
#define NETWORK_RELOAD				"/etc/init.d/network reload & 2 > /dev/null"
//#define NETWORK_RELOAD				"echo network reload > /dev/console"
#define SYSTEM_RELOAD				"/etc/init.d/system reload"
#define WIFI_RESTART				"wifi & 2 > /dev/null"


#define UCI_DELETE_WIRELESS_DEVICE_0	"uci delete wireless.@wifi-device[0]."
#define UCI_DELETE_WIRELESS_DEVICE_1	"uci delete wireless.@wifi-device[1]."

#define UCI_SET_WIRELESS_DEVICE_0	"uci set wireless.@wifi-device[0]."
#define UCI_SET_WIRELESS_DEVICE_1	"uci set wireless.@wifi-device[1]."

#define UCI_SET_WIRELESS_IFACE		"uci set wireless.@wifi-iface"

#define UCI_IFACE_SET_PARAM_INT(cmd, index, param, value)		\
				{CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);\
				sprintf(cmd, UCI_SET_WIRELESS_IFACE "[%d]." "%s=%d", index, param, value);\
				system(cmd);}
#define UCI_IFACE_SET_PARAM_STRING(cmd, index, param, value)		\
				{CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);\
				sprintf(cmd, UCI_SET_WIRELESS_IFACE "[%d]." "%s=%s", index, param, value);\
				system(cmd);}
#define UCI_IFACE_DEL_PARAM(cmd, index, param)		\
				{CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);\
				sprintf(cmd, "uci delete wireless.@wifi-iface[%d].%s", index, param);\
				system(cmd);}

#define EBTABLES_ADD_BROADCAST(wlan, cmd)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "ebtables -A FORWARD -i %s -o %s -d ff:ff:ff:ff:ff:ff/ff:ff:ff:ff:ff:ff -j DROP", wlan, wlan);\
				system(cmd);}

#define EBTABLES_DEL_BROADCAST(wlan, cmd)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "ebtables -D FORWARD -i %s -o %s -d ff:ff:ff:ff:ff:ff/ff:ff:ff:ff:ff:ff -j DROP", wlan, wlan);\
				system(cmd);}

#define EBTABLES_ADD_UNICAST(wlan, cmd)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "ebtables -A FORWARD -i %s -o %s -d 00:00:00:00:00:00/01:00:00:00:00:00 -j DROP", wlan, wlan);\
				system(cmd);}

#define EBTABLES_DEL_UNICAST(wlan, cmd)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "ebtables -D FORWARD -i %s -o %s -d 00:00:00:00:00:00/01:00:00:00:00:00 -j DROP", wlan, wlan);\
				system(cmd);}

#define EBTABLES_SET_MARK(chain, wlan, mark, cmd)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "ebtables -t nat -A "chain" -i %s -j mark --mark-set %d --mark-target CONTINUE", wlan, mark);\
				system(cmd);\
				memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "ebtables -t nat -A "chain" -i %s -j RETURN", wlan);\
				system(cmd);}

#define EBTABLES_CLEAR_CHAIN(chain, cmd)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "ebtables -t nat -F "chain);\
				system(cmd);}

/*< 等待无线初始化完成，设置下行限速队列*/
#define TC_SLEEP_WAIT_WLAN(cmd, dev)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "i=0;while [ `ifconfig | grep %s |  wc -l` -lt 1 ] && [ $i -lt 3 ];do i=`expr $i + 1`;sleep 1;done", dev);\
				system(cmd);}

/*< 清除顶层队列*/
#define TC_QISC_CLEAR_ROOT(cmd, dev)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "tc qdisc del dev %s root", dev);\
				system(cmd);}

/*< 定义顶层队列*/
#define TC_QISC_ROOT_CREAT(cmd, dev)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "tc qdisc add dev %s root handle 1: htb default 256", dev);\
				system(cmd);}
/*< 创建每一个类别*/
#define TC_TRAFFIC_LIMIT(cmd, dev, id, limit)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "tc class replace dev %s parent 1: classid 1:%d htb rate %dkbit burst 15k quantum 1500", dev, id, limit);\
				system(cmd);}
/*< 清空一个类别*/
#define TC_CLEAR_CLASS_TRAFFIC_LIMIT(cmd, dev, id)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "tc class del dev %s classid 1:%d", dev, id);\
				system(cmd);}

/*< 添加过滤器，将流量导向相应的类*/
#define TC_ADD_FILTER(cmd, dev, mark, id)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "tc filter replace dev %s parent 1: prio 1 handle %d fw flowid 1:%d", dev, mark, id);\
				system(cmd);}
/*< 清空过滤器*/
#define TC_DEL_FILTER(cmd, dev, mark, id)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "tc filter del dev %s parent 1: prio 1 handle %d fw flowid 1:%d", dev, mark, id);\
				system(cmd);}
/*< 上行  给数据流打标记，以使流量流向相应类*/
#define TC_UPLOAD_EBTABLES_MARK(cmd, inWlan, mark, chain)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "ebtables -t nat -A "chain" -i %s -j mark --mark-set %d --mark-target CONTINUE", inWlan, mark);\
				system(cmd);\
				memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "ebtables -t nat -A "chain" -i %s -j RETURN", inWlan);\
				system(cmd);}
/*< 下行 给数据流打标记，以使流量流向相应类*/
#define TC_DOWNLOAD_EBTABLES_MARK(cmd, inWlan, mark,chain)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "ebtables -t nat -A "chain" -o %s -j mark --mark-set %d --mark-target CONTINUE", inWlan, mark);\
				system(cmd);\
				memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "ebtables -t nat -A "chain" -o %s -j RETURN", inWlan);\
				system(cmd);}
/*< 保证数据的公平性*/
#define TC_QDISC_SQF(cmd, dev, id, mark)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "tc qdisc replace dev %s parent 1:%d handle %d: sfq perturb 10", dev, id, mark);\
				system(cmd);}
/*< sta上行  给数据流打标记，以使流量流向相应类*/
/*< sta在ebtables中被匹配后，直接accept，不再继续下面的基于SSID限速的打mark，也就是说，如果即有SSID限速，也有基于mac的限速，以mac限速为准*/
/*< QOS_STA_UPLOAD_CHAIN链的默认规则是RETURN*/
#define TC_STA_UPLOAD_EBTABLES_MARK(cmd, mac, mark)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "ebtables -t nat -A QOS_STA_UPLOAD_CHAIN -s %s -j mark --mark-set %d --mark-target ACCEPT", mac, mark);\
				system(cmd);}


#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

/*< VAP的认证方式*/
#define WIRELESS_AUTH_OPEN_SYSTEM			0x00
#define WIRELESS_AUTH_SHARED_KEY			0x01
#define WIRELESS_AUTH_LEGACY_8021X			0x02
#define WIRELESS_AUTH_WPA_WITH_RADIUS		0x04
#define WIRELESS_AUTH_WPA2_WITH_RADIUS		0x08
#define WIRELESS_AUTH_WPA_WPA2_WITH_RADIUS	(0x04|0x08)
#define WIRELESS_AUTH_WPA_PSK				0x10
#define WIRELESS_AUTH_WPA2_PSK				0x20
#define WIRELESS_AUTH_WPA_WPA2_PSK			(0x10|0x20)
#define WIRELESS_AUTH_WAPI_PSK				0x40
#define WIRELESS_AUTH_WAPI_CERT				0x80
/*< VAP的加密方式*/
#define WIRELESS_AUTH_ENCRYPT_NONE			0x00
#define WIRELESS_AUTH_ENCRYPT_WEP			0x01
#define WIRELESS_AUTH_ENCRYPT_TKIP			0x02
#define WIRELESS_AUTH_ENCRYPT_AES			0x04
#define WIRELESS_AUTH_ENCRYPT_AES_TKIP		0x06  /*< 协议中为0x8，实际数据报文中为0x6*/

/*******************/

enum{
	ACL_TYPE_RESPONSR=0,
	ACL_TYPE_DEFAULT_ACCEPT=1,
	ACL_TYPE_DEFAULT_REJECT=2,
	ACL_TYPE_CLEAR_WHITE_LIST=3,
	ACL_TYPE_CHANGE_WHITE_LIST=4,
	ACL_TYPE_SWITCH_ON=5,
	ACL_TYPE_SWITCH_OFF=6,
	ACL_TYPE_SSID_SWITCH_ON=7,
	ACL_TYPE_VLAN_SWITCH_ON=8,
};


typedef struct localCfgStruct{
	int flag;/*< 为1时，需在设置vlan以及vap的时候重新设置集中转发设置*/
	unsigned char localSwitch[MAX_VAP];
}localCfg;

typedef struct __updateCfg{
	char *name;
	struct in_addr *ip;
	char *user;
	char *password;
}updateCfg;
/*< 基于sta mac限速的结构*/
typedef struct __staLimitCfg{
	unsigned char mac[6];
	unsigned short rev;
	unsigned int up;
	unsigned int down;
}staLimitCfg;

CWBool DTTParseUCIWirelessHwmode(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIWirelessIsDisable(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIWirelessCountryCode(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIWirelessChannel(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIWirelessRTS(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIWirelessTxPower(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIWirelessVAPSwitch(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIWirelessSSID(CWProtocolMessage *msgPtr, char *cmd, unsigned short len, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIWirelessHideSSID(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr) ;
CWBool DTTParseUCIWirelessAutoChannel(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIWirelessBeaconInterval(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIWirelessVAPVlan(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseIsolate(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIAPPassword(CWProtocolMessage *msgPtr, char *cmd, unsigned short len, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIAPName(CWProtocolMessage *msgPtr, char *cmd, unsigned short len, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCI11nChanMode(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseACLControl(CWProtocolMessage *msgPtr, char *cmd, unsigned short len, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIWirelessAuthType(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIWirelessEncryptType(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIWirelessWPAPSK(CWProtocolMessage *msgPtr, char *cmd, unsigned short len, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseFirmwareFilename(CWProtocolMessage *msgPtr, unsigned short len);
CWBool DTTParseFTPServerIP(CWProtocolMessage *msgPtr, unsigned short len);
CWBool DTTParseDoUpdate(char *cmd);
CWBool DTTParseFTPServerUser(CWProtocolMessage *msgPtr, unsigned short len);
CWBool DTTParseFTPServerPwd(CWProtocolMessage *msgPtr, unsigned short len);
CWBool DTTParseLocalForwardSwitch(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseVAPTrafficLimitSwitch(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIShortGI(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseVAPUploadLimit(CWProtocolMessage *msgPtr, char *cmd);
CWBool DTTParseVAPDownloadLimit(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseRebootAP(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseResetFactoryAP(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseStaLimit(CWProtocolMessage *msgPtr, char *cmd, unsigned short len, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseTemplateID(CWProtocolMessage *msgPtr);
CWBool DTTParseUCIRadiusServer(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIRadiusPort(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIRadiusSecret(CWProtocolMessage *msgPtr, char *cmd, unsigned short len, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIWirelessDtimInterval(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIWirelessPreamble(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIWirelessWmm(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);
CWBool DTTParseUCIVapMaxSta(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr);

unsigned int getCountryCodeCfg();

void setDownloadLimit(char *cmd, char index);
void getAllVapVlanID(unsigned int *pvlan);
unsigned int getVapVlanID(int index);
unsigned int getVapSwitch(int index);
unsigned int getWirelessMode();
void APOnlineTypeLock(void);
void APOnlineTypeUnLock(void);
void setAPOnlineACIPandCount(int count, char *ip);
int getAPOnlineACCountOption43();
void getAPOnlineACIPOption43(CWACDescriptor *CWACList);

#endif
