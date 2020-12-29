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

#define SSID_LIMTI_MARK_VLAN_OFFSET				16
#define SSID_LIMTI_MARK_CLASSID_OFFSET			6
#define SSID_LIMTI_MARK_VAP_OFFSET				2
#define SSID_LIMTI_MARK_WLANCARD_OFFSET			0

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
#define UCI_COMMIT_NTPCLIENT		"uci commit system"
#define NETWORK_RELOAD				"/etc/init.d/network reload > /dev/null"
#define SYSTEM_RELOAD				"/etc/init.d/system reload"
#define NTPCLIENT_RESTART			"/etc/init.d/ntpclient restart &"
#define NTPCLIENT_STOP				"/etc/init.d/ntpclient stop &"
#define WIFI_RESTART				"wifi reload > /dev/null"
#define SWITCH_RELOAD               "swconfig dev eth0 load network && fix_wan_vlan"
#define NTPD_RELOAD                 "/etc/init.d/sysntpd restart"

#define WIFI_RELOAD(cmd, index)		\
				{CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);\
				sprintf(cmd, "wifi reload wifi%d", index);\
				system(cmd);}

#define UCI_DELETE_WIRELESS_DEVICE_0	"uci delete wireless.@wifi-device[0]."
#define UCI_DELETE_WIRELESS_DEVICE_1	"uci delete wireless.@wifi-device[1]."

#define UCI_SET_WIRELESS_DEVICE_0	"uci set wireless.@wifi-device[0]."
#define UCI_SET_WIRELESS_DEVICE_1	"uci set wireless.@wifi-device[1]."

#define UCI_SET_WIRELESS_IFACE		"uci set wireless.@wifi-iface"

#define UCI_SET_NTPD	"uci set system.ntp.server="
#define UCI_SET_NTPCLIENT	"uci set ntpclient.@ntpserver[0].hostname="


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

#define EBTABLES_ADD_UNICAST_STATISTIC_RULE(chain, port)	\
				{memset(buf, 0, sizeof(buf));\
				if(inout==1)\
				sprintf(buf, "ebtables -A %s -o %s -d Unicast -j RETURN", chain, port);\
				else\
				sprintf(buf, "ebtables -A %s -i %s -d Unicast -j RETURN", chain, port);\
				system(buf);}
#define EBTABLES_ADD_MULTICAST_STATISTIC_RULE(chain, port)	\
				{memset(buf, 0, sizeof(buf));\
				if(inout==1)\
				sprintf(buf, "ebtables -A %s -o %s -d Multicast -j RETURN", chain, port);\
				else\
				sprintf(buf, "ebtables -A %s -i %s -d Multicast -j RETURN", chain, port);\
				system(buf);}
#define EBTABLES_ADD_BROADCAST_STATISTIC_RULE(chain, port)	\
				{memset(buf, 0, sizeof(buf));\
				if(inout==1)\
				sprintf(buf, "ebtables -A %s -o %s -d Broadcast -j RETURN", chain, port);\
				else\
				sprintf(buf, "ebtables -A %s -i %s -d Broadcast -j RETURN", chain, port);\
				system(buf);}

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
				sprintf(cmd, "tc class replace dev %s parent 1: classid 1:%d htb rate %dkbit burst 10k quantum 1500", dev, id, limit);\
				system(cmd);}
/*< 清空一个类别*/
#define TC_CLEAR_CLASS_TRAFFIC_LIMIT(cmd, dev, id)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "tc class del dev %s classid 1:%d", dev, id);\
				system(cmd);}

/*< 添加过滤器，将流量导向相应的类*/
#define TC_ADD_FILTER(cmd, dev, mark, id)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "tc filter replace dev %s parent 1: prio 2 handle %d fw flowid 1:%d", dev, mark, id);\
				system(cmd);}
/*< 清空过滤器*/
#define TC_DEL_FILTER(cmd, dev, mark, id)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "tc filter del dev %s parent 1: prio 2 handle %d fw flowid 1:%d", dev, mark, id);\
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
/*< 基于MAC地址限速，直接使用tc的u32匹配MAC地址，在wlan上进行限速*/
#define TC_STA_UPLOAD_FILTER(cmd, wlan, mac, id)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "tc filter replace dev %s parent 1: protocol ip prio 1 u32 match u16 0x0800 0xffff at -2 match u16 0x%02X%02X 0xffff at -4 match u32 0x%02X%02X%02X%02X 0xffffffff at -8 flowid 1:%d", \
					wlan, mac[4],mac[5],mac[0], mac[1], mac[2], mac[3], id);\
				system(cmd);}
#define TC_STA_DOWNLOAD_FILTER(cmd, wlan, mac, id)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "tc filter replace dev %s parent 1: protocol ip prio 1 u32 match u16 0x0800 0xffff at -2 match u32 0x%02X%02X%02X%02X 0xffffffff at -12 match u16 0x%02X%02X 0xffff at -14 flowid 1:%d", \
					wlan, mac[2], mac[3], mac[4],mac[5],mac[0], mac[1], id);\
				system(cmd);}
#define TC_STA_CLEAR_FILTER(cmd, wlan)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "tc filter del dev %s parent 1: protocol ip prio 1", wlan);\
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

typedef struct 
{
	unsigned char isSeted_5;			/*< 第二张卡的配置标志,若第二张卡已配置，需要在vlan信息修改后，重新配置卡2的vlan*/
	unsigned int vapSwitch[MAX_VAP*2];
	unsigned int vapVlan[MAX_VAP*2];	/*< 将全局vap信息保存*/
	unsigned int trafficLimitSwitch[MAX_VAP*2];
	unsigned int downLoadLimit[MAX_VAP*2];
	/*< 基于sta上行限速*/
	staLimitCfg *upLoadStaLimit[1024];
	/*< network文件中switch配置，lan和wan配置为0和1，vlan的配置从下标2开始*/
	unsigned int switchId;
}vapPublicCfg;

typedef struct{
	unsigned int ntpswitch;
	unsigned int ip;
}ntpCfg;

#define WEP_KEY_64BIT         (40)
#define WEP_KEY_128BIT        (104)
#define WEP_KEY_152BIT        (128)
#define WEP_KEY_LENGTH        (44)

typedef struct{
	unsigned long wep_key_type;
	unsigned char key1[WEP_KEY_LENGTH];
	unsigned char key2[WEP_KEY_LENGTH];
	unsigned char key3[WEP_KEY_LENGTH];
	unsigned char key4[WEP_KEY_LENGTH];
	unsigned char passphrase[WEP_KEY_LENGTH];
	unsigned char wep_swh[MAX_VAP];
	unsigned long def_wep_key[MAX_VAP];
}WEPCfg;

CWBool DTTDispatchCfgUpdateCmd(CWProtocolVendorSpecificValues *valPtr, CWProtocolMessage *msgPtr, unsigned short len, char *buf);
#if 1
CWBool DTTParseWTPVersion(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIWirelessHwmode(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIWirelessIsDisable(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIWirelessCountryCode(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIWirelessChannel(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIWirelessRTS(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIWirelessTxPower(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIWirelessVAPSwitch(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIWirelessSSID(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIWirelessHideSSID(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) ;
CWBool DTTParseUCIWirelessAutoChannel(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIWirelessBeaconInterval(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIWirelessVAPVlan(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseIsolate(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIAPPassword(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIAPName(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCI11nChanMode(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseACLControl(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseACLSSIDList(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseACLVlanList(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIWirelessAuthType(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIWirelessEncryptType(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIWirelessWPAPSK(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIWirelessWEPParameter(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseFirmwareFilename(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseFTPServerIP(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseDoUpdate(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseFTPServerUser(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseFTPServerPwd(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseLocalForwardSwitch(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseVAPTrafficLimitSwitch(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIShortGI(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseVAPUploadLimit(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseVAPDownloadLimit(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseRebootAP(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseResetFactoryAP(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseStaLimit(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseTemplateID(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseDataTunnelIP(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIRadiusServer(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIRadiusPort(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIRadiusSecret(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIWirelessDtimInterval(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIWirelessPreamble(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIWirelessWmm(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseUCIVapMaxSta(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseStaTrafficLimitSwitch(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseNTPSwitch(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
CWBool DTTParseNTPServerIP(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr);
#endif
unsigned int getCountryCodeCfg();
unsigned int getDataTunnelIP();

void setUploadLimit(char *cmd, char index);
void setDownloadLimit(char *cmd, char index);
void getAllVapVlanID(unsigned int *pvlan);
unsigned int getVapVlanID(int index);
unsigned int getVapSwitch(int index);
unsigned int getWirelessMode(char index);
void APOnlineTypeLock(void);
void APOnlineTypeUnLock(void);
void setAPOnlineACIPandCount(int count, char *ip);
int getAPOnlineACCountOption43();
void getAPOnlineACIPOption43(CWACDescriptor *CWACList);

#endif
