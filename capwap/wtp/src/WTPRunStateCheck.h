/************************************************************************************************
 * Copyright (c) DTT																			*
 *																								*
 * -------------------------------------------------------------------------------------------- *
 * Project:  DTT Capwap																			*
 *																								*
 * Authors : Suhongbo (suhongbo@datang.com)
 *
 ************************************************************************************************/
#ifndef __CAPWAP_DTTWTP_RUNSTATE_HEADER__
#define __CAPWAP_DTTWTP_RUNSTATE_HEADER__

#define WTP_ETH_MTU_FILE_PATH "/sys/class/net/eth0/mtu"
#define WTP_ETH_WIDTH_FILE_PATH "/sys/class/net/eth0/speed"
#define WTP_WLAN0_MTU_FILE_PATH "/sys/class/net/wifi0/mtu"
#define WTP_WLAN1_MTU_FILE_PATH "/sys/class/net/wifi1/mtu"
#define WTP_WLAN_BSSID_NAME "/sys/class/net/%s/address"


/*< openwrt的无线接口名命名规则为wlan0,wlan0-1,...*/
#define WTP_GET_CARD1_VAP_NUM_CMD "ifconfig | grep ath0 | wc -l"
/*< openwrt的无线接口名命名规则为wlan1,wlan1-1,...*/
#define WTP_GET_CARD2_VAP_NUM_CMD "ifconfig | grep ath1 | wc -l"
#define WTP_GET_WLAN_0_TXPOWER "iwconfig ath0 | grep Tx-Power"
#define WTP_GET_WLAN_1_TXPOWER "iwconfig ath1 | grep Tx-Power"
#define WTP_GET_VAP_CONNECT_STA_NUM "wlanconfig %s list | grep ..:..:..:..:..:.. | wc -l"

#define WTP_GET_NETWORK_MASK "ifconfig br-lan | grep Mask | awk -F \":\" {'printf $4'}"

#define WTP_GET_AP_CPU_INFO "cat /proc/cpuinfo | grep -e \"system type\" -e \"cpu model\"| awk -F\":\" '{printf $2}' | awk '{sub(\"^ *\",\"\");print}'"

#define WTP_GET_UCI_LAN_PROTO "uci get network.lan.proto"
#define WTP_GET_UCI_VAP_SSID "uci get wireless.@wifi-iface[%d].ssid"

struct vap_stat_cfg{
	int assoc_req;
	int assoc_resp;
	int assoc_success;
	int auth_req;
	int auth_resp;
	int auth_success;
	int reassoc_req;
	int reassoc_resp;
	int reassoc_success;
	int active_disassoc;
	int deauth;
};


struct hostapd_stat_sta_cfg{
	/*< 单张卡的统计信息*/
	int radio_assoc_req;
	int radio_assoc_resp;
	int radio_assoc_success;
	int radio_auth_req;
	int radio_auth_resp;
	int radio_auth_success;
	int radio_reassoc_req;
	int radio_reassoc_resp;
	int radio_reassoc_success;
	int radio_active_disassoc;
	int radio_deauth;
	/*< hostapd中统计了无线所有vap的用户关联情况*/
	struct vap_stat_cfg vap_stat[8];
};

typedef struct {
	char *pData;
	short size;
}protocolStaInfo;

enum {
	HOSTAPD_STATISTIC_INVALID = 0,
	HOSTAPD_STATISTIC_TIMEOUT = 1,
	HOSTAPD_STATISTIC_REJECT = 2,
	HOSTAPD_STATISTIC_OTHER = 3,
	HOSTAPD_STATISTIC_DE_USER_LEAVE = 4,
	HOSTAPD_STATISTIC_DE_WTP_CAPABILITY = 5,
	HOSTAPD_STATISTIC_DE_EXCEPTION = 6,
	HOSTAPD_STATISTIC_DE_OTHER = 7,
};


#endif

