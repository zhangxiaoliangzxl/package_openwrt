#ifndef DTT_ACLCONF_HEARD
#define DTT_ACLCONF_HEARD


#define WTP_UNIXSOCK_PATH_1 "/tmp/wtp_sock_1"
#define WTP_UNIXSOCK_PATH_2 "/tmp/wtp_sock_2"
#define WTP_UNIXSOCK_PATH_DATA_1 "/tmp/wtp_datasock_1"
#define WTP_UNIXSOCK_PATH_DATA_2 "/tmp/wtp_datasock_2"
#define HOSTAPD_UNIXSOCK_PATH_1 "/tmp/hostapd_sock_1"
#define HOSTAPD_UNIXSOCK_PATH_2 "/tmp/hostapd_sock_2"
#define HOSTAPD_UNIXSOCK_PATH_DATA_1 "/tmp/hostapd_datasock_1"
#define HOSTAPD_UNIXSOCK_PATH_DATA_2 "/tmp/hostapd_datasock_2"


#define CW_OK 0
#define CW_FAIL -1

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

#define WTP_TRAP_STA_ONLINE_LEN		(198+2+2)//内容198，id 2，lenth 2
#define WTP_VENDOR_ID_LENTH			4
#define WTP_VENDOR_ELEMENT_ID_LENTH			2
#define WTP_VENDOR_ELEMENT_LEN_LENTH		2

enum {
	HOSTAPD_ACL_REJECT = 0,
	HOSTAPD_ACL_ACCEPT = 1,
	HOSTAPD_ACL_PENDING = 2,
	HOSTAPD_ACL_ACCEPT_TIMEOUT = 3,
};

enum {
	ACL_OFF = 0,
	MACL_ACL_ON = 1,
	SSID_ACL_ON = 2,
	VLAN_ACL_ON = 3,
};

/*< hostapd与wtp通信的帧格式*/
struct dtt_acl_wtp_data{
	unsigned char sa[6];	/*< sta的mac地址*/
	unsigned char vapId;	/*< 该sta关联的vap号*/
	unsigned char phyId;	/*< 该sta关联的phy号*/
	unsigned char ssid[32];
};

struct dtt_acl_vlan_cfg{
	/*< AC会根据该AP已配置的VLAN进行ACL的vlan下发，所以16个足够*/
	unsigned short aclVlan[16];
	unsigned short count;
};

typedef struct aclControlCfg_t{
	unsigned char mac[6];
	char aclAuthRes;
	char aclType;
}aclControlCfg;

typedef struct staTrapInfo_t
{
	char			tapMac[6];
	char			apName[64];
	char			trapInfo[128];
}__attribute__ ((packed)) staTrapInfo;

CW_THREAD_RETURN_TYPE CWControlAcl(void *arg);
void setWTPEventReponseSeqnum(int num);
void setACLSwitch(int flag);
void setAclAuthResultInfo(aclControlCfg *pinfo);
int setConfigUpdateReponseCond(int flag);
unsigned char *getAclssidList();
unsigned short *getAclVlanList();
int getVlanIDFromWlanId(char index, char cardId);
void ACLSSIDEditLock(void);
void ACLSSIDEditUnLock(void);

#endif//DTT_ACLCONF_HEARD
