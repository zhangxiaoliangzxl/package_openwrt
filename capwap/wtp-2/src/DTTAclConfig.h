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

#define WTP_TRAP_STA_ONLINE_LEN		(198+2+2)//ÄÚÈÝ198£¬id 2£¬lenth 2
#define WTP_VENDOR_ID_LENTH			4
#define WTP_VENDOR_ELEMENT_ID_LENTH			2
#define WTP_VENDOR_ELEMENT_LEN_LENTH		2

enum {
	HOSTAPD_ACL_REJECT = 0,
	HOSTAPD_ACL_ACCEPT = 1,
	HOSTAPD_ACL_PENDING = 2,
	HOSTAPD_ACL_ACCEPT_TIMEOUT = 3
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


#endif//DTT_ACLCONF_HEARD
