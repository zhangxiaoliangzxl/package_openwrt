#ifndef CLOUD_WLAN_NL_H_
#define CLOUD_WLAN_NL_H_



#define NETLINK_CWLAN		25	/*netlink����ţ����Ϊ32*/
/** ������ݸ���(�̶�) **/  
#define MAX_DATA_PAYLOAD 512
/** ���Э�鸺��(�̶�) **/  
#define MAX_PROTOCOL_LPAYLOAD (MAX_DATA_PAYLOAD + 8)
/*��������̫�󳤶�*/
#define CW_DES_LEN (MAX_DATA_PAYLOAD/2)
/*���������ֵ*/
#define CW_WHITE_LIST_MAX 100
/*URL��󳤶�*/
#define CW_LOCATION_URL_DATA_LEN 1024
/*URL, ע�����ǲ���Ҫ��"/"��*/
#define CW_LOCATION_URL_DATA "http://www.hao123.com"
/*IP*/
#define CW_LOCATION_PORT 8080
/* ����ip*/
#define CW_LOCATION_URL_IP_MAX 10

#define CLOUD_WLAN_WHITE_LIST_MAX_U 50

struct sta_info{
	struct sta_info *next;
	u8 macaddr[6];
};

enum nl_tpye
{
/*����debug���鿴�ں˵Ļ�����Ϣ*/
	CW_NLMSG_DEBUG_SHOW_ONLINE_USER,
	CW_NLMSG_DEBUG_SHOW_WHITE_LIST,
	CW_NLMSG_DEBUG_SHOW_PORTAL,
	CW_NLMSG_PUT_ONLINE_INFO_TO_AC,	//�ϱ����������û���Ϣ
	CW_NLMSG_GET_TEST,					//����ǲ����õ�
	
	CW_NLMSG_AP_DEBUG_MAX,

/****************************************/
	
/*apac�����õ���һЩ״̬��*/
	CW_NLMSG_RES_OK	,					//�ظ�ok
	CW_NLMSG_RES_FAIL ,					//�ظ�FAIL
	
	CW_NLMSG_POBLIC_MAX,

/****************************************/

/*ap��ac֮��ͨ������*/

	CW_NLMSG_SET_OFF,					//ȫ�ֿ���
	CW_NLMSG_SET_ON	,				
	CW_NLMSG_SET_DEBUG_OFF,				//ȫ�ֵ��Կ���
	CW_NLMSG_SET_DEBUG_ON,
	
	CW_NLMSG_UPDATE_PORTAL,			//����portal���ĵ�localtion����
	CW_NLMSG_UPDATE_WHITE_LIST,			//ȫ�ֵ�Ŀ�ĵ�ַ������
	CW_NLMSG_UPDATE_SESSION_CFG,			//ȫ�ֵĻỰ��������
	CW_NLMSG_SET_KLOG_OFF,		//ȫ����־��Ϣ����
	CW_NLMSG_SET_KLOG_ON,
	CW_NLMSG_PUT_KLOG_INFO,
	
	CW_NLMSG_SET_REBOOT,		// ����ap
	CW_NLMSG_SET_WAN_PPPOE,		//����ap wan�ӿ�Ϊpppoe����ģʽ		20
	CW_NLMSG_SET_WAN_DHCP,		//����ap wan�ӿ�Ϊdhcp ģʽ
	CW_NLMSG_SET_WIFI_INFO,		//����ap wifi��Ϣ15

/*< ��ʱ���õ���ID*/
	CW_NLMSG_SET_USER_PID,		//����һ��ȫ�ֵ��û�̫pid
	CW_NLMSG_GET_AP_CARD_MODE,	//��AP��Ƶ˫Ƶģʽ֪ͨ��kmod
	CW_NLMSG_SET_DEV_IP,			//���豸����IP��ַ֪ͨ��kmod	25
	CW_NLMSG_GET_DEV_MAC,			//���豸mac��ַ֪ͨ��kmod
	CW_NLMSG_GET_SLAVE_MAC,			//��mac��ַ֪ͨ��kmod
	CW_NLMSG_GET_AC_IP,			//��discover����AC��IP�·�
	CW_NLMSG_GET_AC_MAC,			//��discover����AC��MAC�·�
	CW_NLMSG_GET_AC_PORT,			//������ת��AC��port�·�		30
	CW_NLMSG_SET_TEMPLATEID_1,			//����һ�����̵�ģ��ID�����ں�
	CW_NLMSG_SET_TEMPLATEID_2,			//���ڶ������̵�ģ��ID�����ں�
	CW_NLMSG_RECORD_USER_IP,			//�ϱ���⵽���û�IP
	CW_NLMSG_RECORD_DHCP_OPTION_43,			//�ϱ�DHCP�е�option43��Ϣ
	CW_NLMSG_SET_WAN_IFNAME,		//�û����֪�ں�̬,��ǰwan�����ýӿ�		35
	
/****************************************/

	CW_NLMSG_HEART_BEAT, //���б���
	CW_NLMSG_SET_HEART_BEAT_INTERVAL, //���б��ķ��ͼ��
	
	CW_NLMSG_AP_MAX,

/****************************************/

/*ac��web֮���ͨ������ӿ�ʼ*/

	CW_NLMSG_WEB_SET_AP_CONFIG,
	CW_NLMSG_WEB_GET_AP_INFO,
	CW_NLMSG_PUT_ONLINE_INFO_TO_WEB, //�ϱ����������û���Ϣ��web
	CW_NLMSG_WEB_ADD_AP_NODE,
	CW_NLMSG_WEB_DEL_AP_NODE,
	CW_NLMSG_WEB_AP_OPEN_AUTH,
	CW_NLMSG_WEB_AP_ADMIN_AUTH,

/*ko��capwapdata֮�佻��*/
	CW_NLMSG_ADD_CONNECT_STA,
	CW_NLMSG_DEL_CONNECT_STA,
	CW_NLMSG_UP_DTA_PACKAGE,
	CW_NLMSG_AC_MAX
};

enum flow_session_status
{
	CW_FS_UP,		//����״̬
	CW_FS_DOWN,		//����״̬
	CW_FS_MAX
};


enum klog_mode
{
	REAL_TIME,
	UNREAL_TIME
};

enum klog_type
{
	KLOG_URL,
	KLOG_MAX
};

typedef struct dns_white_list
{
	u32 number;
	u32 list[CW_WHITE_LIST_MAX];
}dns_white_list_t;

typedef struct dns_protal_url
{
	u32 data_len;
	s8 data[];
}dns_protal_url_t;

/*url ���˵�ַ�ṹ*/
typedef struct ac_udp_white_list
{
	u32 id;
	u32 len;	//ֻ�Ǳ��ṹ�����ݵ�data����
	u8 *data;	//�ַ���Ҫ��\0�ṹ����
}ac_udp_white_list_t;

typedef struct cwlan_flow_session_cfg
{
	u32 over_time;				//��㳬ʱʱ�䣬����Ϊ��λ
	u32 interval_timer;		//��ʱ��ִ�м��ʱ�䣬����Ϊ��λ
	u32 flow_max;		//�������������ֽڼ�
	u32 del_time;		//�û�ɾ�����ʱ��
}cwlan_flow_session_cfg_t;


typedef struct reHttp
{
	u32 destIp[CW_LOCATION_URL_IP_MAX];	//�ض���ָ��Ŀ�ĵ�ַ
	u16 destPort;	//�ض���ָ���Ķ˿ں�
	s8 Location[CW_LOCATION_URL_DATA_LEN];	//�ض���ָ����URL
}reHttp_t;

typedef struct pppoe_cfg
{
	s8 username[64];
	s8 password[64];
}pppoe_cfg_t;


enum encryption_type
{
	EN_NONE,
	EN_WEP_OPEN,
	EN_WEP_SHARE,
	EN_WAP_PSK,
	EN_WAP2_PSK,
	EN_WAP_MIX,
	EN_MAX
};
enum arithmetic_type
{
	ALG_CCMP,
	ALG_TKIP,
	ALG_MIX,
	ALG_MAX
};
typedef struct encryption_cfg_info
{
	u8 arithmetic;
	u8 key_len;
	u8 key[128];//������������
}encryption_cfg_info_t;

typedef struct wifi
{
	u8 wlan_id;
	u8 disabled;//������
	u8 txpower;    //���ù���Ϊ17dbm ̫�߻�������ģ��
	u8 channel;	  //���������ŵ�Ϊ6
	//s8 mode;    //��������ģʽΪap
	u8 ssid_len;
	u8 ssid[128];    //��������SSID
	u8 en_type;    //���ü���ΪWPA2-PSK
	encryption_cfg_info_t en_info;
}wifi_cfg_t;


typedef struct ap_local_info 
{
	u8 apmac[6];
	u32 mem_total; // ��λ��K
	u32 mem_free;
	u32 cpu_idle_rate;
	u64 run_time;	//��λ���룬������Ŀǰ�����˶��
}ap_local_info_t;

typedef struct online_user_info
{
	u32 userip;
	u8 usermac[6];
	u8 apmac[6];
	u32 status;
	u64 time;	//�����ߵ�ǰʱ��
}online_user_info_t;

/*��������ͨ�Žṹ*/
typedef struct kmod_log_info
{
	u32 size;
	u32 type;
	u32 userip;
	u8 usermac[6];
	u8 apmac[6];
	u64 time;
	u8 data[];
}kmod_log_info_t;

/*��������ͨ�Žṹ*/
typedef struct dcma_udp_info
{
	u32 type;	//��������
	u32 number;	//data ����
	u8 data[];	
}dcma_udp_skb_info_t;

#endif

