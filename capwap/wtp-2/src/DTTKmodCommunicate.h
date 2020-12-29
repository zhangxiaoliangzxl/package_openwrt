#ifndef DTTKMODECOM_H
#define DTTKMODECOM_H

#include <stdlib.h>  
#include <stdio.h>  
#include <unistd.h>  
#include <linux/netlink.h>  
#include <sys/socket.h>  
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <errno.h>
#include <asm/types.h>

#include "CWCommon.h"


#define CW_OK 0
#define CW_FAIL -1

#define NETLINK_CWLAN		29	/*netlink����ţ����Ϊ32*/
/** ������ݸ���(�̶�) **/  
#define MAX_DATA_PAYLOAD 1800
/** ���Э�鸺��(�̶�) **/  
#define MAX_PROTOCOL_LPAYLOAD (MAX_DATA_PAYLOAD + 8)

#define DHCP_OPTION_43_IP_COUNT		4

typedef unsigned char		u8;
typedef unsigned short		u16;
typedef unsigned int		u32;
typedef unsigned long long	u64;
typedef char		s8;
typedef short			s16;
typedef int			s32;
typedef long long		s64;

extern CWThreadCondition	gDhcpOption43Wait;

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
	CW_NLMSG_SET_ON	,					//10
	CW_NLMSG_SET_DEBUG_OFF,				//ȫ�ֵ��Կ���
	CW_NLMSG_SET_DEBUG_ON,
	
	CW_NLMSG_UPDATE_PORTAL,			//����portal���ĵ�localtion����
	CW_NLMSG_UPDATE_WHITE_LIST,			//ȫ�ֵ�Ŀ�ĵ�ַ������
	CW_NLMSG_UPDATE_SESSION_CFG,			//ȫ�ֵĻỰ��������
	CW_NLMSG_SET_KLOG_OFF,		//ȫ����־��Ϣ����
	CW_NLMSG_SET_KLOG_ON,
	CW_NLMSG_PUT_KLOG_INFO,
	
	CW_NLMSG_SET_REBOOT,		// ����ap
	CW_NLMSG_SET_WAN_PPPOE,		//����ap wan�ӿ�Ϊpppoe����ģʽ  20
	CW_NLMSG_SET_WAN_DHCP,		//����ap wan�ӿ�Ϊdhcp ģʽ
	CW_NLMSG_SET_WIFI_INFO,		//����ap wifi��Ϣ

/*< ��ʱ���õ���ID*/
	CW_NLMSG_SET_USER_PID,		//����һ��ȫ�ֵ��û�̫pid
	CW_NLMSG_SET_AP_CARD_MODE,	//��AP��Ƶ˫Ƶģʽ֪ͨ��kmod
	CW_NLMSG_SET_DEV_IP,			//���豸����IP��ַ֪ͨ��kmod  25
	CW_NLMSG_SET_DEV_MAC,			//���豸����mac��ַ֪ͨ��kmod
	CW_NLMSG_SET_SLAVE_MAC,			//��mac��ַ֪ͨ��kmod
	CW_NLMSG_SET_AC_IP,			//��discover����AC��IP�·�
	CW_NLMSG_SET_AC_MAC,			//��discover����AC��MAC�·�
	CW_NLMSG_SET_AC_PORT,			//������ת��AC��port�·�  30
	CW_NLMSG_SET_TEMPLATEID_1,			//����һ�����̵�ģ��ID�����ں�
	CW_NLMSG_SET_TEMPLATEID_2,			//���ڶ������̵�ģ��ID�����ں�
	CW_NLMSG_RECORD_USER_IP,			//�ϱ���⵽���û�IP
	CW_NLMSG_RECORD_DHCP_OPTION_43,		//������kmod�ϱ���dhcp��option43��Ϣ
	CW_NLMSG_SET_WAN_IFNAME,		//�û����֪�ں�̬,��ǰwan�����ýӿ�  35

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

/*��������ͨ�Žṹ*/
typedef struct dcma_udp_info
{
	u32 type;	//��������
	u32 number;	//data ����
	u32 length;	//data ����
	u8 data[];	
}dcma_udp_skb_info_t;

typedef struct cw_nl_info
{
	s32 sockfd;  
	struct nlmsghdr *nlh;  
	struct sockaddr_nl src_addr;
	struct sockaddr_nl dst_addr;	
	struct msghdr msg;
}cw_nl_info_t;

struct pthread_id
{
	pthread_t recv_kmod_id;
};
/*< option43�ṹ*/
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

/*< ��kmod���ʼ��*/
s32 kmod_communicate_init(char *devmac);
/*< �������ݵ�kmod*/
s32 sendto_kmod(s32 type, s8 *buff, u32 datalen);
/*< ����kmod�����̣߳���Ҫ�����û�IP�ɼ�*/
s32 dtt_dispose_pthread_init(void);


#endif/*DTTKMODECOM_H*/
