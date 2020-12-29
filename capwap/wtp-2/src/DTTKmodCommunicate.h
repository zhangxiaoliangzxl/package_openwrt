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

#define NETLINK_CWLAN		29	/*netlink　编号，最大为32*/
/** 最大数据负荷(固定) **/  
#define MAX_DATA_PAYLOAD 1800
/** 最大协议负荷(固定) **/  
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
/*本地debug　查看内核的基本信息*/
	CW_NLMSG_DEBUG_SHOW_ONLINE_USER,
	CW_NLMSG_DEBUG_SHOW_WHITE_LIST,
	CW_NLMSG_DEBUG_SHOW_PORTAL,
	CW_NLMSG_PUT_ONLINE_INFO_TO_AC,	//上报本地在线用户信息
	CW_NLMSG_GET_TEST,					//这个是测试用的
	
	CW_NLMSG_AP_DEBUG_MAX,

/****************************************/
	
/*apac公共用到的一些状态码*/
	CW_NLMSG_RES_OK	,					//回复ok
	CW_NLMSG_RES_FAIL ,					//回复FAIL
	
	CW_NLMSG_POBLIC_MAX,

/****************************************/

/*ap与ac之间通信命令*/

	CW_NLMSG_SET_OFF,					//全局开关
	CW_NLMSG_SET_ON	,					//10
	CW_NLMSG_SET_DEBUG_OFF,				//全局调试开关
	CW_NLMSG_SET_DEBUG_ON,
	
	CW_NLMSG_UPDATE_PORTAL,			//设置portal报文的localtion内容
	CW_NLMSG_UPDATE_WHITE_LIST,			//全局的目的地址白名单
	CW_NLMSG_UPDATE_SESSION_CFG,			//全局的会话基础配置
	CW_NLMSG_SET_KLOG_OFF,		//全局日志信息开关
	CW_NLMSG_SET_KLOG_ON,
	CW_NLMSG_PUT_KLOG_INFO,
	
	CW_NLMSG_SET_REBOOT,		// 重新ap
	CW_NLMSG_SET_WAN_PPPOE,		//设置ap wan接口为pppoe拨号模式  20
	CW_NLMSG_SET_WAN_DHCP,		//设置ap wan接口为dhcp 模式
	CW_NLMSG_SET_WIFI_INFO,		//设置ap wifi信息

/*< 暂时仅用到的ID*/
	CW_NLMSG_SET_USER_PID,		//设置一个全局的用户太pid
	CW_NLMSG_SET_AP_CARD_MODE,	//将AP单频双频模式通知给kmod
	CW_NLMSG_SET_DEV_IP,			//将设备自身IP地址通知给kmod  25
	CW_NLMSG_SET_DEV_MAC,			//将设备自身mac地址通知给kmod
	CW_NLMSG_SET_SLAVE_MAC,			//将mac地址通知给kmod
	CW_NLMSG_SET_AC_IP,			//将discover到的AC的IP下发
	CW_NLMSG_SET_AC_MAC,			//将discover到的AC的MAC下发
	CW_NLMSG_SET_AC_PORT,			//将集中转发AC的port下发  30
	CW_NLMSG_SET_TEMPLATEID_1,			//将第一个进程的模板ID发给内核
	CW_NLMSG_SET_TEMPLATEID_2,			//将第二个进程的模板ID发给内核
	CW_NLMSG_RECORD_USER_IP,			//上报检测到的用户IP
	CW_NLMSG_RECORD_DHCP_OPTION_43,		//接收由kmod上报的dhcp的option43信息
	CW_NLMSG_SET_WAN_IFNAME,		//用户层告知内核态,当前wan口配置接口  35

	CW_NLMSG_HEART_BEAT, //心中报文
	CW_NLMSG_SET_HEART_BEAT_INTERVAL, //心中报文发送间隔
	
	CW_NLMSG_AP_MAX,

/****************************************/

/*ac与web之间的通信命令从开始*/

	CW_NLMSG_WEB_SET_AP_CONFIG,
	CW_NLMSG_WEB_GET_AP_INFO,
	CW_NLMSG_PUT_ONLINE_INFO_TO_WEB, //上报本地在线用户信息到web
	CW_NLMSG_WEB_ADD_AP_NODE,
	CW_NLMSG_WEB_DEL_AP_NODE,
	CW_NLMSG_WEB_AP_OPEN_AUTH,
	CW_NLMSG_WEB_AP_ADMIN_AUTH,
	
/*ko与capwapdata之间交互*/
	CW_NLMSG_ADD_CONNECT_STA,
	CW_NLMSG_DEL_CONNECT_STA,
	CW_NLMSG_UP_DTA_PACKAGE,

	CW_NLMSG_AC_MAX
};

/*所有数据通信结构*/
typedef struct dcma_udp_info
{
	u32 type;	//命令类型
	u32 number;	//data 个数
	u32 length;	//data 个数
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
/*< option43结构*/
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

/*< 与kmod间初始化*/
s32 kmod_communicate_init(char *devmac);
/*< 发送数据到kmod*/
s32 sendto_kmod(s32 type, s8 *buff, u32 datalen);
/*< 接收kmod数据线程，主要负责用户IP采集*/
s32 dtt_dispose_pthread_init(void);


#endif/*DTTKMODECOM_H*/
