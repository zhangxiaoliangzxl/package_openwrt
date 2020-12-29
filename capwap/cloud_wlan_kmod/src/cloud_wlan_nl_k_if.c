#include <linux/version.h>
#include <linux/module.h>  
#include <linux/netlink.h>  
#include <net/netlink.h>  
#include <net/net_namespace.h>  
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/inet.h>

//#include "cloud_wlan_types.h"
#include "cloud_wlan_nl.h"

#include "cloud_wlan_main.h"
#include "cloud_wlan_session.h"
#include "cloud_wlan_http_pub.h"
#include "cloud_wlan_log.h"
#include "cloud_wlan_nl_u_if.h"

static struct sock *sk; //内核端socket  
extern dns_white_list_t g_cloud_wlan_white_list;

struct sta_info *g_sta_list = NULL;
struct timer_list g_update_wlan_mac_timer; 
u32 g_wlanMac_update_interval = 3;

struct net_device *wlan_dev;

struct net_device *getWlanDev(void)
{
	return wlan_dev;
}

struct sta_info *getStaList(void)
{
	return g_sta_list;
}
/*通信示例函数*/
static void cloud_wlan_nl_get_test(struct nlmsghdr *nlh)
{
    void *payload;  
    struct sk_buff *out_skb;  
    void *out_payload;  
    struct nlmsghdr *out_nlh;  
    int payload_len; // with padding, but ok for echo   
    

	payload = nlmsg_data(nlh);	
	payload_len = nlmsg_len(nlh);  
	printk("payload_len = %d\n", payload_len);  
	printk("Recievid: %s, From: %d\n", (char *)payload, nlh->nlmsg_pid);	

	
	out_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL); //分配足以存放默认大小的sk_buff  
	if (!out_skb)
		goto failure;  
	//skb, pid, seq, type, len
	out_nlh = nlmsg_put(out_skb, 0, 0, CW_NLMSG_RES_OK, MAX_DATA_PAYLOAD, 0); //填充协议头数据  
	if (!out_nlh)
		goto failure;  
	out_payload = nlmsg_data(out_nlh);	
	// 在响应中加入字符串，以示区别  
	snprintf(out_payload, MAX_DATA_PAYLOAD, "[kernel res info]: GETPID[%d] TYPE [%2X] OK\n", nlh->nlmsg_pid, nlh->nlmsg_type);
	nlmsg_unicast(sk, out_skb, nlh->nlmsg_pid); 
	return;
failure:  
	printk(" failed in fun dataready!\n");  
}
u32 cloud_wlan_nl_debug_off(void)
{

	g_cloud_wlan_debug= 0;
	printk(" ap cloud mode debug close ok\n");
	return CWLAN_OK;
}
u32 cloud_wlan_nl_debug_on(void)
{

	g_cloud_wlan_debug= -1;
	printk(" ap cloud mode debug open ok\n");
	return CWLAN_OK;
}
u32 cloud_wlan_nl_cw_off(void)
{

	printk(" ap cloud mode close ok\n");
	return CWLAN_OK;
}
u32 cloud_wlan_nl_cw_on(void)
{

	printk(" ap cloud mode open ok\n");
	return CWLAN_OK;
}

u32 cloud_wlan_nl_klog_off(void)
{
	g_cloud_wlan_klog_switch= 0;
	printk(" ap klog mode close ok\n");
	return CWLAN_OK;
}
u32 cloud_wlan_nl_klog_on(void)
{

	g_cloud_wlan_klog_switch= -1;
	printk(" ap klog mode open ok\n");
	return CWLAN_OK;
}
u32 cloud_wlan_nl_cw_update_white_list(dns_white_list_t *buf)
{
	u32 i;	
	memcpy(&g_cloud_wlan_white_list, buf, sizeof(g_cloud_wlan_white_list));

	printk(" ap cloud mode update_white_list ok:\n");
	for(i=0; i<g_cloud_wlan_white_list.number; i++)
	{
		printk("[%d] [%x]\n", i, g_cloud_wlan_white_list.list[i]);
	}
	return CWLAN_OK;
}
u32 cloud_wlan_nl_cw_update_portal_url(s8 *buf)
{
	u32 i;
	memcpy((void *)&g_portal_config.rehttp_conf, (void *)buf, sizeof(reHttp_t));
	
	printk(" ap cloud mode update_portal_info:\n\n %s\n",g_portal_config.rehttp_conf.Location);
	for(i=0; i<CW_LOCATION_URL_IP_MAX; i++)
	{
		printk("[%d] [%x]\n", i, g_portal_config.rehttp_conf.destIp[i]);
	}
	return CWLAN_OK;
}
u32 cloud_wlan_nl_cw_update_session_cfg(s8 *buf)
{
	memcpy((void *)&g_cw_fs_cfg, (void *)buf, sizeof(g_cw_fs_cfg));
	
	printk(" ap cloud mode update_portal_session_cfg ok:\n\n");
	printk(" over_time     : %d\n",g_cw_fs_cfg.over_time);
	printk(" interval_timer: %d\n",g_cw_fs_cfg.interval_timer);
	printk(" del_time      : %d\n",g_cw_fs_cfg.del_time);

	return CWLAN_OK;
}

u32 cloud_wlan_nl_cw_show_white_list(void)
{
	u32 i;
	printk(" ap cloud mode white_list info:\n");
	for(i=0; i<g_cloud_wlan_white_list.number; i++)
	{
		printk("[%d] [%x]\n", i, g_cloud_wlan_white_list.list[i]);
	}
	return CWLAN_OK;
}
u32 cloud_wlan_nl_cw_show_online_user(void)
{
	flow_session_show_online_list();
	return CWLAN_OK;
}
u32 cloud_wlan_nl_cw_show_portal_url(void)
{
	u32 i;
	printk(" ap cloud mode portal_url url info:\n %s\n",g_portal_config.rehttp_conf.Location);
	
	printk(" ap cloud mode portal_url ip info:\n");
	for(i=0; i<CW_LOCATION_URL_IP_MAX; i++)
	{
		printk("[%d] [%x]\n", i, g_portal_config.rehttp_conf.destIp[i]);
	}
	return CWLAN_OK;
}

int findStaFromStalist(u8 *addr)
{
	struct sta_info *psta = g_sta_list;
	while(psta)
	{
		if(!memcmp(psta->macaddr, addr, 6))
		{
			return 1;
//			printk("macaddr ##%02x:%02x:%02x:%02x:%02x:%02x#\n",psta->macaddr[0], psta->macaddr[1], psta->macaddr[2], psta->macaddr[3], psta->macaddr[4], psta->macaddr[5]);
			break;
		}
		psta = psta->next;
	}
	return 0;
}

static void add_station(u8 *addr)
{
	struct sta_info *statmp;
	printk("111111111add_station: ##%02x:%02x:%02x:%02x:%02x:%02x#\n",addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	statmp = (struct sta_info *)kmalloc(sizeof(struct sta_info), GFP_KERNEL);
	memset(statmp, 0, sizeof(struct sta_info));

	memcpy(statmp->macaddr, addr, 6);
	statmp->next = g_sta_list;
	g_sta_list = statmp;
#if 0
	statmp = g_sta_list;
	while(statmp)
	{
		printk("station: ##%02x:%02x:%02x:%02x:%02x:%02x#\n",statmp->macaddr[0], statmp->macaddr[1], statmp->macaddr[2], statmp->macaddr[3], statmp->macaddr[4], statmp->macaddr[5]);
		statmp = statmp->next;
	}
#endif
}
static void del_station(u8 *addr)
{
	struct sta_info *psta = g_sta_list;
	struct sta_info *statmp = NULL;
	if(!psta)
		return;
	printk("111111111del_station: ##%02x:%02x:%02x:%02x:%02x:%02x#\n",addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	if(!memcmp(g_sta_list->macaddr, addr, 6))
	{
		statmp = g_sta_list;
		g_sta_list = g_sta_list->next;
		kfree(statmp);
		statmp = NULL;
	}
	while(psta)
	{
		if(psta->next && !memcmp(psta->next->macaddr, addr, 6))
		{
			statmp = psta->next;
			psta->next = psta->next->next;
			
			kfree(statmp);
			statmp = NULL;
			return;
		}
		psta = psta->next;
	}
#if 0
	statmp = g_sta_list;
	while(statmp)
	{
		printk("station: ##%02x:%02x:%02x:%02x:%02x:%02x#\n",statmp->macaddr[0], statmp->macaddr[1], statmp->macaddr[2], statmp->macaddr[3], statmp->macaddr[4], statmp->macaddr[5]);
		statmp = statmp->next;
	}
#endif
}


/*
	 内核与用户太通信控制命令总的分之函数，
	 不要在这个函数里边直接添加业务功能，
	 使用switch 分支结构去添加命令和接口函数。
*/
static void cloud_wlan_nl_console_branch(struct sk_buff *skb)  
{  
    struct nlmsghdr *nlh;  
	unsigned char IP[32] = {0};

    nlh = nlmsg_hdr(skb);  
	if(nlh->nlmsg_len - NLMSG_HDRLEN != 1800)
		return;
    switch(nlh->nlmsg_type)  
    {  
        case CW_NLMSG_RES_OK:  
            break;  
        case CW_NLMSG_GET_TEST:  
			cloud_wlan_nl_get_test(nlh);
            break;
		case CW_NLMSG_SET_USER_PID:
			g_cloud_wlan_nlmsg_pid = *(u32 *)nlmsg_data(nlh);
			printk("########WTP pid = %d\n", g_cloud_wlan_nlmsg_pid);
			if(g_option43_flag){
				cloud_wlan_sendto_umod(CW_NLMSG_RECORD_DHCP_OPTION_43, (uint8_t *)&g_option43_info, sizeof(option43_cfg));
			}
			break;
		case CW_NLMSG_SET_WAN_IFNAME:
			memset(APWanIfname, 0, 16);
			memcpy(APWanIfname, (u8 *)nlmsg_data(nlh), 16);
			printk("#######AP wan is %s\n", APWanIfname);
			break;
		case CW_NLMSG_SET_DEV_IP:
			memcpy(IP, (u8 *)nlmsg_data(nlh), sizeof(IP));
			APAddr = in_aton(IP);
			break;
		case CW_NLMSG_GET_DEV_MAC:
//			memcpy(APMac, (u8 *)nlmsg_data(nlh), 6);
//			printk("ap mac: ##%02x:%02x:%02x:%02x:%02x:%02x#\n",APMac[0], APMac[1], APMac[2], APMac[3], APMac[4], APMac[5]);
			break;
		case CW_NLMSG_GET_AC_IP:
			memcpy(IP, (u8 *)nlmsg_data(nlh), sizeof(IP));
			ACAddr = in_aton(IP);
			break;
		case CW_NLMSG_GET_AC_MAC:
			memcpy(ACMAC, (u8 *)nlmsg_data(nlh), sizeof(ACMAC));
//			printk("get ac mac: ##%02x:%02x:%02x:%02x:%02x:%02x#\n",ACMAC[0], ACMAC[1], ACMAC[2], ACMAC[3], ACMAC[4], ACMAC[5]);
			break;
		case CW_NLMSG_GET_AC_PORT:
			ACPort = *(u32 *)nlmsg_data(nlh);
			break;
		case CW_NLMSG_SET_TEMPLATEID_1:
			gTemplateID_1 = *(u32 *)nlmsg_data(nlh);
			printk("############gTemplateID 1=%d\n", gTemplateID_1);
			break;
		case CW_NLMSG_SET_TEMPLATEID_2:
			gTemplateID_2 = *(u32 *)nlmsg_data(nlh);
			printk("############gTemplateID 2=%d\n", gTemplateID_2);
			break;
#if 0
		case CW_NLMSG_SET_OFF:
			cloud_wlan_nl_cw_off();
			break;
		case CW_NLMSG_SET_ON:
			cloud_wlan_nl_cw_on();
			break;
		case CW_NLMSG_SET_KLOG_OFF:
			cloud_wlan_nl_klog_off();
			break;
		case CW_NLMSG_SET_KLOG_ON:
			cloud_wlan_nl_klog_on();
			break;
		case CW_NLMSG_UPDATE_WHITE_LIST:
			cloud_wlan_nl_cw_update_white_list((dns_white_list_t *)nlmsg_data(nlh));
			break;
		case CW_NLMSG_UPDATE_PORTAL:
			cloud_wlan_nl_cw_update_portal_url((s8 *)nlmsg_data(nlh));
			break;
		case CW_NLMSG_UPDATE_SESSION_CFG:
			cloud_wlan_nl_cw_update_session_cfg((s8 *)nlmsg_data(nlh));
			break;
		case CW_NLMSG_DEBUG_SHOW_WHITE_LIST:
			cloud_wlan_nl_cw_show_white_list();
			break;
		case CW_NLMSG_DEBUG_SHOW_ONLINE_USER:
			cloud_wlan_nl_cw_show_online_user();
			break;
		case CW_NLMSG_DEBUG_SHOW_PORTAL:
			cloud_wlan_nl_cw_show_portal_url();
			break;
		case CW_NLMSG_ADD_CONNECT_STA:
//			add_station((u8 *)nlmsg_data(nlh));
			break;
		case CW_NLMSG_DEL_CONNECT_STA:
			del_station((u8 *)nlmsg_data(nlh));
			break;
#endif
        default:  
            CLOUD_WLAN_DEBUG("Unknow msgtype recieved! [%2x]\n", nlh->nlmsg_type);
			break;
    }  
    return;  
}  
  
u32 cloud_wlan_nl_init(void)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,3,8)
    struct netlink_kernel_cfg nlcfg = {  
        .input = cloud_wlan_nl_console_branch,  
    };  
    sk = netlink_kernel_create(&init_net, NETLINK_CWLAN, &nlcfg);  
#else
    sk = netlink_kernel_create(&init_net, NETLINK_CWLAN, 0, cloud_wlan_nl_console_branch, NULL, THIS_MODULE);  
#endif
    if (sk == NULL) {  
		CLOUD_WLAN_DEBUG("cw init netlink_kernel_create fail\n");
		return CWLAN_FAIL;
    } 
	
	printk("cw init netlink_kernel_create ok...\n");
    return CWLAN_OK;  

}
u32 cloud_wlan_nl_exit(void)
{
    netlink_kernel_release(sk); 
	
	printk("cw exit netlink_kernel_create ok\n");
	return CWLAN_OK;
}
s32 cloud_wlan_sendto_umod(s32 type, s8 *buff, u32 datalen)
{
	struct sk_buff *out_skb;  
	void *out_payload;	
	struct nlmsghdr *out_nlh;  	

	out_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL); //分配足以存放默认大小的sk_buff  
	if (!out_skb)
		goto failure;  
	//skb, pid, seq, type, len
	out_nlh = nlmsg_put(out_skb, 0, 0, type, datalen, 0); //填充协议头数据  
	if (!out_nlh)
		goto failure;  
	
	out_payload = nlmsg_data(out_nlh);	
	// 在响应中加入字符串，以示区别  
	memcpy(out_payload, buff,datalen);
	if (sk != NULL){
		nlmsg_unicast(sk, out_skb, g_cloud_wlan_nlmsg_pid); 
	}
	return CWLAN_OK;
failure:  
	printk(" failed in fun dataready!\n");	
	return CWLAN_OK;
}

void wlanMacUpdateHandle(void)
{
//	printk("time overout####################\n");
	
	wlan_dev = dev_get_by_name(&init_net, "ath0");
	
//	printk("dev_addr is [%2x][%2x][%2x][%2x][%2x][%2x]#\n", wlan_dev->dev_addr[0], wlan_dev->dev_addr[1], wlan_dev->dev_addr[2], wlan_dev->dev_addr[3], wlan_dev->dev_addr[4],wlan_dev->dev_addr[5]);
	mod_timer( &(g_update_wlan_mac_timer),(jiffies + g_wlanMac_update_interval*HZ) );
}


void wlan_mac_update_init(void)
{
	init_timer(&(g_update_wlan_mac_timer));
	g_update_wlan_mac_timer.function = wlanMacUpdateHandle;
	g_update_wlan_mac_timer.data = 0;
	g_update_wlan_mac_timer.expires = jiffies + g_wlanMac_update_interval*HZ;
	add_timer( &(g_update_wlan_mac_timer) );

	printk("cw init g_flow_ageing_timer ok\n");

	return;
}

void wlan_mac_update_exit(void)
{
	del_timer( &(g_update_wlan_mac_timer) );
	printk("cw exit wlan mac update timer ok\n");

	return;
}

