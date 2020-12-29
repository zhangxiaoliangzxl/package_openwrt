#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if.h>
#include <linux/socket.h>

#include <net/arp.h>
#include <net/sock.h>

#include <linux/net.h>

#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/string.h>
#include <linux/sysctl.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <asm/checksum.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <net/net_namespace.h>
#include <net/route.h>
#include <linux/route.h>
#include <linux/stddef.h>
#include <linux/mutex.h>
#include <linux/inet.h>
#include <linux/time.h>
#include <linux/vmalloc.h>
#include <linux/jhash.h>
#include <linux/tcp.h>
#include <linux/etherdevice.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <asm/bitops.h>

//#include "cloud_wlan_types.h"
#include "cloud_wlan_nl.h"

#include "cloud_wlan_main.h"
#include "cloud_wlan_session.h"
#include "cloud_wlan_http_pub.h"
#include "cloud_wlan_log.h"
#include "cloud_wlan_ebtable.h"
#include "cloud_wlan_nl_u_if.h"

u32 g_cloud_wlan_debug = 0;
u32 g_cloud_wlan_nlmsg_pid = 0;
u32 g_option43_flag = 0;
option43_cfg g_option43_info;

/*< AP以及AC的IP、MAC地址等信息*/
u8 APWanIfname[16] = {0};
u8 APMac[6] = {0};
u32 ACAddr = 0;
u32 APAddr = 0;
u8 ACMAC[6] = {0};
u32 ACPort = 0;
/*< 第一张网卡的模板ID*/
int gTemplateID_1 = -1;
/*< 第二张网卡的模板ID*/
int gTemplateID_2 = -1;
/*****************************/

dns_white_list_t g_cloud_wlan_white_list={0,{0}};

#define USE_IMMEDIATE

/* IP Hooks */
/* After promisc drops, checksum checks. */
#define NF_IP_PRE_ROUTING	0
/* If the packet is destined for this box. */
#define NF_IP_LOCAL_IN		1
/* If the packet is destined for another interface. */
#define NF_IP_FORWARD		2
/* Packets coming from a local process. */
#define NF_IP_LOCAL_OUT		3
/* Packets about to hit the wire. */
#define NF_IP_POST_ROUTING	4
#define NF_IP_NUMHOOKS		5

/* 用于注册我们的函数的数据结构 */ 
struct nf_hook_ops g_cwlan_in_hook_prer; 
struct nf_hook_ops g_cwlan_out_hook_prer; 

#define IP_PRINTF_FORM "%d.%d.%d.%d"

#define COVER_IP_FORM(ipaddr)	\
	(ipaddr>>24) & 0xff, \
    (ipaddr>>16) & 0xff, \
    (ipaddr>>8) & 0xff, \
    ipaddr & 0xff

static uint32_t wltp_pkt_seq = 0;

void send_udp(u8 *msg, int len, unsigned int mark)  
{  
	struct net_device *odev = NULL;

    struct sk_buff *skb;  
    int total_len, ip_len, udp_len, header_len;  
    struct udphdr *udph;  
    struct iphdr *iph;  
    struct ethhdr *eth;
	int i = 0;

    // 设置各个协议数据长度  
    udp_len = len + sizeof(struct udphdr);  
    ip_len = udp_len + sizeof(*iph);  
    total_len = ip_len + ETH_HLEN;// + NET_IP_ALIGN;  
    header_len = total_len - len;  
  
    // 分配skb  
    skb = alloc_skb(total_len + LL_MAX_HEADER, GFP_ATOMIC | __GFP_ZERO);  //
    if ( !skb ) {  
        printk( "alloc_skb fail.\n" );  
        return;  
    }
    // 预先保留skb的协议首部长度大小  
    skb_reserve(skb, header_len);  
  
    // 拷贝负载数据  
    skb_copy_to_linear_data(skb, msg, len);  
    skb->len += len;  
  
    // skb->data 移动到udp首部  
    udph = (struct udphdr *)skb_push(skb, sizeof(struct udphdr));    
    udph->source = htons(7070);  
    udph->dest = htons(6969);  
    udph->len = htons(udp_len);  

    skb_reset_transport_header(skb); 

    // skb->data 移动到ip首部  
    iph = (struct iphdr *)skb_push(skb, sizeof(struct iphdr));
	iph->ihl	= sizeof(struct iphdr) >> 2;
    iph->version = 4;
    iph->tos      = 0;  
	iph->tot_len    = htons(skb->len);
    iph->id       = 0;  
    iph->frag_off = 0;  
    iph->ttl      = 64;  
    iph->protocol = IPPROTO_UDP;
	iph->saddr	  = APAddr;
	iph->daddr	  = ACAddr;
	ip_send_check(iph);
    skb_reset_network_header(skb);   

    // skb->data 移动到eth首部 
    eth = (struct ethhdr *)skb_push(skb, sizeof(struct ethhdr)); 
	skb->protocol = eth->h_proto = htons(ETH_P_IP);
//	eth->h_dest[0] = 0x3c;eth->h_dest[1] = 0x46;eth->h_dest[2] = 0xd8;eth->h_dest[3] = 0x6b;eth->h_dest[4] = 0xda;eth->h_dest[5] = 0xf6;
	memcpy(eth->h_dest, ACMAC, 6);
//	eth->h_dest[0] = 0x0;eth->h_dest[1] = 0x14;eth->h_dest[2] = 0xd5;eth->h_dest[3] = 0x80;eth->h_dest[4] = 0x04;eth->h_dest[5] = 0x13;
//	eth->h_source[0] = 0x0;eth->h_source[1] = 0x14;eth->h_source[2] = 0xd5;eth->h_source[3] = 0x11;eth->h_source[4] = 0x11;eth->h_source[5] = 0x11;
	memcpy(eth->h_source, APMac, 6);
    skb_reset_mac_header(skb); 
	
	skb->tail = skb_mac_header(skb)+skb->len;

	udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - iph->ihl * 4, IPPROTO_UDP, skb->csum);
    skb->csum = skb_checksum(skb, iph->ihl * 4, skb->len - iph->ihl * 4, 0);
    
    skb->dev = __dev_get_by_name(&init_net, APWanIfname);
	if(!skb->dev){
		goto free_skb;
	}

	skb->mark = mark;
    // 直接发送  
    dev_queue_xmit(skb);
    return;

free_skb:
    kfree_skb(skb);  
    return ;  
}


u32 cloud_wlan_get_quintuple(struct sk_buff *skb, cloud_wlan_quintuple_s *quintuple_info)
{
	struct iphdr *iphdr;
	//struct tcphdr *tcphdr;

	
	iphdr = ip_hdr(skb);
	//tcphdr = tcp_hdr(skb);

	memcpy(&quintuple_info->eth_hd, eth_hdr(skb), sizeof(struct ethhdr));
	memcpy(&quintuple_info->ip_hd, iphdr, sizeof(struct iphdr));
	//memcpy(&quintuple_info->tcp_hd, tcphdr, tcphdr->doff * 4);

	quintuple_info->skb_data_len = ntohs(iphdr->tot_len);

	
	return CWLAN_OK;
}
/******************************************************************************* 
功能:过滤条件判断
 -------------------------------------------------------------------------------
参数:	pdesc 原报文信息
-------------------------------------------------------------------------------
返回值:	CWLAN_FAIL	
			CWLAN_OK	forwar处理
*******************************************************************************/
u32 cloud_wlan_packet_transparent_forward(struct sk_buff *skb)
{
	//struct ethhdr *ethhdr;
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;

	//struct eth8021hdr *ethhdr_8021;
	/*
	1、cloud wlan 的一个全局开关
		判断下是否为ap到外网报文
	*/

	if(skb == NULL || skb->dev == NULL )
	{
		return CWLAN_OK;
	}
	/*
	ethhdr_8021 = (struct eth8021hdr *)eth_hdr(skb);
	if(ethhdr_8021->ethhdr.h_proto != htons(ETH_P_IP) && ethhdr_8021->ethhdr.h_proto != htons(ETH_P_8021Q))
	{
		CLOUD_WLAN_DEBUG("not ETH_P_IP or ETH_P_8021Q\n");
		return CWLAN_OK;
	}
	
	if(ethhdr_8021->ethhdr.h_proto == htons(ETH_P_8021Q) && ethhdr_8021->proto != htons(ETH_P_IP))
	{
		CLOUD_WLAN_DEBUG("is ETH_P_8021Q but not ETH_P_IP\n");
		return CWLAN_OK;
	}
*/
	if( memcmp("br-lan", skb->dev->name, 6) )
	{
		return CWLAN_OK;
	}
	
	iphdr = ip_hdr(skb);
	tcphdr = tcp_hdr(skb);

	//包过滤目的端口为snmp,dns端口号则报文透传
	/* DNS DHCP CAPWAP SNMP Needs to be forwarded, you can add remove or make a corresponding interface*/
	if( iphdr->protocol == IPPROTO_ICMP )
	{
		return CWLAN_OK;
	}
	switch(ntohs(tcphdr->dest))
	{
		case PROTO_DNS:
		case PROTO_DHCP67:
		case PROTO_DHCP68:
		case PROTO_CAPWAP_C:
		case PROTO_CAPWAP_D:
		case PROTO_SNMP1:
		case PROTO_SNMP2:
		case PROTO_SSH:
		//case PROTO_HTTP:
		//case PROTO_HTTPS:
		//case PROTO_HTTP2:
			return CWLAN_OK;
		default:
			break;
	}

	return CWLAN_FAIL;

}

wltp_fragment_buffer_t wltp_fragment_buffer[WLTP_FRAGMENT_BUFFER_NUM]={0};
/*< 大小端字节序转换*/
static void wltp_head_transfer_nettohost(wltp_header *wltp_head){
	if(wltp_head == NULL)
		return;

	wltp_head->protocol = ntohs(wltp_head->protocol);
	wltp_head->type = ntohs(wltp_head->type);
	wltp_head->seq = ntohl(wltp_head->seq);
	wltp_head->length = ntohs(wltp_head->length);
	wltp_head->fragment = ntohs(wltp_head->fragment);
	wltp_head->rssi = ntohl(wltp_head->rssi);
	wltp_head->vapIndex = wltp_head->vapIndex;
	wltp_head->pad1 = wltp_head->pad1;
	wltp_head->configid = ntohs(wltp_head->configid);
	wltp_head->pad2 = ntohl(wltp_head->pad2);
}

void CWWltpReceivePkt_for_Kmod(wltp_header *wltp_head, char *buf, int buf_leng, int readBytes, wltp_deal_info *wltp_ret)
{
	int writeBytes;
	int i;
	
	int wltp_frgbuf_seq;
	int wltp_frgbuf_seq_1st;
	int wltp_frgbuf_seq_2nd;
	int wltp_frgbuf_cpy_len;
	
//	wltp_header *wltp_head = NULL;
	wltp_header *wltp_head_1st = NULL;
	wltp_header *wltp_head_2nd = NULL;

	
	wltp_fragment_buffer_t *wltp_frgbuf_1st;
	wltp_fragment_buffer_t *wltp_frgbuf_2nd;

//	wltp_head = (wltp_header *)buf;

	memset(wltp_ret, 0, sizeof(wltp_deal_info));
	switch(wltp_head->fragment)
	{
		case FIRST_FRAGMENT_FLAG:
		case SECOND_FRAGMENT_FLAG:
			wltp_frgbuf_seq = wltp_head->seq % WLTP_FRAGMENT_BUFFER_NUM;
			wltp_frgbuf_cpy_len = (readBytes > WLTP_PKT_BUFFER_LENGTH)?WLTP_PKT_BUFFER_LENGTH:readBytes;

			wltp_fragment_buffer[wltp_frgbuf_seq].length = readBytes;
			wltp_fragment_buffer[wltp_frgbuf_seq].buno = RES_BUSY_16 + wltp_frgbuf_seq;
			memcpy(wltp_fragment_buffer[wltp_frgbuf_seq].wltp_pkt_data, buf, wltp_frgbuf_cpy_len);
#if 0
			if(FIRST_FRAGMENT_FLAG == wltp_head->fragment)
				printk("WTP Wltp rcv pkt fm0:seq(%d-hton-%d) leng(%d)!\n", wltp_head->seq, htonl(wltp_head->seq), readBytes);
			else
				printk("WTP Wltp rcv pkt fm1:seq(%d-hton-%d) leng(%d)!\n", wltp_head->seq, htonl(wltp_head->seq), readBytes);
#endif
			break;
		default:
			wltp_ret->ret = WLTP_PKG_NOT_BURST;//非分片WLTP报文
			return;
	}
		
	switch(wltp_head->fragment)
	{
		case FIRST_FRAGMENT_FLAG:
			wltp_frgbuf_seq_1st = wltp_head->seq % WLTP_FRAGMENT_BUFFER_NUM;
			wltp_frgbuf_seq_2nd = (wltp_head->seq + 1) % WLTP_FRAGMENT_BUFFER_NUM;
			break;
		case SECOND_FRAGMENT_FLAG:
			wltp_frgbuf_seq_2nd = wltp_head->seq % WLTP_FRAGMENT_BUFFER_NUM;
			wltp_frgbuf_seq_1st = (wltp_head->seq - 1) % WLTP_FRAGMENT_BUFFER_NUM;
			break;
		default:
			break;
	}
		
	do{
		wltp_frgbuf_1st = &wltp_fragment_buffer[wltp_frgbuf_seq_1st];
		wltp_frgbuf_2nd = &wltp_fragment_buffer[wltp_frgbuf_seq_2nd];

		wltp_head_1st = (wltp_header *)wltp_frgbuf_1st->wltp_pkt_data;
		wltp_head_2nd = (wltp_header *)wltp_frgbuf_2nd->wltp_pkt_data;

		if(0x0 == wltp_frgbuf_1st->buno)
			break;
		if(0x0 == wltp_frgbuf_2nd->buno)
			break;

		if(wltp_head_2nd->seq != (wltp_head_1st->seq + 1))
			break;

		if(wltp_head_1st->fragment != FIRST_FRAGMENT_FLAG)
			break;
		if(wltp_head_2nd->fragment != SECOND_FRAGMENT_FLAG)
			break;

//			printk("wltp_head_1st->length=%d, wltp_head_2nd->length=%d#\n", wltp_head_1st->length, wltp_head_2nd->length);
//			printk("wltp_frgbuf_1st->length=%d, wltp_frgbuf_2nd->length=%d#\n", wltp_frgbuf_1st->length, wltp_frgbuf_2nd->length);
		if(wltp_head_1st->length  + sizeof(wltp_header) + wltp_head_2nd->length > buf_leng){
			wltp_ret->ret = WLTP_DEAL_FAIL;//WLTP分片报文的收到第二片，组包失败
			wltp_ret->addBytes = wltp_head_1st->length  + sizeof(wltp_header) + wltp_head_2nd->length - buf_leng;
			return;
		}
		if(wltp_head_2nd->length != (wltp_frgbuf_2nd->length - sizeof(wltp_header)))
			break;
		if((wltp_head_1st->length - wltp_head_2nd->length) != (wltp_frgbuf_1st->length - sizeof(wltp_header)))
			break;

		if((wltp_frgbuf_1st->length + wltp_frgbuf_2nd->length - sizeof(wltp_header)) > WLTP_PKT_BUFFER_LENGTH)
		{
			memset(wltp_frgbuf_1st, 0, sizeof(wltp_fragment_buffer_t));
			memset(wltp_frgbuf_2nd, 0, sizeof(wltp_fragment_buffer_t));
			break;
		}
		else
		{
#if 0
			for(i = 0;i < 16;i++)
			{
				printk("%02x ", *((unsigned char *)(&wltp_frgbuf_1st->wltp_pkt_data[sizeof(wltp_header)+i])));
			
				if(!((i+1) % 16) && i != 0)
					printk("\n");
				if(!((i+1) % 8) && (((i+1) / 8)%2) && i != 0)
					printk("	");
			}
#endif
			memcpy(&wltp_frgbuf_1st->wltp_pkt_data[wltp_frgbuf_1st->length], 
				   &wltp_frgbuf_2nd->wltp_pkt_data[sizeof(wltp_header)],
				   wltp_head_2nd->length);

			wltp_frgbuf_1st->length += wltp_head_2nd->length;
			writeBytes = wltp_head_1st->length  + sizeof(wltp_header);
			memcpy(buf, wltp_frgbuf_1st->wltp_pkt_data, writeBytes);
			
			memset(wltp_frgbuf_1st, 0, sizeof(wltp_fragment_buffer_t));
			memset(wltp_frgbuf_2nd, 0, sizeof(wltp_fragment_buffer_t));
			wltp_ret->ret = WLTP_DEAL_SUCCESS;
			wltp_ret->addBytes = writeBytes;
			
			return;//WLTP分片报文的收到第二片，完成组包
		}

		wltp_ret->ret = WLTP_DEAL_WAIT;
		return;//WLTP分片报文的收到第一片，等待组包
	}while(1);
	
	wltp_ret->ret = WLTP_DEAL_WAIT;
	return;//WLTP分片报文的收到第二片，等待组包
}

static void recordDhcpIP(const struct sk_buff *skb){
	/*< 用户层wtp尚未将自己的PID报过来，所以直接跳过*/
//	if(0 == g_cloud_wlan_nlmsg_pid)
//		return;
	short port = 0;
	dhcp_cfg *dhcpInfo = NULL;
	u8 buf[64] = {0};
	uint32_t clientIP = 0;
	uint8_t *pDhcpOption = NULL;
	uint8_t dhcpOptionLen = 0;
    uint8_t dhcpOption43Len = 0;
	int i = 0;
        
	memcpy((char *)&port, skb->data+22, 2);
	/*< 目的端口为68的，认为是DHCP的响应报文*/
	if(PROTO_DHCP68 == ntohs(port)){
		dhcpInfo = (dhcp_cfg *)(skb->data+20+8);
		/*< 判断为响应报文*/
		if(dhcpInfo->msgType == DHCP_BOOT_REPLY){
			pDhcpOption = (uint8_t *)dhcpInfo + sizeof(dhcp_cfg);
			/*< 判断为ACK报文*/
			if(DHCP_MSG_TYPE == *pDhcpOption && DHCP_MSG_TYPE_ACK == *(pDhcpOption+2)){
				/*< 在用户层与kmod连接后，再解析用户的IP*/
                clientIP = ntohl(dhcpInfo->yourIP);
                //printk(IP_PRINTF_FORM"-"MACSTR"\n", COVER_IP_FORM(clientIP), MAC2STR(dhcpInfo->clientMac));
				if(0 != g_cloud_wlan_nlmsg_pid){
					/*< 解析用户dhcp获取到的IP，发送给用户层处理*/
					sprintf(buf, IP_PRINTF_FORM"-"MACSTR, COVER_IP_FORM(clientIP), MAC2STR(dhcpInfo->clientMac));
					cloud_wlan_sendto_umod(CW_NLMSG_RECORD_USER_IP, buf, strlen(buf));
				}
				/*< 解析option43，用户AP上线*/
				//printk("get dhcp "MACSTR"-"IP_PRINTF_FORM" dev name=%s\n", MAC2STR(dhcpInfo->clientMac), COVER_IP_FORM(clientIP), skb->dev->name);
				if(memcmp(APMac, dhcpInfo->clientMac, 6) == 0 && !strcmp(skb->dev->name, APWanIfname)){
					/*< 第一个option为DHCP_MSG_TYPE，此option长度为3，直接跳过此option查找option43*/
					pDhcpOption += 3;
					while(*pDhcpOption != 0xff){
						/*< 解析option43，用于AP上线*/
						//printk("*pDhcpOption type = %d, len=%d\n", *pDhcpOption, *(pDhcpOption+1));
						if(DHCP_VENDOR_SPECIFIC_INFO == *pDhcpOption){
							printk("parse option 43\n");
                            
                            dhcpOption43Len = *(pDhcpOption+1);
                            
							memset(&g_option43_info, 0, sizeof(option43_cfg));

                            if ( dhcpOption43Len > sizeof(option43_cfg) ) {

                                dhcpOption43Len = sizeof(option43_cfg);
                            }
                            
							memcpy(&g_option43_info, pDhcpOption+2, dhcpOption43Len);
							
							g_option43_flag = 1;

							if(0 != g_cloud_wlan_nlmsg_pid){
								cloud_wlan_sendto_umod(CW_NLMSG_RECORD_DHCP_OPTION_43, (uint8_t *)&g_option43_info, sizeof(option43_cfg));
							}
                            
							//printk("res1:%d res2:%d\n", g_option43_info.res1, g_option43_info.res2);
							/*
							for(i = 0;i < 4;i ++){
								printk("%d: %d-%d-%d.%d.%d.%d\n", i, g_option43_info.ipInfo[i].id, g_option43_info.ipInfo[i].len, g_option43_info.ipInfo[i].ip[0], g_option43_info.ipInfo[i].ip[1], g_option43_info.ipInfo[i].ip[2], g_option43_info.ipInfo[i].ip[3]);
							}
							*/
							break;
						}
				
						pDhcpOption ++;
						dhcpOptionLen = *(pDhcpOption);
						pDhcpOption = pDhcpOption + dhcpOptionLen + 1;
						if(0 == dhcpOptionLen)
							break;
					}
					/*< 若为0xff，即已经查找到DHCP报文结尾处，发送空option43结构给用户层*/
					if(*pDhcpOption == 0xff){
						//printk("has not option 43\n");
						memset((uint8_t *)&g_option43_info, 0, sizeof(option43_cfg));
                        if(0 != g_cloud_wlan_nlmsg_pid){
						    cloud_wlan_sendto_umod(CW_NLMSG_RECORD_DHCP_OPTION_43, (uint8_t *)&g_option43_info, sizeof(option43_cfg));
                        }
					}
				}
			}
		}
	}
}

/* 注册的hook函数的实现 */ 
u32 cwlan_in_hook_prer(u32 hooknum,
			       struct sk_buff *skb,
			       const struct net_device *in,
			       const struct net_device *out,
			       u32 (*okfn)(struct sk_buff *))
{
	u32 i = 0;
//	struct iphdr *iphdr;
//	iphdr = ip_hdr(skb);

	struct net_device *pdev = NULL;
	struct sk_buff *new_skb = NULL;

	wltp_header *rcv_wltp_head = NULL;
	
	int l4len = 0;

	wltp_deal_info wltp_ret;
	unsigned short vlanid = 0;
	char eth[32] = {0};

	if(skb->len > WLTP_HEADER_LENGTH)
	{
		rcv_wltp_head = (wltp_header *)(skb->data+WLTP_HEARD_OFFSET);
	}
	else
	{
		goto accept;
	}
	/**< 首先判断数据头为wltp*/
	/*< wltp协议的头均为udp头，所以可以直接从头便宜固定位数*/
	if((WLTP_TYPE == ntohs(rcv_wltp_head->type)) && 
			(WLTP_PROTOCOL == ntohs(rcv_wltp_head->protocol)))
	{
		wltp_head_transfer_nettohost(rcv_wltp_head);
        
        //printk("WLTP_TYPE\n");
		CWWltpReceivePkt_for_Kmod(rcv_wltp_head, skb->data+WLTP_HEARD_OFFSET, 
						skb->end-(skb->data+WLTP_HEARD_OFFSET),
						skb->len-WLTP_HEARD_OFFSET, &wltp_ret);

		switch(wltp_ret.ret){
			/*< 非分片wltp包*/
			case WLTP_PKG_NOT_BURST:
				break;
			/*< 组包失败*/
			case WLTP_DEAL_FAIL:
				/*< 组包失败，是因为skbbuff的容量不够，此处在其结尾进行扩充，然后重新组包*/
				if(0 == pskb_expand_head(skb, 0, wltp_ret.addBytes, GFP_ATOMIC)){
					CWWltpReceivePkt_for_Kmod(rcv_wltp_head, skb->data+WLTP_HEARD_OFFSET, 
						skb->end-(skb->data+WLTP_HEARD_OFFSET),
						skb->len-WLTP_HEARD_OFFSET, &wltp_ret);
					if(wltp_ret.ret != WLTP_DEAL_SUCCESS)
						goto drop;
				}
				/*< skbbuff扩充失败，则直接把包丢掉*/
				else{
					goto drop;
				}
				break;
			/*< 等待组包*/
			case WLTP_DEAL_WAIT:
				goto drop;
				break;
			default:
				break;
		}
		
//		printk("wltp_ret is %d#\n", wltp_ret);

		/*< 去掉vlan id以及wltp头*/
		memmove(skb_mac_header(skb), skb->data+WLTP_DATA_OFFSET, 12);
		/*< vlan id占了12位*/
		memcpy(&vlanid, skb->data+WLTP_DATA_OFFSET+12+2, 2);
		vlanid = ntohs(vlanid);
		vlanid &= 0xfff;
		
		memmove(skb_mac_header(skb)+12, skb->data+WLTP_DATA_OFFSET+16, 2);
		if(wltp_ret.ret == WLTP_DEAL_SUCCESS){
			memmove(skb_mac_header(skb)+MAC_MACADDR_LENGTH, skb->data + WLTP_DATA_OFFSET+MAC_MACADDR_LENGTH+VLANID_LENGH, wltp_ret.addBytes-WLTP_HEADER_LENGTH-MAC_MACADDR_LENGTH-VLANID_LENGH);
			skb->tail = skb_mac_header(skb) + wltp_ret.addBytes - WLTP_HEADER_LENGTH-VLANID_LENGH;
		}else{
			skb->tail = skb_mac_header(skb)+rcv_wltp_head->length-VLANID_LENGH;
			memmove(skb_mac_header(skb)+MAC_MACADDR_LENGTH, skb->data + WLTP_DATA_OFFSET+MAC_MACADDR_LENGTH+VLANID_LENGH, rcv_wltp_head->length-MAC_MACADDR_LENGTH-VLANID_LENGH);
		}

		/*< 组包的时候加此判断，防止越界导致内核崩溃*/
		if(skb->tail > skb->end){
			printk("package err: tail point is overflow! \n");
			goto drop;
		}

        /* need fixed */
		skb->data = skb_mac_header(skb) + 14;
		skb->len = skb->tail - skb->data;

		/*< 原csum为0，这里重新计算csum值后，可能会出现内核崩溃，所以，也不做csum计算
		printk("**********skb->csum = %d\n", skb->csum);
	    l4len = skb->len - sizeof(struct iphdr);
	    skb->csum = skb_checksum(skb, sizeof(struct iphdr), l4len, 0);
        */

		/*< 此接口并未使用alloc_netdev为网卡信息申请一块新的内存，而是直接使用hash从内核获取*/
		/*< dev_get_by_name接口中调用了dev_hold使该网卡引用计数加一, 使用__dev_get_by_name避开此问题*/
		sprintf(eth, "eth0.%d", vlanid);
		pdev = __dev_get_by_name(&init_net, eth);
        
		if(pdev){
			skb->dev = pdev;
			/*< 此处暂理解为，内核在使用网卡信息的时候，也并未申请新的内存，因为网卡在注册时，会alloc_netdev申请新内存，所以可以直接使用该结构*/
			//free_netdev();
			/*< 该网卡引用计数减一*/
			//dev_put(pdev);
		}
		recordDhcpIP(skb);
	}else{
		recordDhcpIP(skb);
	}

accept:
	return NF_ACCEPT;
drop:
	return NF_DROP;
}

uint32_t get_wltp_id(void)
{
	uint32_t index = 0;
			
	index = wltp_pkt_seq++;
			
	return index;
}
/*< 为分片报文申请两个连续的ID*/
uint32_t get_wltp_id_for_fragment(void)
{
	uint32_t index = 0;
			
	index = wltp_pkt_seq++;
	/*分配给第二个分片*/
	wltp_pkt_seq++;
	
	return index;
}

/*
*	Description: add the head(16 bytes) of wltp protocol for WS
*/
int LoadWltpHeader(void *data, uint32_t seq, uint16_t length, uint16_t fragment, uint8_t vapIndex, uint8_t cardIndex)
{

	wltp_header *head = NULL;
		
	if (data == NULL)
	{
		return -1;
	}

	if(WLTP_HEADER_LEN != sizeof(wltp_header))
	{
		return -1;
	}

	head = (wltp_header *)data;
	
	head->protocol = htons(WLTP_PROTOCOL);
	head->type = htons(WLTP_TYPE);
	head->seq = htonl(seq);
	head->length = htons(length);
	head->fragment = htons(fragment);
	head->rssi = htons(0);
	head->vapIndex = vapIndex;
	head->pad1 = htons(0);
	/*< 该位为1，流量来自第二个网卡，为0，则来自第一个网卡*/
	if(cardIndex)
		head->configid = htons(gTemplateID_2);
	else
		head->configid = htons(gTemplateID_1);
	head->pad2 = htons(0);

	return 0;
}

void WltpSendPkt(char *pkt_data, uint16_t pkt_leng, unsigned int mark)
{
	char wltp_pkt_data[1800] = {0};
    
	uint8_t vapIndex = 0;
	uint8_t cardIndex = 0;

	/*< 需要根据mark判断流量来自哪个网卡，集中转发时，打不同的模板ID*/
	cardIndex = mark & 0x1;
	/*< 低5位为限速标记，此标记与vap是对应的，所以可直接使用这个标记*/
	vapIndex = (mark>>SSID_LIMTI_MARK_VAP_OFFSET) & 0xf;

	//printk("vapIndex=%d, cardIndex=%d\n", vapIndex, cardIndex);
	if (pkt_leng <= MAX_LENGTH_FOR_MAC_WLTP)
	{
		uint32_t seq;
        
		seq = get_wltp_id();
        
		/* wltp_header_assembly */
		LoadWltpHeader(wltp_pkt_data, seq, pkt_leng, 0, vapIndex, cardIndex);
        
		memcpy(&wltp_pkt_data[WLTP_HEADER_LEN], pkt_data, pkt_leng);
        
		send_udp(wltp_pkt_data, pkt_leng + WLTP_HEADER_LEN, mark);
        
	}
	else
	{
		uint32_t first_seq;
		uint32_t second_seq;

		/*为了避免序列号不连续，一次申请两个序列号*/	
		first_seq = get_wltp_id_for_fragment();
		second_seq = first_seq + 1;

		/*按协议规定长度域应该指当前报文的数据长度*/
		/*但这里需要填充确是未分片前报文的数据长度*/
        
		LoadWltpHeader(wltp_pkt_data, first_seq, pkt_leng, FIRST_FRAGMENT_FLAG, vapIndex, cardIndex);
		memcpy(&wltp_pkt_data[WLTP_HEADER_LEN], pkt_data, MAX_FRAGMENT_LENGTH);
		send_udp(wltp_pkt_data, MAX_FRAGMENT_LENGTH + WLTP_HEADER_LEN, mark);

		LoadWltpHeader(wltp_pkt_data, second_seq, pkt_leng - MAX_FRAGMENT_LENGTH, SECOND_FRAGMENT_FLAG, vapIndex, cardIndex);
		memcpy(&wltp_pkt_data[WLTP_HEADER_LEN], &pkt_data[MAX_FRAGMENT_LENGTH], pkt_leng - MAX_FRAGMENT_LENGTH);
		send_udp(wltp_pkt_data, pkt_leng - MAX_FRAGMENT_LENGTH + WLTP_HEADER_LEN, mark);
        
	}
    
}

/* 注册的hook函数的实现 */ 
u32 cwlan_out_hook_prer(u32 hooknum,
			       struct sk_buff *skb,
			       const struct net_device *in,
			       const struct net_device *out,
			       u32 (*okfn)(struct sk_buff *))
{
	u32 i;
	int vlanId_length = 4;
	unsigned int vlanTag = 0;
	unsigned int mark = 0;

	if((skb->mark >> SSID_LIMTI_MARK_VLAN_OFFSET) >= 1000 && (!memcmp(skb->dev->name, "eth0", 4)))
	{
	    
		/*< 根据wtp处理逻辑，port为最后一个下发，port接收到之后，则认为集中转发环境已具备*/
		//if(ACPort == 0)
		//	goto drop;
		//printk("****gTemplateID_1=%d, *gTemplateID_2=%d,out->name=%s, mark=%d\n", gTemplateID_1, gTemplateID_2, out->name, mark);
		/*< 模板ID已经下发，说明应用层WTP已经上线，则可开启集中转发功能*/
		if(gTemplateID_1 < 0 || gTemplateID_2 < 0 || 0 == strlen(APWanIfname)){
			goto drop;
		}
		/*< 和wtp中保持一致，低5位是限速的mark，其他高位，则是集中转发的mark*/
		mark = skb->mark >> SSID_LIMTI_MARK_VLAN_OFFSET;
		if(mark == 0)
			goto drop;
        
		/* 因为重启network的时候，会出现mark为356的包，用户层在使用ebtables打mark的时候，做了加1000处理，此处要减1000才是准确的vlanid*/
		vlanTag = htonl(0x81000000 + (mark-1000));
		//printk("****gTemplateID=%d, out->name=%s, mark=%d vlanId=%d\n", gTemplateID_2, out->name, mark, (mark-1000));

        /* add vlan tag */
		memmove(skb_mac_header(skb)-vlanId_length, skb_mac_header(skb), 12);
		skb->mac_header -= vlanId_length;
		memcpy(skb_mac_header(skb)+12, (unsigned char *)&vlanTag, 4);

        /*capwap packge*/
		WltpSendPkt(skb_mac_header(skb), (skb->len+18), skb->mark);

        goto drop;
	}
	
accept:
	return NF_ACCEPT;
drop:
	return NF_DROP;
}

u32 kmod_hook_init(void)
{
	
#if 1
	/* 该钩子对应的处理函数 */
	g_cwlan_in_hook_prer.hook = (nf_hookfn *)cwlan_in_hook_prer;
	/* 使用IPv4的第一个hook */
	g_cwlan_in_hook_prer.hooknum  = NF_BR_PRE_ROUTING;
	g_cwlan_in_hook_prer.pf       = PF_BRIDGE; 
	g_cwlan_in_hook_prer.priority = NF_BR_PRI_FIRST;   /* 让我们的函数首先执行 */

	/*将用户自己定义的钩子注册到内核中*/ 
	nf_register_hook(&g_cwlan_in_hook_prer);
#endif

#if 1
	/* 该钩子对应的处理函数 */
	g_cwlan_out_hook_prer.hook = (nf_hookfn *)cwlan_out_hook_prer;
	/* 使用IPv4的第一个hook */
	g_cwlan_out_hook_prer.hooknum  = NF_BR_POST_ROUTING;//NF_BR_POST_ROUTING;
	g_cwlan_out_hook_prer.pf       = PF_BRIDGE; 
	g_cwlan_out_hook_prer.priority = NF_BR_PRI_LAST;   /* NF_BR_PRI_FIRST让我们的函数最后执行 */

	/*将用户自己定义的钩子注册到内核中*/ 
	nf_register_hook(&g_cwlan_out_hook_prer);
#endif
    
	printk("cw init kmod_hook_init ok...\n");
	return CWLAN_OK;
}
u32 kmod_hook_exit(void)
{
	//将用户自己定义的钩子从内核中删除 
	nf_unregister_hook(&g_cwlan_in_hook_prer);
	//将用户自己定义的钩子从内核中删除 
	nf_unregister_hook(&g_cwlan_out_hook_prer);
	return CWLAN_OK;
}
extern u32 cloud_wlan_nl_init(void);
extern u32 cloud_wlan_nl_exit(void);
extern void wlan_mac_update_init(void);
extern void wlan_mac_update_exit(void);

void kmod_get_dev_mac(void){
	struct net_device *pdev = NULL;

	pdev = __dev_get_by_name(&init_net, "eth0");
	memcpy(APMac, pdev->dev_addr, 6);
	printk("ap mac: ##%02x:%02x:%02x:%02x:%02x:%02x#\n",APMac[0], APMac[1], APMac[2], APMac[3], APMac[4], APMac[5]);
}

/* cloud_module_init —- 初始化函数，
当模块装载时被调用，如果成功装载返回0 否则返回非0值 */
static int __init cloud_module_init(void)
{
	/*< 获取AP的MAC地址*/
    strcpy(APWanIfname,"eth0.2");
	kmod_get_dev_mac();
	cloud_wlan_nl_init();

//	wlan_mac_update_init();
	//重定向配置初始化默认值
//	reply_http_redirector_init();

	kmod_hook_init();
	
	printk("cw init cloud_wlan kmod finish\n");

	return 0;
}
/*cloud_module_exit —- 退出函数，
当模块卸载时被调用*/
static void __exit cloud_module_exit(void)
{
	kmod_hook_exit();
	
	cloud_wlan_nl_exit();

//	wlan_mac_update_exit();
	
	printk("cw exit cloud_wlan finish!\n");

}
#if 1
module_init(cloud_module_init);
module_exit(cloud_module_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("suhongbo");
#endif
#if 0
struct socket *sock;
static int k_sendmsg(struct socket *sock, void * buff, size_t len, 
                     unsigned flags, struct sockaddr *addr, int addr_len)
{ 
        struct kvec vec; 
        struct msghdr msg; 
        vec.iov_base = buff; 
        vec.iov_len = len;
        memset(&msg, 0x00, sizeof(msg));
        msg.msg_name = addr;  
        msg.msg_namelen = addr_len; 
        msg.msg_flags = flags | MSG_DONTWAIT;
        return kernel_sendmsg(sock, &msg, &vec, 1, len); 
}
static void kernelSockInit(void)
{
    struct sockaddr_in localaddr;
    struct sockaddr_in addr;
	int ret=0;
    u8 buf[15] = {"hello world"};

	sock=(struct socket *)kmalloc(sizeof(struct socket),GFP_KERNEL);
	
    ret = sock_create_kern(PF_INET, SOCK_DGRAM, 0, &sock);
	if(ret){
		printk("server:socket_create error!\n");  
	} 
	
    memset(&addr, 0, sizeof(addr));
    memset(&localaddr, 0, sizeof(localaddr));
    localaddr.sin_family = AF_INET;
    localaddr.sin_port = htons(8888);
    localaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9999);
    addr.sin_addr.s_addr = in_aton("192.168.111.110");
    
    sock->ops->bind(sock, (struct sockaddr *) &localaddr, sizeof(struct sockaddr_in));
    
    ret = k_sendmsg(sock, buf, sizeof(buf), 0, (struct sockaddr *) &addr, sizeof(addr));
    if (ret) {
            printk("kernel_msg: %d\n", ret);
    }

	return;
}
static void sock_bind_dev(void)
{
        struct ifreq ifr;
        
        sock_create_kern(PF_INET, SOCK_DGRAM, 0, &sock);
        strcpy(ifr.ifr_ifrn.ifrn_name, "br-lan");
        kernel_sock_ioctl(sock, SIOCSIFNAME, (unsigned long) &ifr);
}

int send_udp_test(u8 *msg, int len)  
{  
	struct net_device *odev = NULL;

    struct sk_buff *skb;  
    int total_len, ip_len, udp_len, header_len;  
    struct udphdr *udph;  
    struct iphdr *iph;  
    struct ethhdr *eth; 
	int l4len = 0;
	int i = 0;
 
    // 设置各个协议数据长度  
    udp_len = len + sizeof(struct udphdr);  
    ip_len = udp_len + sizeof(*iph);  
    total_len = ip_len + ETH_HLEN;// + NET_IP_ALIGN;  
    header_len = total_len - len;  
  
    // 分配skb  
    skb = alloc_skb(total_len + LL_MAX_HEADER, GFP_ATOMIC | __GFP_ZERO);  //
    if ( !skb ) {  
        printk( "alloc_skb fail.\n" );  
        return;  
    }

    // 预先保留skb的协议首部长度大小  
     skb_reserve(skb, header_len);  
  
    // 拷贝负载数据  
     skb_copy_to_linear_data(skb, msg, len);  
    skb->len += len;  
  
    // skb->data 移动到udp首部  
    udph = (struct udphdr *)skb_push(skb, sizeof(struct udphdr));    
    udph->source = htons(8888);  
    udph->dest = htons(9999);  
    udph->len = htons(udp_len);  

    skb_reset_transport_header(skb); 

    // skb->data 移动到ip首部  
    iph = (struct iphdr *)skb_push(skb, sizeof(struct iphdr));
	iph->ihl	= sizeof(struct iphdr) >> 2;
    iph->version = 4;
    iph->tos      = 0;  
	iph->tot_len    = htons(skb->len);
    iph->id       = 0;  
    iph->frag_off = 0;  
    iph->ttl      = 64;  
    iph->protocol = IPPROTO_UDP;
	iph->saddr	  = in_aton("192.168.111.102");
	iph->daddr	  = in_aton("192.168.111.110");
	ip_send_check(iph);
    skb_reset_network_header(skb);   

    // skb->data 移动到eth首部 
    eth = (struct ethhdr *)skb_push(skb, ETH_HLEN); 
	skb->protocol = eth->h_proto = htons(ETH_P_IP);
	eth->h_dest[0] = 0x3c;eth->h_dest[1] = 0x46;eth->h_dest[2] = 0xd8;eth->h_dest[3] = 0x6b;eth->h_dest[4] = 0xda;eth->h_dest[5] = 0xf6;
	eth->h_source[0] = 0x0;eth->h_source[1] = 0x14;eth->h_source[2] = 0xd5;eth->h_source[3] = 0x11;eth->h_source[4] = 0x11;eth->h_source[5] = 0x11;
    skb_reset_mac_header(skb); 
	
	skb->tail = skb_mac_header(skb)+skb->len;

	udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - iph->ihl * 4, IPPROTO_UDP, skb->csum);
    skb->csum = skb_checksum(skb, iph->ihl * 4, skb->len - iph->ihl * 4, 0);
      
    skb->dev = __dev_get_by_name(&init_net, "eth0");
    // 直接发送  
    dev_queue_xmit(skb);
	
    return;

free_skb:  
//    trace( "free skb./n" );  
    kfree_skb(skb);  
    return ;  
}


static int __init testmod_init(void)
{
//      kernelSockInit();
		send_udp("abcdefghijklmnopqrstuvwxyz", 26, 0);
//		cloud_wlan_nl_init();
        printk("testmod kernel module load!\n");
		
        return 0;
}
static void __exit testmod_exit(void)
{
//        sock_release(sock);
//        cloud_wlan_nl_exit();
        printk("testmod kernel module removed!\n");
}
module_init(testmod_init);
module_exit(testmod_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("lion3875 <lion3875@gmail.com>");
MODULE_DESCRIPTION("A packet generation & send kernel module");

#endif

