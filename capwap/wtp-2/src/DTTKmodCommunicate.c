/*
 * ���ļ���Ҫ����wtp�������ں�֮��Ľ���
 *
 * �ں�̬������Ҫ���ڼ���ת��wltp����
 *
 * �����������֮��ͨ�ţ�����mac��ַ�Լ�AC��IP�ȵ�ͨ��
 *
 * 2016��3��17��
 *
 * suhongbo@datang.com
 */

#include "DTTKmodCommunicate.h"
#include "CWWTP.h"

static cw_nl_info_t g_cw_nl_info;
static struct iovec iov;  
struct pthread_id g_pthread;
extern gAPFoundACType;

s32 nl_set_tpye(unsigned short nlmsg_type)
{
	g_cw_nl_info.nlh->nlmsg_type = nlmsg_type;  

	if(nlmsg_type == CW_NLMSG_SET_USER_PID)
		return CW_OK;
	
	g_cw_nl_info.nlh->nlmsg_len = NLMSG_SPACE(MAX_DATA_PAYLOAD); //��֤����  
	g_cw_nl_info.nlh->nlmsg_pid = getpid();  /* self pid */  
	g_cw_nl_info.nlh->nlmsg_flags = 0;
	
	iov.iov_base = (void *)g_cw_nl_info.nlh;  
	iov.iov_len = g_cw_nl_info.nlh->nlmsg_len;  
	g_cw_nl_info.msg.msg_name = (void *)&g_cw_nl_info.dst_addr;  
	g_cw_nl_info.msg.msg_namelen = sizeof(struct sockaddr_nl);  
	g_cw_nl_info.msg.msg_iov = &iov;  
	g_cw_nl_info.msg.msg_iovlen = 1; 
	
	return CW_OK;
}
s32 nl_set_data(s8 *buff, u32 datalen)
{
	if(buff == NULL)
	{
		datalen = 0;
	}
	datalen = datalen>MAX_DATA_PAYLOAD?MAX_DATA_PAYLOAD:datalen;
	memcpy(NLMSG_DATA(g_cw_nl_info.nlh), buff, datalen);
	return CW_OK;
}
s32 nl_send_data(void)
{
	sendmsg(g_cw_nl_info.sockfd, &g_cw_nl_info.msg, 0); // ����  
	return CW_OK;
}

s32 sendto_kmod(s32 type, s8 *buff, u32 datalen)
{
	nl_set_tpye(type);
	nl_set_data(buff, datalen);
	nl_send_data();
	return CW_OK;
}

/*< ��ʼ����kmod��ͨ�Žӿ�*/
s32 kmod_communicate_init(char *devmac)
{
	u32 ret;

	g_cw_nl_info.sockfd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CWLAN); // ����NETLINK_CWLANЭ���socket	
	/* ���ñ��ض˵㲢�󶨣��������� */  
	bzero(&g_cw_nl_info.src_addr, sizeof(struct sockaddr_nl));  
	g_cw_nl_info.src_addr.nl_family = AF_NETLINK;	
	g_cw_nl_info.src_addr.nl_pid = getpid();  
	g_cw_nl_info.src_addr.nl_groups = 0; //δ����ಥ��  
	ret = bind(g_cw_nl_info.sockfd, (struct sockaddr*)&g_cw_nl_info.src_addr, sizeof(struct sockaddr_nl));  
	if( ret != CW_OK)
	{
		CWDTTLog("kernel capwap module not start!! socket bind error %d %s\n", errno, strerror(errno));
		return CW_FAIL;
	}
	/* ����Ŀ�Ķ˵㣬���ڷ��� */  
	bzero(&g_cw_nl_info.dst_addr, sizeof(struct sockaddr_nl));  
	g_cw_nl_info.dst_addr.nl_family = AF_NETLINK;	
	g_cw_nl_info.dst_addr.nl_pid = 0; // ��ʾ�ں�	
	g_cw_nl_info.dst_addr.nl_groups = 0; //δָ�����նಥ��   
	/* ���췢����Ϣ */  

	g_cw_nl_info.nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_DATA_PAYLOAD)); 
	if(g_cw_nl_info.nlh == NULL)
	{
		printf("g_cw_nl_info struct init fail\n");
		return CW_FAIL;
	}
	g_cw_nl_info.nlh->nlmsg_len = NLMSG_SPACE(MAX_DATA_PAYLOAD); //��֤����  
	g_cw_nl_info.nlh->nlmsg_pid = getpid();  /* self pid */  
	g_cw_nl_info.nlh->nlmsg_flags = 0;  
	g_cw_nl_info.nlh->nlmsg_type = CW_NLMSG_RES_OK;  
	snprintf(NLMSG_DATA(g_cw_nl_info.nlh), MAX_DATA_PAYLOAD, "OK!\n");  
	iov.iov_base = (void *)g_cw_nl_info.nlh;  
	iov.iov_len = g_cw_nl_info.nlh->nlmsg_len;  
	g_cw_nl_info.msg.msg_name = (void *)&g_cw_nl_info.dst_addr;  
	g_cw_nl_info.msg.msg_namelen = sizeof(struct sockaddr_nl);  
	g_cw_nl_info.msg.msg_iov = &iov;  
	g_cw_nl_info.msg.msg_iovlen = 1; 
	
	if(1 == gAPIndex){
		/*< ��һ�����̣���Ҫ���ں˽������·��Լ���pid�����ڶ������̣�ֻ��Ҫ�����ںˣ��Լ���ģ��ID������ת��ʱʹ��*/
		sendto_kmod(CW_NLMSG_SET_USER_PID, (s8 *)&g_cw_nl_info.nlh->nlmsg_pid, sizeof(u32));
		sendto_kmod(CW_NLMSG_SET_WAN_IFNAME, (s8 *)gWanIfname, 16);
	}
	/*< �豸MAC��kmod�˻�ȡ*/
//	sendto_kmod(CW_NLMSG_SET_DEV_MAC, (s8 *)devmac, sizeof(s8)*6);
	
	return CW_OK;

}

static void dtt_record_user_ip(u8 *buf){
	char mac[32] = {0};
    char ip[32] = {0};
	char cmd[64] = {0};

    sscanf(buf, "%[^-]-%s", ip, mac);
	sprintf(cmd, "sed '/%s/d' -i /tmp/capwap/kmod-ip-mac", mac);
    system(cmd);
	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "echo %s >> /tmp/capwap/kmod-ip-mac", buf);
	system(cmd);
}

static void dtt_parse_option43(u8 *buf){
	option43_cfg *option43 = (option43_cfg *)buf;
	int i = 0;
	char ipstr[32] = {0};
	/*< ����һ��IP��id�Լ����ȶ�Ϊ0����֤��kmod�Ѿ����ص�AP��DHCP ACK���ģ�����û��option43��Ϣ*/
	if(option43->ipInfo[0].id == 0 && option43->ipInfo[0].len == 0){
		return;
	}else{
		gCWACCfg->gCWACCount = 0;
		for(i = 0; i < DHCP_OPTION_43_IP_COUNT;i ++){
			if(0 == option43->ipInfo[i].ip[0] && 0 == option43->ipInfo[i].ip[1] && 0 == option43->ipInfo[i].ip[2] && 0 == option43->ipInfo[i].ip[3])
				continue;
			else{
				if(NULL == gCWACCfg->gCWACList){
 					CW_CREATE_ARRAY_ERR(gCWACCfg->gCWACList, DHCP_OPTION_43_IP_COUNT+1, CWACDescriptor, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
				}
				memset(ipstr, 0, sizeof(ipstr));
				if(inet_ntop(AF_INET, (struct in_addr *)(option43->ipInfo[i].ip), ipstr, 32) != 0){
					/*< ��ЧIP�ż���,�����ڵ�һ����������У�����д�빲���ڴ棬�ڶ���������̳�ʼ��ʱֱ��ʹ��*/
					setAPOnlineACIPandCount(gCWACCfg->gCWACCount, ipstr);
					CWLog("##Option43 : AC %d at %s\t##", gCWACCfg->gCWACCount, ipstr);
					gCWACCfg->gCWACCount ++;
					CW_COPY_MEMORY(gCWACCfg->gCWACList[i].address, ipstr, strlen(ipstr));
//					CW_CREATE_STRING_FROM_STRING_ERR(gCWACCfg->gCWACList[i].address, ipstr, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
				}
			}
		}
	}
}
s32 dtt_nl_recv_from_kmod(dcma_udp_skb_info_t *buff)
{
	int recv_st=0;
	/* ������Ϣ����ӡ */  
	memset(g_cw_nl_info.nlh, 0, NLMSG_SPACE(MAX_DATA_PAYLOAD));  
	recvmsg(g_cw_nl_info.sockfd, &g_cw_nl_info.msg, 0);
	if(-1 == recv_st)
	{
		printf("recvfrom :%d %s\n", errno, strerror(errno));
		return CW_FAIL;
	}
	buff->length = g_cw_nl_info.nlh->nlmsg_len - NLMSG_HDRLEN;
	buff->type = g_cw_nl_info.nlh->nlmsg_type;
	memcpy(buff->data, NLMSG_DATA(g_cw_nl_info.nlh), buff->length); 

	switch(buff->type){
		case CW_NLMSG_RECORD_USER_IP:
			dtt_record_user_ip(buff->data);
			break;
		case CW_NLMSG_RECORD_DHCP_OPTION_43:
			/*< AP����״̬Ϊoption43ʱ���Ž���option43����*/
			if(WTP_FOUND_AC_TYPE_INIT == gAPFoundACType || WTP_FOUND_AC_TYPE_OPTION43 == gAPFoundACType){
				/*< ���������ڶ��������ڵ�����������ʱ�������¶�ȡoption43��Ϣ�����Լӽ��������ƣ���Ҫ�������ڴ�*/
//				APOnlineTypeLock();
				/*< �߳���������������һ���߳���discoverʱ�����ȡgCWACCfg�ṹ�����Լ��߳���*/
				CWThreadMutexLock(& gCWACCfg->mutex);
				dtt_parse_option43(buff->data);
				CWThreadMutexUnlock(& gCWACCfg->mutex);
//				APOnlineTypeUnLock();
				CWSignalThreadCondition(&gDhcpOption43Wait);
			}
			break;
	}
	return CW_OK;
}

void *dtt_ap_recv_kmod_info(void *param)
{
	s32 ret=0;
	u8 buf[MAX_PROTOCOL_LPAYLOAD]={0};

	while(1)
	{
		memset(buf, 0, sizeof(buf));
		/* ����kernel nl������Ϣ */
		ret = dtt_nl_recv_from_kmod((dcma_udp_skb_info_t *)buf);
		if(ret == CW_FAIL)
		{
			continue;
		}
	}
	
	return NULL;
}

s32 dtt_dispose_pthread_init(void)
{
	s32 ret = CW_OK;
	pthread_attr_t attr;

	ret = pthread_attr_init(&attr);

	//�߳��˳�ֱ���ͷ���Դ
	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if(ret!=0){
		printf("init pthread_attr_setdetachstate fail %d!\n",ret);
		goto EXIT;
	}

	/* ���ؽ����ں������߳�*/
	ret = pthread_create(&g_pthread.recv_kmod_id, &attr, dtt_ap_recv_kmod_info, NULL);
	if(ret!=0){
		printf("init cw_ap_recv_kmod_info fail %d!\n",ret);
		goto EXIT;
	}
EXIT:
	return ret;
}



 
