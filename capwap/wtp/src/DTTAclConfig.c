#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <linux/socket.h>
#include <errno.h>
#include <sys/un.h>

#include <pthread.h>
#include <semaphore.h>

#include "CWWTP.h"
#include "DTTAclConfig.h"
#include "CWLog.h"
#include "CWProtocol.h"
#include "dtt.h"
/*< acl开关*/
char doOffAcl = 0;
int aclSwitch = 0;
/*< frament的seq，用于匹配是否为本event的reponse*/
int seqNum;
int eventReponseSeqnum;
int configResponseFlag = 0;

aclControlCfg aclAuthStaInfo;

int fd_wtp = -1;
int fd_wtp_1 = -1;
int fd_wtp_2 = -1;
int fd_wtp_data_1 = -1;
int fd_wtp_data_2 = -1;

/*< AC端配置，可最多输入138个字符，算逗号，此处按最多可配64个SSID计算，每个最长64*/
unsigned char gAclssid[256] = {0};

unsigned short gAclVlanCfg[16] = {0};

pthread_mutex_t aclMutex = PTHREAD_MUTEX_INITIALIZER;

#if 0
int getauthContrFd(){
	return fd_wtp;
}
int getauthDataFd(){
	return fd_wtp_data;
}
#endif

void ACLSSIDEditLock(void){
	CWThreadMutexLock(&aclMutex);
}
void ACLSSIDEditUnLock(void){
	CWThreadMutexUnlock(&aclMutex);
}

unsigned char *getAclssidList(){
	return gAclssid;
}
unsigned short *getAclVlanList(){
	return gAclVlanCfg;
}

int setConfigUpdateReponseCond(int flag){
	return configResponseFlag = flag;
}
void setAclAuthResultInfo(aclControlCfg *pinfo){
	memset(&aclAuthStaInfo, 0, sizeof(aclAuthStaInfo));
	memcpy(&aclAuthStaInfo, pinfo, sizeof(aclAuthStaInfo));
}

void setACLSwitch(int flag){
	if(aclSwitch != 0 && flag == 0){
		doOffAcl = 1;
	}
	aclSwitch = flag;
}
static int getACLSwitch(){
	return aclSwitch;
}

void setWTPEventReponseSeqnum(int num){
	eventReponseSeqnum = num;
}
static int *getWTPEventReponseSeqnum(){
	return &eventReponseSeqnum;
}

static CWBool sendWTPEventPkg(short elemType, char *buffer, size_t size){
	int fragmentsNumPtr = 0;
	
	CWProtocolMessage *messagesPtr = NULL;
	CWProtocolMessage *msgElems= NULL;
	CWProtocolMessage *msgElemsBinding= NULL;
	const int msgElemBindingCount=0;
	int msgElemCount = 1;
		
	seqNum = CWGetSeqNum();
	
 	CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgElems, msgElemCount, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	CW_CREATE_PROTOCOL_MESSAGE(*msgElems, size+WTP_VENDOR_ELEMENT_ID_LENTH+WTP_VENDOR_ELEMENT_LEN_LENTH+WTP_VENDOR_ID_LENTH, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWProtocolStore32(msgElems, CW_VENDOR_ID); // z-com
	CWProtocolStore16(msgElems, elemType);
	CWProtocolStore16(msgElems, size);
	CWProtocolStoreRawBytes(msgElems, buffer, size);

	CWAssembleMsgElem(msgElems, CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE);

	if (!(CWAssembleMessage(&messagesPtr,
				&fragmentsNumPtr,
				gWTPPathMTU,
				seqNum,
				CW_MSG_TYPE_VALUE_WTP_EVENT_REQUEST,
				msgElems,
				msgElemCount,
				msgElemsBinding,
				msgElemBindingCount,
				-1,
#ifdef CW_NO_DTLS
				CW_PACKET_PLAIN
#else
				CW_PACKET_CRYPT
#endif
				)))
	 	return CW_FALSE;

	int i;
	for(i = 0; i < fragmentsNumPtr; i++) {
		if(!CWNetworkSendUnsafeConnected(gWTPSocket, messagesPtr[i].msg, messagesPtr[i].offset)) {
			return CW_FALSE;
		}
		CW_FREE_PROTOCOL_MESSAGE(messagesPtr[i]);
	}

	return CW_TRUE;
}

static CWBool sendTrapStaOnline(char *apMac, char *apName, unsigned char *staMac){
	staTrapInfo trap;
	char buffer[128] = {0};
	
	memset(&trap, 0, sizeof(staTrapInfo));
	memcpy(trap.tapMac, apMac, sizeof(trap.tapMac));
	memcpy(trap.apName, apName, strlen(apName));
	snprintf(buffer, sizeof(buffer), MACSTR"|NO INFORMAT INO|", MAC2STR(staMac));
	memcpy(trap.trapInfo, buffer, sizeof(buffer));

	sendWTPEventPkg(WTP_ACL_TRAP_STA_ONLINE, (char *)&trap, sizeof(staTrapInfo));
	
	return CW_TRUE;
}

static CWBool sendAuthRequestToAC(struct dtt_acl_wtp_data *aclWtpData, int aclState, unsigned short vlanId){
	char buffer[128] = {0};
	size_t size = 0;

	CWDTTLog("send " MACSTR " AuthRequest to AC", MAC2STR(aclWtpData->sa));
	if(SSID_ACL_ON == aclState){
		memcpy(buffer, aclWtpData->sa, 6);
		size += 6;
		memcpy(buffer+size, aclWtpData->ssid, strlen(aclWtpData->ssid));
		size += strlen(aclWtpData->ssid);
		/*< 发送认证请求包，内容为mac地址，6字节*/
		sendWTPEventPkg(CW_DTT_MSG_ELEMENT_CONFIG_AP_ASK_AC_AUTH_MACADDR, buffer, size+1);
	}
	if(VLAN_ACL_ON == aclState){
		memcpy(buffer, aclWtpData->sa, 6);
		size += 6;
		if(vlanId == 0){
			goto FAIL;
		}
		memcpy(buffer+size, &vlanId, 2);
		size += 2;
		/*< 发送认证请求包，内容为mac地址，6字节*/
		sendWTPEventPkg(CW_DTT_MSG_ELEMENT_CONFIG_AP_ASK_AC_AUTH_MACADDR, buffer, size);
	}
    if(MACL_ACL_ON == aclState){
		memcpy(buffer, aclWtpData->sa, 6);
		size += 6;
		
		/*< 发送认证请求包，内容为mac地址，6字节*/
		sendWTPEventPkg(CW_DTT_MSG_ELEMENT_CONFIG_AP_ASK_AC_AUTH_MACADDR, buffer, size);
	}
	
	return CW_TRUE;
FAIL:
	return CW_FALSE;
}
#if 0
/*< wtp与hostapd之间的握手过程*/
static int shakeInit(void *wtpState, int fd_wtp, struct sockaddr_un hostapd_addr){
	fd_set fds; 
	char buffer[8] = {0};
	struct timeval tv_out;
	int ret = CW_FAIL;
	
	while(1){
		if(*(int *)wtpState != CW_ENTER_RUN){
			sleep(1);
			continue;
		}

		FD_ZERO(&fds);
		FD_SET(fd_wtp,&fds);
		tv_out.tv_sec = 3;//等待10秒
		tv_out.tv_usec = 0;
		
		memset(buffer, 0, sizeof(buffer));
		strcpy(buffer, "wtp");
		sendto(fd_wtp, buffer, strlen(buffer), 0, (struct sockaddr *)&hostapd_addr, sizeof(struct sockaddr_un));

		ret = select(fd_wtp+1, &fds, NULL, NULL, &tv_out);
		if(ret == 0)
		{
			continue;
		}
		else if(ret < 0)
		{
			return CW_FAIL;
		}
		else
		{
			if(FD_ISSET(fd_wtp,&fds))
			{
				memset(buffer, 0, sizeof(buffer));
				recvfrom(fd_wtp, buffer, sizeof(buffer), 0,NULL, NULL);
				printf("recv buffer from hostapd:%s\n", buffer);
				if(!memcmp(buffer, "hostapd", 7))
				{
					break;
				}
			}
		}
	}
	return CW_OK;
}
#endif
static int delayWaitPkg(int *seq, struct sockaddr_un *hostapd_data_addr, const unsigned char *sa){
	int count = 0;
	unsigned char auth_ret_str[7] = {0};
	
	while(1){
		if(*seq != seqNum){
			usleep(10000);
			count ++;
			if(count >= 200)
				break;
			continue;
		}else{
			break;
		}
	}
	
	if(count >= 200){
        
//		auth_ret = HOSTAPD_ACL_ACCEPT_TIMEOUT;
//		sendto(fd_wtp, &auth_ret, sizeof(auth_ret), 0, (struct sockaddr *)hostapd_data_addr, sizeof(struct sockaddr_un));
		auth_ret_str[0] = HOSTAPD_ACL_ACCEPT_TIMEOUT;

		memcpy(&auth_ret_str[1], sa, 6);
		sendto(fd_wtp, auth_ret_str, sizeof(auth_ret_str), 0, (struct sockaddr *)hostapd_data_addr, sizeof(struct sockaddr_un));
        
		return -1;
	}
	
	return 0;
}

void compareMax(int param, int *max)
{
	if(param > *max)
		*max = param;
}

int staSSIDCmpFromAclSSID(unsigned char *stassid)
{
	int ret = 0;
	char buffer[64] = {0};
	int i = 0;

	sprintf(buffer, "%s,", stassid);
//	CWLog("#######find %s from %s", stassid, gAclssid);
	if(strstr(gAclssid, buffer)){
		ret = 1;
	}

	return ret;
}
int staVlanFindFromAclVlan(unsigned short vlanId, int cardId)
{
	int i = 0;
	int ret = 0;

	for(i = 0;i < 8;i ++){
		if(!gAclVlanCfg[i+(cardId-1)*8])
			break;
//		CWLog("#######sta vlan=%d, list %d = %d, cardId = %d", vlanId, i+(cardId-1)*8, gAclVlanCfg[i+(cardId-1)*8], cardId);
		if(gAclVlanCfg[i+(cardId-1)*8] == vlanId){
			ret = 1;
			break;
		}
	}
	
//	CWLog("#######sta vlan ret = %d", ret);

	return ret;
}

/*< 黑白名单处理线程*/
CW_THREAD_RETURN_TYPE CWControlAcl(void *arg){
	int ret = CW_OK;
	int waitreponscount = 0;
	struct sockaddr_un local_1;
	struct sockaddr_un localdata_1;
	struct sockaddr_un local_2;
	struct sockaddr_un localdata_2;
	unsigned char authMac[6] = {0};
	char buffer[16] = {0};
	struct sockaddr_un hostapd_addr_1;
	struct sockaddr_un hostapd_addr_2;
	struct sockaddr_un hostapd_data_addr_1;
	struct sockaddr_un hostapd_data_addr_2;
	struct sockaddr_un *hostapd_data_addr = NULL;
	char shakeflag = 0;
	char WTPName[64] = {0};
	int maxsock = 0;
	/*< 开启SSID ACL时，未在配置列表内的SSID下的STA关联请求，无需上报AC*/
//	char localAuthRes = 0;
	/*< 开启VLAN ACL时，用户所在的vlanid*/
	unsigned short vlanId = 0;
	unsigned char auth_ret_str[7] = {0};

	fd_set fds; 
	struct timeval tv_out;

	struct dtt_acl_wtp_data aclWtpData;

	/*< 设置为线程分离*/
	pthread_detach(pthread_self());

	/*< 负责卡1与hostapd通信*/
	unlink(WTP_UNIXSOCK_PATH_1);
	unlink(WTP_UNIXSOCK_PATH_DATA_1);

	/*< 负责卡2与hostapd通信
	unlink(WTP_UNIXSOCK_PATH_2);
	unlink(WTP_UNIXSOCK_PATH_DATA_2);*/


	fd_wtp_1 = socket(AF_UNIX, SOCK_DGRAM, 0);
	compareMax(fd_wtp_1, &maxsock);
    
	//fd_wtp_2 = socket(AF_UNIX, SOCK_DGRAM, 0);
	//compareMax(fd_wtp_2, &maxsock);
    
	fd_wtp_data_1 = socket(AF_UNIX, SOCK_DGRAM, 0);
	compareMax(fd_wtp_data_1, &maxsock);
    
	//fd_wtp_data_2 = socket(AF_UNIX, SOCK_DGRAM, 0);
	//compareMax(fd_wtp_data_2, &maxsock);
	
	hostapd_addr_1.sun_family = AF_UNIX;
	//hostapd_addr_2.sun_family = AF_UNIX;
	hostapd_data_addr_1.sun_family = AF_UNIX;
	//hostapd_data_addr_2.sun_family = AF_UNIX;
	
	strcpy(hostapd_addr_1.sun_path, HOSTAPD_UNIXSOCK_PATH_1);
	strcpy(hostapd_data_addr_1.sun_path, HOSTAPD_UNIXSOCK_PATH_DATA_1);

	//strcpy(hostapd_addr_2.sun_path, HOSTAPD_UNIXSOCK_PATH_2);
	//strcpy(hostapd_data_addr_2.sun_path, HOSTAPD_UNIXSOCK_PATH_DATA_2);
	

	local_1.sun_family = AF_UNIX;
	localdata_1.sun_family = AF_UNIX;
	strcpy(local_1.sun_path, WTP_UNIXSOCK_PATH_1);
	strcpy(localdata_1.sun_path, WTP_UNIXSOCK_PATH_DATA_1);

	//local_2.sun_family = AF_UNIX;
	//localdata_2.sun_family = AF_UNIX;
	//strcpy(local_2.sun_path, WTP_UNIXSOCK_PATH_2);
	//strcpy(localdata_2.sun_path, WTP_UNIXSOCK_PATH_DATA_2);
	

	if (bind(fd_wtp_1, (struct sockaddr *)&local_1, strlen(local_1.sun_path) + sizeof(local_1.sun_family)) < 0) {
		CWDTTLog("%s socket bind error %d %s\n", local_1.sun_path, errno, strerror(errno));
		return NULL;
	}
    /*
	if (bind(fd_wtp_2, (struct sockaddr *)&local_2, strlen(local_2.sun_path) + sizeof(local_2.sun_family)) < 0) {
		CWDTTLog("%s socket bind error %d %s\n", local_2.sun_path, errno, strerror(errno));
		return NULL;
	}
	*/
	if (bind(fd_wtp_data_1, (struct sockaddr *)&localdata_1, strlen(localdata_1.sun_path) + sizeof(localdata_1.sun_family)) < 0) {
		CWDTTLog("%s socket bind error %d %s\n", localdata_1.sun_path, errno, strerror(errno));
		return NULL;
	}
    /*
	if (bind(fd_wtp_data_2, (struct sockaddr *)&localdata_2, strlen(localdata_2.sun_path) + sizeof(localdata_2.sun_family)) < 0) {
		CWDTTLog("%s socket bind error %d %s\n", localdata_2.sun_path, errno, strerror(errno));
		return NULL;
	}
    */
	CWDTTLog("Init dtt acl thread success!");
	while(1){
		if(doOffAcl){
			strcpy(buffer, "off");
			sendto(fd_wtp_1, buffer, strlen(buffer), 0, (struct sockaddr *)&hostapd_addr_1, sizeof(struct sockaddr_un));
            CWDTTLog("send acl switch off to hostapd");
			//sendto(fd_wtp_2, buffer, strlen(buffer), 0, (struct sockaddr *)&hostapd_addr_2, sizeof(struct sockaddr_un));
			doOffAcl = 0;
		}
        
		if(*(int *)arg != CW_ENTER_RUN || !getACLSwitch()){
			sleep(1);
			continue;
		}
        
		seqNum = -1;
		configResponseFlag = 0;

		FD_ZERO(&fds);
		FD_SET(fd_wtp_1,&fds);
		//FD_SET(fd_wtp_2,&fds);
		FD_SET(fd_wtp_data_1,&fds);
		//FD_SET(fd_wtp_data_2,&fds);
		tv_out.tv_sec = 3;//等待3秒
		tv_out.tv_usec = 0;
		
		if(!shakeflag){
			memset(buffer, 0, sizeof(buffer));
			strcpy(buffer, "wtp");
			sendto(fd_wtp_1, buffer, strlen(buffer), 0, (struct sockaddr *)&hostapd_addr_1, sizeof(struct sockaddr_un));
			//sendto(fd_wtp_2, buffer, strlen(buffer), 0, (struct sockaddr *)&hostapd_addr_2, sizeof(struct sockaddr_un));
            CWDTTLog("acl send wtp to hostapd!");
			shakeflag = 1;
		}
		ret = select((maxsock+1), &fds, NULL, NULL, &tv_out);
		if(ret == 0)
		{
			continue;
		}
		else if(ret < 0)
		{
			break;
		}
		else
		{
			if(FD_ISSET(fd_wtp_data_1, &fds)){
				memset(&aclWtpData, 0, sizeof(struct dtt_acl_wtp_data));
				recvfrom(fd_wtp_data_1, &aclWtpData, sizeof(aclWtpData), 0,NULL, NULL);
				fd_wtp = fd_wtp_data_1;
				hostapd_data_addr = &hostapd_data_addr_1;
			}
            /*
            else if(FD_ISSET(fd_wtp_data_2, &fds)){
				memset(&aclWtpData, 0, sizeof(struct dtt_acl_wtp_data));
				recvfrom(fd_wtp_data_2, &aclWtpData, sizeof(aclWtpData), 0,NULL, NULL);
				fd_wtp = fd_wtp_data_2;
				hostapd_data_addr = &hostapd_data_addr_2;
			}*/
			else if(FD_ISSET(fd_wtp_1, &fds))
			{
				memset(buffer, 0, sizeof(buffer));
				recvfrom(fd_wtp_1, buffer, sizeof(buffer), 0,NULL, NULL);
				CWDTTLog("**************shake recv buffer from hostapd 1 : %s\n", buffer);
				if(!memcmp(buffer, "hostapd", 7))
				{
					memset(buffer, 0, sizeof(buffer));
					strcpy(buffer, "wtp");
                    CWDTTLog("acl send wtp to hostapd!");
					sendto(fd_wtp_1, buffer, strlen(buffer), 0, (struct sockaddr *)&hostapd_addr_1, sizeof(struct sockaddr_un));
					continue;
				}
			}
            /*
            else if(FD_ISSET(fd_wtp_2, &fds)){
				memset(buffer, 0, sizeof(buffer));
				recvfrom(fd_wtp_2, buffer, sizeof(buffer), 0,NULL, NULL);
				CWDTTLog("**************shake recv buffer from hostapd 2 : %s\n", buffer);
				if(!memcmp(buffer, "hostapd", 7))
				{
					memset(buffer, 0, sizeof(buffer));
					strcpy(buffer, "wtp");
					//sendto(fd_wtp_2, buffer, strlen(buffer), 0, (struct sockaddr *)&hostapd_addr_2, sizeof(struct sockaddr_un));
					continue;
				}
			}*/
			else{
				continue;
			}
            
		}
		/*< 期间，AC可能会下发配置，修改SSID列表，所以加锁*/
		ACLSSIDEditLock();
		
		memset(authMac, 0, sizeof(authMac));
		memcpy(authMac, aclWtpData.sa, 6);
		memcpy(&auth_ret_str[1], authMac, 6);

        
		if(SSID_ACL_ON == getACLSwitch() && !staSSIDCmpFromAclSSID(aclWtpData.ssid)){
//			localAuthRes = HOSTAPD_ACL_ACCEPT;
//			sendto(fd_wtp, &localAuthRes, sizeof(char), 0, (struct sockaddr *)hostapd_data_addr, sizeof(struct sockaddr_un));
			auth_ret_str[0] = HOSTAPD_ACL_ACCEPT;
			sendto(fd_wtp, auth_ret_str, sizeof(auth_ret_str), 0, (struct sockaddr *)hostapd_data_addr, sizeof(struct sockaddr_un));
			ACLSSIDEditUnLock();
			continue;
		}

		if(VLAN_ACL_ON == getACLSwitch())
		{
			//vlanId = getVlanIDFromWlanId(aclWtpData.vapId, fd_wtp == fd_wtp_data_1 ? 1 : 2);
			vlanId = getVlanIDFromWlanId(aclWtpData.vapId, aclWtpData.phyId+1);
            //CWDTTLog("**************vlan acl vlanid: %d\n", vlanId);
		}

        
		//if(VLAN_ACL_ON == getACLSwitch() && !staVlanFindFromAclVlan(vlanId, fd_wtp == fd_wtp_data_1 ? 1 : 2)){
		if(VLAN_ACL_ON == getACLSwitch() && !staVlanFindFromAclVlan(vlanId, aclWtpData.phyId+1)){
//			localAuthRes = HOSTAPD_ACL_ACCEPT;
//			sendto(fd_wtp, &localAuthRes, sizeof(char), 0, (struct sockaddr *)hostapd_data_addr, sizeof(struct sockaddr_un));
			auth_ret_str[0] = HOSTAPD_ACL_ACCEPT;
			sendto(fd_wtp, auth_ret_str, sizeof(auth_ret_str), 0, (struct sockaddr *)hostapd_data_addr, sizeof(struct sockaddr_un));
			ACLSSIDEditUnLock();
			continue;
		}
#if 0
		getWTPName(NULL, WTPName, 32);
		/*< 发送wtp trap报文*/
		sendTrapStaOnline(gWtpPublicInfo.ethMac, WTPName, authMac);
		/*< 等待AC下发reponse报文,2s超时*/
		if(delayWaitPkg(getWTPEventReponseSeqnum(), hostapd_data_addr, authMac) < 0)
			continue;
#endif
		if(!sendAuthRequestToAC(&aclWtpData, getACLSwitch(), vlanId)){
//			localAuthRes = HOSTAPD_ACL_REJECT;
//			sendto(fd_wtp, &localAuthRes, sizeof(char), 0, (struct sockaddr *)hostapd_data_addr, sizeof(struct sockaddr_un));
			auth_ret_str[0] = HOSTAPD_ACL_REJECT;
			sendto(fd_wtp, auth_ret_str, sizeof(auth_ret_str), 0, (struct sockaddr *)hostapd_data_addr, sizeof(struct sockaddr_un));
            
			ACLSSIDEditUnLock();
			continue;

		}
        
		ACLSSIDEditUnLock();

        
        
		/*< 等待第二帧wtp event response*/
        
		if(delayWaitPkg(getWTPEventReponseSeqnum(), hostapd_data_addr, authMac) < 0)
			continue;
        
		/*< 第二帧wtp event reponse到后，AC已下发认证结果*/
		if(!memcmp(aclAuthStaInfo.mac, authMac, sizeof(authMac))){
			CWDTTLog("auth STA MAC:"MACSTR" - result:%s", MAC2STR(authMac), aclAuthStaInfo.aclAuthRes?"accept":"reject");
//			sendto(fd_wtp, &aclAuthStaInfo.aclAuthRes, sizeof(char), 0, (struct sockaddr *)hostapd_data_addr, sizeof(struct sockaddr_un));
			auth_ret_str[0] = aclAuthStaInfo.aclAuthRes;
			sendto(fd_wtp, auth_ret_str, sizeof(auth_ret_str), 0, (struct sockaddr *)hostapd_data_addr, sizeof(struct sockaddr_un));
            
		}
		
		/*< 等待wtp回应完config update包，再进入下个循环*/
		waitreponscount = 0;
		while(!configResponseFlag){
			usleep(100000);
			waitreponscount ++;
			if(waitreponscount > 30){
				CWDTTLog("wait config update reponse timeout");
				break;
			}
		}
        
	}
	return NULL;
}

