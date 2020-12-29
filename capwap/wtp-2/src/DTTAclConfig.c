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
int fd_wtp_data = -1;

int getauthContrFd(){
	return fd_wtp;
}
int getauthDataFd(){
	return fd_wtp_data;
}

int setConfigUpdateReponseCond(int flag){
	return configResponseFlag = flag;
}
void setAclAuthResultInfo(aclControlCfg *pinfo){
	memset(&aclAuthStaInfo, 0, sizeof(aclAuthStaInfo));
	memcpy(&aclAuthStaInfo, pinfo, sizeof(aclAuthStaInfo));
}

void setACLSwitch(int flag){
	if(aclSwitch == 1 && flag == 0){
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

static CWBool sendAuthRequestToAC(unsigned char *staMac){
	/*< 发送认证请求包，内容为mac地址，6字节*/
	sendWTPEventPkg(CW_DTT_MSG_ELEMENT_CONFIG_AP_ASK_AC_AUTH_MACADDR, staMac, 6);
	
	return CW_TRUE;
}
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

static int delayWaitPkg(int *seq, struct sockaddr_un *hostapd_data_addr){
	int count = 0;
	char auth_ret = 0;
	
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
		auth_ret = HOSTAPD_ACL_ACCEPT_TIMEOUT;
		sendto(fd_wtp, &auth_ret, sizeof(auth_ret), 0, (struct sockaddr *)hostapd_data_addr, sizeof(struct sockaddr_un));
		return -1;
	}
	
	return 0;
}
/*< 黑白名单处理线程*/
CW_THREAD_RETURN_TYPE CWControlAcl(void *arg){
	int ret = CW_OK;
	int waitreponscount = 0;
	struct sockaddr_un local;
	struct sockaddr_un localdata;
	unsigned char authMac[6] = {0};
	char buffer[16] = {0};
	struct sockaddr_un hostapd_addr;
	struct sockaddr_un hostapd_data_addr;
	char shakeflag = 0;
	char WTPName[64] = {0};

	fd_set fds; 
	struct timeval tv_out;

	/*< 设置为线程分离*/
	pthread_detach(pthread_self());

	if(1 == gAPIndex){
		unlink(WTP_UNIXSOCK_PATH_1);
		unlink(WTP_UNIXSOCK_PATH_DATA_1);
	}
	else{
		unlink(WTP_UNIXSOCK_PATH_2);
		unlink(WTP_UNIXSOCK_PATH_DATA_2);
	}

	fd_wtp = socket(AF_UNIX, SOCK_DGRAM, 0);
	fd_wtp_data = socket(AF_UNIX, SOCK_DGRAM, 0);
	
	hostapd_addr.sun_family = AF_UNIX;
	hostapd_data_addr.sun_family = AF_UNIX;
	if(1 == gAPIndex){
		strcpy(hostapd_addr.sun_path, HOSTAPD_UNIXSOCK_PATH_1);
		strcpy(hostapd_data_addr.sun_path, HOSTAPD_UNIXSOCK_PATH_DATA_1);
	}
	else{
		strcpy(hostapd_addr.sun_path, HOSTAPD_UNIXSOCK_PATH_2);
		strcpy(hostapd_data_addr.sun_path, HOSTAPD_UNIXSOCK_PATH_DATA_2);
	}

	local.sun_family = AF_UNIX;
	localdata.sun_family = AF_UNIX;
	if(1 == gAPIndex){
		strcpy(local.sun_path, WTP_UNIXSOCK_PATH_1);
		strcpy(localdata.sun_path, WTP_UNIXSOCK_PATH_DATA_1);
	}
	else{
		strcpy(local.sun_path, WTP_UNIXSOCK_PATH_2);
		strcpy(localdata.sun_path, WTP_UNIXSOCK_PATH_DATA_2);
	}

	if (bind(fd_wtp, (struct sockaddr *)&local, strlen(local.sun_path) + sizeof(local.sun_family)) < 0) {
		CWDTTLog("%s socket bind error %d %s\n", local.sun_path, errno, strerror(errno));
		return NULL;
	}
	if (bind(fd_wtp_data, (struct sockaddr *)&localdata, strlen(localdata.sun_path) + sizeof(localdata.sun_family)) < 0) {
		CWDTTLog("%s socket bind error %d %s\n", local.sun_path, errno, strerror(errno));
		return NULL;
	}

	CWDTTLog("Init dtt acl thread success!");
	while(1){
		if(doOffAcl){
			strcpy(buffer, "off");
			sendto(fd_wtp, buffer, strlen(buffer), 0, (struct sockaddr *)&hostapd_addr, sizeof(struct sockaddr_un));
			doOffAcl = 0;
		}
		if(*(int *)arg != CW_ENTER_RUN || !getACLSwitch()){
			sleep(1);
			continue;
		}
		seqNum = -1;
		configResponseFlag = 0;

		FD_ZERO(&fds);
		FD_SET(fd_wtp,&fds);
		FD_SET(fd_wtp_data,&fds);
		tv_out.tv_sec = 3;//等待3秒
		tv_out.tv_usec = 0;
		
		if(!shakeflag){
			memset(buffer, 0, sizeof(buffer));
			strcpy(buffer, "wtp");
			sendto(fd_wtp, buffer, strlen(buffer), 0, (struct sockaddr *)&hostapd_addr, sizeof(struct sockaddr_un));
			
			shakeflag = 1;
		}
		ret = select(((fd_wtp_data > fd_wtp) ? (fd_wtp_data) : (fd_wtp))+1, &fds, NULL, NULL, &tv_out);
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
			if(FD_ISSET(fd_wtp_data, &fds)){
				memset(authMac, 0, sizeof(authMac));
				recvfrom(fd_wtp_data, authMac, sizeof(authMac), 0,NULL, NULL);
			}else if(FD_ISSET(fd_wtp, &fds))
			{
				memset(buffer, 0, sizeof(buffer));
				recvfrom(fd_wtp, buffer, sizeof(buffer), 0,NULL, NULL);
				CWDTTLog("shake recv buffer from hostapd:%s\n", buffer);
				if(!memcmp(buffer, "hostapd", 7))
				{
					memset(buffer, 0, sizeof(buffer));
					strcpy(buffer, "wtp");
					sendto(fd_wtp, buffer, strlen(buffer), 0, (struct sockaddr *)&hostapd_addr, sizeof(struct sockaddr_un));
					continue;
				}
			}else{
				continue;
			}
		}
		getWTPName(NULL, WTPName, 32);
		/*< 发送wtp trap报文*/
		sendTrapStaOnline(g_DevMAC, WTPName, authMac);
		/*< 等待AC下发reponse报文,2s超时*/
		if(delayWaitPkg(getWTPEventReponseSeqnum(), &hostapd_data_addr) < 0)
			continue;
		sendAuthRequestToAC(authMac);
		/*< 等待第二帧wtp event response*/
		if(delayWaitPkg(getWTPEventReponseSeqnum(), &hostapd_data_addr) < 0)
			continue;
		/*< 第二帧wtp event reponse到后，AC已下发认证结果*/
		if(!memcmp(aclAuthStaInfo.mac, authMac, sizeof(authMac))){
			CWDTTLog("auth STA MAC:"MACSTR" - result:%s", MAC2STR(authMac), aclAuthStaInfo.aclAuthRes?"accept":"reject");
			sendto(fd_wtp, &aclAuthStaInfo.aclAuthRes, sizeof(char), 0, (struct sockaddr *)&hostapd_data_addr, sizeof(struct sockaddr_un));
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

