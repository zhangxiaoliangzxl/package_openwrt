/************************************************************************************************
 * Copyright (c) 2006-2009 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica	*
 *                          Universita' Campus BioMedico - Italy								*
 *																								*
 * This program is free software; you can redistribute it and/or modify it under the terms		*
 * of the GNU General Public License as published by the Free Software Foundation; either		*
 * version 2 of the License, or (at your option) any later version.								*
 *																								*
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY				*
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A				*
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.						*
 *																								*
 * You should have received a copy of the GNU General Public License along with this			*
 * program; if not, write to the:																*
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,							*
 * MA  02111-1307, USA.																			*
 *																								*
 * -------------------------------------------------------------------------------------------- *
 * Project:  Capwap																				*
 *																								*
 * Authors : Ludovico Rossi (ludo@bluepixysw.com)												*  
 *           Del Moro Andrea (andrea_delmoro@libero.it)											*
 *           Giovannini Federica (giovannini.federica@gmail.com)								*
 *           Massimo Vellucci (m.vellucci@unicampus.it)											*
 *           Mauro Bisson (mauro.bis@gmail.com)													*
 *	         Antonio Davoli (antonio.davoli@gmail.com)											*
 ************************************************************************************************/

#include "CWWTP.h"
#include "DTTConfigbin.h"
#include "DTTKmodCommunicate.h"
#include "DTTAclConfig.h"
#include "DTTWltp.h"
#include "DTTConfigUpdate.h"
#include <sys/param.h>

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

//#define MAX_VAP 8
//#define UCI_CMD_LENGTH 128
/* not need set dhcp */
#define UCI_ADD_INTERFACE(cmd, id)	\
				{memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "uci set network.vlan%d=interface", id);\
				system(cmd);\
				memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "uci set network.vlan%d.ifname=eth0.%d", id, id);\
				system(cmd);\
				memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "uci set network.vlan%d.proto=none", id);\
				system(cmd);\
				memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "uci set network.vlan%d.type=bridge", id);\
				system(cmd);\
				memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "uci set network.vlan%d.disabled=1", id);\
				system(cmd);}

CW_THREAD_RETURN_TYPE CWWltpSendPkt(void *arg);
CW_THREAD_RETURN_TYPE CWWltpReceivePkt(void *arg);
/*< AP发现AC的方式，共4种: 1.静态地址；2.Option43； 3.dns；4.广播地址*/
int gAPFoundACType = WTP_FOUND_AC_TYPE_INIT;

int 	gEnabledLog;
int 	gMaxLogFileSize;
char 	gLogFileName[32] = {0};

/* addresses of ACs for Discovery */
char	**gCWACAddresses;
/*< 配置文件中所配置的AC地址个数*/
char gCWAPCardCount = 0;

int gIPv4StatusDuplicate = 0;
int gIPv6StatusDuplicate = 0;

char *gWTPLocation = NULL;
char *gWTPName = NULL;
/*< 当为双频设备时，第一个WTP进程的gAPIndex为1，管理AP以及2.4G，第二个进程gAPIndex为2，管理5.8G*/
char gAPIndex = -1;
char g_DevModel[64] = {0};
char g_DevMAC[64] = {0};
char g_SlaveDevMAC[64] = {0};
char g_DevSn[64] = {0};
/*< 硬件型号和版本型号*/
char g_DevHwMode[48] = {0};
char g_DevFwMode[48] = {0};
/*< 隐藏版本号*/
char g_DevHideFwMode[48] = {0};
/*< br-lan卡的ip*/
char g_DevIP[32] = {0};

unsigned int g_WtpMaxTxpower = 0;

/* if not NULL, jump Discovery and use this address for Joining */
CWAuthSecurity 	gWTPForceSecurity;

/* UDP network socket */
CWSocket 		gWTPSocket = -1;
CWSocket 		gWTPDataSocket = -1;
/* DTLS session vars */
CWSecurityContext	gWTPSecurityContext;
CWSecuritySession 	gWTPSession;

/* list used to pass frames from wireless interface to main thread */
CWSafeList 		gFrameList;

/* list used to pass CAPWAP packets from AC to main thread */
CWSafeList 		gPacketReceiveList;

/* used to synchronize access to the lists */
CWThreadCondition    gInterfaceWait;
CWThreadMutex 		gInterfaceMutex;
/*< 初始化过程中等待option43*/
CWThreadCondition	gDhcpOption43Wait;
CWThreadMutex	gOption43Mutex;

/* infos about the ACs to discover */
/*< 在申请该结构地址时，申请实际配置AC个数+1个，预留以为给广播地址，gCWACCount为实际个数，
	首先使用option43或者静态配置的IP进行discover查找，一段时间内无任何AC响应，则配置最后一位为广播地址，对gCWACCount+1，重新进行discover*/
CWACFoundCfg *gCWACCfg = NULL;
/* infos on the better AC we discovered so far */
CWACInfoValues *gACInfoPtr = NULL;

/* WTP statistics timer */
int gWTPStatisticsTimer = CW_STATISTIC_TIMER_DEFAULT;

WTPRebootStatisticsInfo gWTPRebootStatistics;
CWWTPRadiosInfo gRadiosInfo;

/* path MTU of the current session */
int gWTPPathMTU = 0;

int gWTPRetransmissionCount;

static char *decodeKey="XADTTelecom";   //加密密钥
#define shift_len       13    //字符位移

CWPendingRequestMessage gPendingRequestMsgs[MAX_PENDING_REQUEST_MSGS];	

CWBool WTPExitOnUpdateCommit = CW_FALSE;
CWBool CWWTPGetAPIndex(char *CardIndex);
static void CWWTPChangeOnlineType();

/* 
 * Receive a message, that can be fragmented. This is useful not only for the Join State
 */
CWBool CWReceiveMessage(CWProtocolMessage *msgPtr) {
	CWList fragments = NULL;
	int readBytes;
	char buf[CW_BUFFER_SIZE];
	
	CW_REPEAT_FOREVER {
		CW_ZERO_MEMORY(buf, CW_BUFFER_SIZE);
#ifdef CW_NO_DTLS
		char *pkt_buffer = NULL;

		CWLockSafeList(gPacketReceiveList);

		while (CWGetCountElementFromSafeList(gPacketReceiveList) == 0)
			CWWaitElementFromSafeList(gPacketReceiveList);

		pkt_buffer = (char*)CWRemoveHeadElementFromSafeList(gPacketReceiveList, &readBytes);

		CWUnlockSafeList(gPacketReceiveList);

		CW_COPY_MEMORY(buf, pkt_buffer, readBytes);
		CW_FREE_OBJECT(pkt_buffer);
#else
		if(!CWSecurityReceive(gWTPSession, buf, CW_BUFFER_SIZE, &readBytes)) {return CW_FALSE;}
#endif
		CWBool dataFlag = CW_FALSE;
		if(!CWProtocolParseFragment(buf, readBytes, &fragments, msgPtr, &dataFlag)) {
			if(CWErrorGetLastErrorCode() == CW_ERROR_NEED_RESOURCE) { // we need at least one more fragment
				continue;
			} else { // error
				CWErrorCode error;
				error=CWErrorGetLastErrorCode();
				switch(error)
				{
					case CW_ERROR_SUCCESS: {CWDebugLog("ERROR: Success"); break;}
					case CW_ERROR_OUT_OF_MEMORY: {CWDebugLog("ERROR: Out of Memory"); break;}
					case CW_ERROR_WRONG_ARG: {CWDebugLog("ERROR: Wrong Argument"); break;}
					case CW_ERROR_INTERRUPTED: {CWDebugLog("ERROR: Interrupted"); break;}
					case CW_ERROR_NEED_RESOURCE: {CWDebugLog("ERROR: Need Resource"); break;}
					case CW_ERROR_COMUNICATING: {CWDebugLog("ERROR: Comunicating"); break;}
					case CW_ERROR_CREATING: {CWDebugLog("ERROR: Creating"); break;}
					case CW_ERROR_GENERAL: {CWDebugLog("ERROR: General"); break;}
					case CW_ERROR_OPERATION_ABORTED: {CWDebugLog("ERROR: Operation Aborted"); break;}
					case CW_ERROR_SENDING: {CWDebugLog("ERROR: Sending"); break;}
					case CW_ERROR_RECEIVING: {CWDebugLog("ERROR: Receiving"); break;}
					case CW_ERROR_INVALID_FORMAT: {CWDebugLog("ERROR: Invalid Format"); break;}
					case CW_ERROR_TIME_EXPIRED: {CWDebugLog("ERROR: Time Expired"); break;}
					case CW_ERROR_NONE: {CWDebugLog("ERROR: None"); break;}
				}
				CWDebugLog("~~~~~~");
				return CW_FALSE;
			}
		} else break; // the message is fully reassembled
	}
	
	return CW_TRUE;
}

CWBool CWWTPSendAcknowledgedPacket(int seqNum, 
				   CWList msgElemlist,
				   CWBool (assembleFunc)(CWProtocolMessage **, int *, int, int, CWList),
				   CWBool (parseFunc)(char*, int, int, void*), 
				   CWBool (saveFunc)(void*),
				   void *valuesPtr) {

	CWProtocolMessage *messages = NULL;
	CWProtocolMessage msg;
	int fragmentsNum = 0, i;

	struct timespec timewait;
	
	int gTimeToSleep = gCWRetransmitTimer-1;
	int gMaxTimeToSleep = CW_ECHO_INTERVAL_DEFAULT/2;

	msg.msg = NULL;
	
	if(!(assembleFunc(&messages, 
			  &fragmentsNum, 
			  gWTPPathMTU, 
			  seqNum, 
			  msgElemlist))) {

		goto cw_failure;
	}
	
	gWTPRetransmissionCount= 0;
	
	while(gWTPRetransmissionCount < gCWMaxRetransmit) 
	{
		CWDebugLog("Transmission Num:%d", gWTPRetransmissionCount);
		for(i = 0; i < fragmentsNum; i++) 
		{
			if(!CWNetworkSendUnsafeConnected(gWTPSocket, 
							 messages[i].msg,
							 messages[i].offset))
			{
				CWDTTLog("Failure sending Request");
				goto cw_failure;
			}
		}
		
		timewait.tv_sec = time(0) + gTimeToSleep;
		timewait.tv_nsec = 0;

		CW_REPEAT_FOREVER 
		{
			CWThreadMutexLock(&gInterfaceMutex);

			if (CWGetCountElementFromSafeList(gPacketReceiveList) > 0)
				CWErrorRaise(CW_ERROR_SUCCESS, NULL);
			else {
				if (CWErr(CWWaitThreadConditionTimeout(&gInterfaceWait, &gInterfaceMutex, &timewait)))
					CWErrorRaise(CW_ERROR_SUCCESS, NULL);
			}

			CWThreadMutexUnlock(&gInterfaceMutex);

			switch(CWErrorGetLastErrorCode()) {

				case CW_ERROR_TIME_EXPIRED:
				{
					gWTPRetransmissionCount++;
					goto cw_continue_external_loop;
					break;
				}

				case CW_ERROR_SUCCESS:
				{
					/* there's something to read */
					if(!(CWReceiveMessage(&msg))) 
					{
						CW_FREE_PROTOCOL_MESSAGE(msg);
						CWDTTLog("Failure Receiving Response");
						goto cw_failure;
					}
					
					if(!(parseFunc(msg.msg, msg.offset, seqNum, valuesPtr))) 
					{
						if(CWErrorGetLastErrorCode() != CW_ERROR_INVALID_FORMAT) {

							CW_FREE_PROTOCOL_MESSAGE(msg);
							CWDTTLog("Failure Parsing Response");
							goto cw_failure;
						}
						else {
							CWErrorHandleLast();

							gWTPRetransmissionCount++;
							/*< 如果接受到的不是 response包，则直接继续接受，再次超时后，重发 request包*/
							goto cw_continue_get_recv_loop;

//							break;
						}
					}
					
					if((saveFunc(valuesPtr))) {

						goto cw_success;
					} 
					else {
						if(CWErrorGetLastErrorCode() != CW_ERROR_INVALID_FORMAT) {
							CW_FREE_PROTOCOL_MESSAGE(msg);
							CWDTTLog("Failure Saving Response");
							goto cw_failure;
						} 
					}
					break;
				}

				case CW_ERROR_INTERRUPTED: 
				{
					gWTPRetransmissionCount++;
					goto cw_continue_external_loop;
					break;
				}	
				default:
				{
					CWErrorHandleLast();
					CWDTTLog("Failure");
					goto cw_failure;
					break;
				}
			}
			cw_continue_get_recv_loop:
				CWDTTLog("Recv pkg is not the response, recv continue...");
		}
		
		cw_continue_external_loop:
			CWDebugLog("Retransmission time is over");
			
			gTimeToSleep<<=1;
			if ( gTimeToSleep > gMaxTimeToSleep ) gTimeToSleep = gMaxTimeToSleep;
	}

	/* too many retransmissions */
	return CWErrorRaise(CW_ERROR_NEED_RESOURCE, "Peer Dead");
	
cw_success:	
	for(i = 0; i < fragmentsNum; i++) {
		CW_FREE_PROTOCOL_MESSAGE(messages[i]);
	}
	
	CW_FREE_OBJECT(messages);
	CW_FREE_PROTOCOL_MESSAGE(msg);
	
	return CW_TRUE;
	
cw_failure:
	if(messages != NULL) {
		for(i = 0; i < fragmentsNum; i++) {
			CW_FREE_PROTOCOL_MESSAGE(messages[i]);
		}
		CW_FREE_OBJECT(messages);
	}
	CWDebugLog("Failure");
	return CW_FALSE;
}

#if 1
static int change_hex(char pstr[],char bits[]) 
{
    int i,n = 0;
    char mac_tmp[20] = {0};
    char s[20] = {0};

    strcpy(mac_tmp, pstr); 
    sscanf(mac_tmp, "%02X%02X%02X%02X%02X%02X", &s[0],&s[1],&s[2],&s[3],&s[4],&s[5]);
    for(i = 0; s[i]; i += 2) {
        if(s[i] >= 'A' && s[i] <= 'F')
            bits[n] = s[i] - 'A' + 10;
        else if(s[i] >= 'a' && s[i] <= 'f')
            bits[n] = s[i] - 'a' + 10;
        else bits[n] = s[i] - '0';
        
        if(s[i + 1] >= 'A' && s[i + 1] <= 'F')
            bits[n] = (bits[n] << 4) | (s[i + 1] - 'A' + 10);
        else if(s[i + 1] >= 'a' && s[i + 1] <= 'f')
            bits[n] = (bits[n] << 4) | (s[i + 1] - 'a' + 10);
        else bits[n] = (bits[n] << 4) | (s[i + 1] - '0');
        ++n;
        //printf("[%02X %02X]", s[i], s[i + 1]);
    }
    //printf("\n");
    return n;
}
#endif

static CWBool CWSetGlobalParam(){
	FILE *fp = NULL;
	char buffer[128] = {0};
	
    char str[20] = {0};
    int len = 0;

	if(gCWAPCardCount != 1 && gCWAPCardCount != 2){
		CWLog("Can't start WTP, AP Card count parse err! count:%d", gCWAPCardCount);
		return CW_FALSE;
	}

    if(gCWAPCardCount == CW_ONE_CARD)
    {
		/*< 兼容双频，dttConfig分区中的mac地址是wlan1的，所以单频直接去取该MAC*/
        getConfigbinMac("mac", g_DevMAC, 64, "wan");
    }
	else
    {
        if(gAPIndex == 1){
			getConfigbinMac("mac", g_DevMAC, 64, "wlan0");
			getConfigbinMac("mac", g_SlaveDevMAC, 64, "wlan1");
		}else{
			getConfigbinMac("mac", g_DevMAC, 64, "wlan1");
			getConfigbinMac("mac", g_SlaveDevMAC, 64, "wlan0");
		}
	}

	
    /* get mode */
    //getConfigbinInfo("model", g_DevModel, 64, NULL);
    fp = popen("uci get wtp.cfg.device_model", "r");
    if(fp){
		fgets(buffer, sizeof(buffer), fp);
        //buffer[strlen(buffer) - 1] = '\0';
        snprintf(g_DevModel, sizeof(g_DevModel), "%s", buffer);
        pclose(fp);
		fp = NULL;
    }
    else
    {
        return CW_FALSE;
    }
    memset(buffer, 0 ,128);

    /* get sn */
	//getConfigbinInfo("sn", g_DevSn, 64, NULL);
	fp = popen("uci get wtp.cfg.device_sn", "r");
    if(fp){
		fgets(buffer, sizeof(buffer), fp);
        //buffer[strlen(buffer) - 1] = '\0';
        snprintf(g_DevSn, sizeof(g_DevSn), "%s", buffer);
        pclose(fp);
		fp = NULL;
    }
    else
    {
        return CW_FALSE;
    }
    memset(buffer, 0 ,128);

    /* get hwmode */
	//getConfigbinInfo("hwmode", g_DevHwMode, 48, NULL);
    fp = popen("uci get wtp.cfg.device_hw", "r");
    if(fp){
		fgets(buffer, sizeof(buffer), fp);
        //buffer[strlen(buffer) - 1] = '\0';
        snprintf(g_DevHwMode, sizeof(g_DevHwMode), "%s", buffer);
        pclose(fp);
		fp = NULL;
    }
    else
    {
        return CW_FALSE;
    }
    memset(buffer, 0 ,128);

    /* get fwmode */
	//getConfigbinInfo("fwmode", g_DevFwMode, 48, NULL);
	fp = popen("uci get wtp.cfg.device_fw", "r");
    if(fp){
		fgets(buffer, sizeof(buffer), fp);
        //buffer[strlen(buffer) - 1] = '\0';
        snprintf(g_DevFwMode, sizeof(g_DevFwMode), "%s", buffer);
        pclose(fp);
		fp = NULL;
    }
    else
    {
        return CW_FALSE;
    }
    memset(buffer, 0 ,128);
    
    /*
    strcpy(g_DevSn, "V334R126A160000001");
    strcpy(g_DevHwMode, "DTT_QCA9558ED2"); //ZDC_MIPS_ZN7100
    strcpy(g_DevFwMode, "AIROCOV_V2.3.0");
    */
    
    fp = fopen("/etc/dtt_version", "r");
	if(fp){
		fgets(buffer, sizeof(buffer), fp);
		if('\n' == buffer[strlen(buffer)-1])
			buffer[strlen(buffer)-1] = '\0';
		memcpy(g_DevHideFwMode, buffer, sizeof(buffer));
		fclose(fp);
		fp = NULL;
	}
	
	CWLog("gAPIndex:%d, gCWAPCardCount=%d", gAPIndex, gCWAPCardCount);
	while(!CWNetworkGetWTPIP(g_DevIP)){
		/*< 因为需要将设备的IP报给kmod模块，所以直到获取到IP，才继续进行*/
		sleep(1);
		continue;
	}
	CWLog("%02x:%02x:%02x:%02x:%02x:%02x, %d, %s", g_DevMAC[0], g_DevMAC[1], g_DevMAC[2], g_DevMAC[3], g_DevMAC[4], g_DevMAC[5], gCWAPCardCount, g_DevSn);
	return CW_TRUE;

}

static void createEbtablesChain(){
	/*< 本程序设计上，流量必须先流经集中转发链，再流经限速链，因为两者都需要mark，所以在限速链中使用或运算进行标记*/
	/*< 分别创建各自的规则链*/
	if(1 == gAPIndex){
		system("ebtables -t nat -N 24FORWARD -P RETURN");
		system("ebtables -t nat -D PREROUTING -j 24FORWARD");
		system("ebtables -t nat -A PREROUTING -j 24FORWARD");
		/*< 基于SSID上行限速2.4G专用链*/
		system("ebtables -t nat -N QOS_24UPLOAD_CHAIN -P RETURN");
		system("ebtables -t nat -D PREROUTING -j QOS_24UPLOAD_CHAIN");
		system("ebtables -t nat -A PREROUTING -j QOS_24UPLOAD_CHAIN");

		system("ebtables -t nat -N QOS_24DOWNLOAD_CHAIN -P RETURN");
		system("ebtables -t nat -D POSTROUTING -j QOS_24DOWNLOAD_CHAIN");
		system("ebtables -t nat -A POSTROUTING -j QOS_24DOWNLOAD_CHAIN");
	}else{
		system("ebtables -t nat -N 58FORWARD -P RETURN");
		system("ebtables -t nat -D PREROUTING -j 58FORWARD");
		system("ebtables -t nat -A PREROUTING -j 58FORWARD");
		/*< 基于SSID上行限速5.8G专用链*/
		system("ebtables -t nat -N QOS_58UPLOAD_CHAIN -P RETURN");
		system("ebtables -t nat -D PREROUTING -j QOS_58UPLOAD_CHAIN");
		system("ebtables -t nat -A PREROUTING -j QOS_58UPLOAD_CHAIN");
		
		system("ebtables -t nat -N QOS_58DOWNLOAD_CHAIN -P RETURN");
		system("ebtables -t nat -D POSTROUTING -j QOS_58DOWNLOAD_CHAIN");
		system("ebtables -t nat -A POSTROUTING -j QOS_58DOWNLOAD_CHAIN");
	}
	/*< 基于mac限速专用链*/
//	system("ebtables -t nat -N QOS_STA_UPLOAD_CHAIN -P RETURN");
//	system("ebtables -t nat -D PREROUTING -j QOS_STA_UPLOAD_CHAIN");
//	system("ebtables -t nat -A PREROUTING -j QOS_STA_UPLOAD_CHAIN");
	
	return;
}

/*< 初始化network文件，扩展多个vlan*/
static void networkFileInit(void){
	int i = 0;
	char cmd[UCI_CMD_LENGTH] = {0};
	FILE *fp = NULL;
	char buffer[8] = {0};

	for(i = 0;i < MAX_VAP; i++){
		memset(cmd, 0, UCI_CMD_LENGTH);
		sprintf(cmd, "cat /etc/config/network | grep vlan%d | wc -l", i+1+(gAPIndex-1)*MAX_VAP);
		fp=popen(cmd, "r");
		fgets(buffer, 8, fp);
		pclose(fp);
		fp = NULL;
		if(1 == strtol(buffer, NULL, 10))
			continue;
		UCI_ADD_INTERFACE(cmd, i+1+(gAPIndex-1)*MAX_VAP);
	}
	return;
}

/* init wireless config for vap and vlan */
static void wirelessConfInit(void)
{
    int i = 0;
    char cmd[UCI_CMD_LENGTH] = {0};
    FILE *fp = NULL;
    char buffer[8] = {0};
    int num = 0;

    if (gAPIndex != 1)
    {
        return ;
    }
    
    memset(cmd, 0, UCI_CMD_LENGTH);
    sprintf(cmd, "cat /etc/config/wireless | grep wifi-iface | wc -l");
    
    fp=popen(cmd, "r");
    if (NULL != fp)
    {
        fgets(buffer, 8, fp);
        pclose(fp);
        fp = NULL;
    }
    
    /* add wifi-ifcae */
    num = MAX_VAP*2 - strtol(buffer, NULL, 10);

    if (num < 1)
    {
        return ;
    }
    memset(cmd, 0, UCI_CMD_LENGTH);
    sprintf(cmd, "uci add wireless wifi-iface");
    for (i = 0;i < num; i++)
    {
        system(cmd);
    }

    /* set wifi iface , 0-7 wifi0 , 8-15 wifi1 */
    
    for (i = 0;i < 16; i++)
    {
        memset(cmd, 0, UCI_CMD_LENGTH);
        if (i < 8)
        {
            sprintf(cmd, "uci set wireless.@wifi-iface[%d].device=wifi0", i);
        }
        else
        {
            sprintf(cmd, "uci set wireless.@wifi-iface[%d].device=wifi1", i);
        }
        system(cmd);
       
        memset(cmd, 0, UCI_CMD_LENGTH);
        sprintf(cmd, "uci set wireless.@wifi-iface[%d].disabled=1", i);
        system(cmd);
        
        memset(cmd, 0, UCI_CMD_LENGTH);
        sprintf(cmd, "uci set wireless.@wifi-iface[%d].mode=ap", i);
        system(cmd);
    }

    return;
}


#if 0
static void CWGetWTPMaxTxpower()
{
	FILE *fp = NULL;
	char buf[128] = {0};
	char *p = NULL;

	if(g_WtpMaxTxpower != 0)
	{
		return;
	}
	else{
		if(gAPIndex == 1)
			fp = popen("iw phy phy0 info | sed -n '/Frequencies/,/valid interface combinations/p' | sed -e '$d' -e '/disabled/d' | awk 'END {print}'", "r");
		else
			fp = popen("iw phy phy1 info | sed -n '/Frequencies/,/valid interface combinations/p' | sed -e '$d' -e '/disabled/d' | awk 'END {print}'", "r");

		if(fp){
			fgets(buf, 128, fp);
			pclose(fp);
			fp = NULL;
		}
		p = strstr(buf, "(")+1;
		g_WtpMaxTxpower = strtoul(p, NULL, 10);
	//	printf("g_WtpMaxTxpower = %d\n", g_WtpMaxTxpower);

		return;
	}
}
#else
static void CWGetWTPMaxTxpower()
{
	FILE *fp = NULL;
	char buf[128] = {0};

	if(g_WtpMaxTxpower != 0)
	{
		return;
	}
	else{
		if(gAPIndex == 1)
			fp = popen("iwpriv wifi0 getTxPowLim2G | awk -F':' '{print $2/2}'", "r");
		else
			fp = popen("iwpriv wifi1 getTxPowLim5G | awk -F':' '{print $2/2}'", "r");

		if(fp){
			fgets(buf, 128, fp);
			pclose(fp);
			fp = NULL;
		}
		g_WtpMaxTxpower = atoi(buf);
		CWLog("g_WtpMaxTxpower = %d\n", g_WtpMaxTxpower);

		return;
	}
}


#endif
int decrypt(char *str,char *plaintext,int plaintextLen)
{
        if(!str || !plaintext || !plaintextLen)
        {   
                return -1; 
        }   
        int i,j=0;
        int maxlen;
        if(strlen(str) > plaintextLen)
                maxlen = plaintextLen;
        else
                maxlen = strlen(str);
        for(i=0;i< maxlen;i++)
        {   
                for(j=0;j < strlen(decodeKey);j++){
                        plaintext[i]=str[i]^decodeKey[j];
                        plaintext[i]= plaintext[i]-shift_len;
                }   
        }   
        return 0;
 
}

CWBool licenseCheck()
{
	FILE *fp = NULL;
	char password[128] = {0};
	char string[128]={0};
	int i = 0;

	char devMac[6] = {0};
	unsigned int startMac[6] = {0};
    unsigned int endMac[6] = {0};

	fp = fopen("/usr/capwap/capwap.lic", "r");
	if(NULL == fp){
		CWDTTLog("open /usr/capwap/capwap.lic failed, please check the license file");
		return CW_FALSE;
	}
	fread(password, sizeof(password), 1, fp);
	fclose(fp);

	decrypt(password,string,sizeof(password));

	sscanf(string, "%02x:%02x:%02x:%02x:%02x:%02x-%02x:%02x:%02x:%02x:%02x:%02x", startMac, startMac+1, startMac+2,startMac+3,startMac+4,startMac+5, endMac, endMac+1, endMac+2, endMac+3, endMac+4, endMac+5);

	memset(string, 0, sizeof(string));
	getConfigbinInfo("mac", devMac, sizeof(devMac), "wan");

	for(i = 0;i < 6;i ++){
//		CWDTTLog("%d---%d, %d, %d\n", i, (unsigned char)devMac[i], startMac[i], endMac[i]);
		if((unsigned char)devMac[i] > startMac[i] && (unsigned char)devMac[i] < endMac[i]){
			break;
		}else if((unsigned char)devMac[i] > endMac[i] || (unsigned char)devMac[i] < startMac[i] || startMac[i] > endMac[i]){
			i = 7;
			break;
		}else if((unsigned char)devMac[i] == startMac[i] || (unsigned char)devMac[i] == endMac[i]){
			continue;
		}
	}
	if(i > 6){
		CWDTTLog("license file is invalid, please get the correct license file !\n");
		CWDTTLog("Current license for MAC %02x:%02x:%02x:%02x:%02x:%02x-%02x:%02x:%02x:%02x:%02x:%02x\n", startMac[0], startMac[1],startMac[2],startMac[3],startMac[4],startMac[5], endMac[0], endMac[1], endMac[2], endMac[3], endMac[4], endMac[5]);
		CWDTTLog("This AP MAC is %02x:%02x:%02x:%02x:%02x:%02x\n", (unsigned char)devMac[0], (unsigned char)devMac[1], (unsigned char)devMac[2], (unsigned char)devMac[3], (unsigned char)devMac[4], (unsigned char)devMac[5]);
		return CW_FALSE;
	}

	return CW_TRUE;
}

int main(int argc, const char * argv[])
{	
	pid_t pid;
	int i = 0;
	
	if (argc <= 1){
		printf("Usage: WTP working_path\n");
	}
	CWStateTransition nextState = CW_ENTER_DISCOVERY;
#if 1	
	if ((pid = fork()) < 0){
		exit(1);
	}
	else if (pid != 0){
		exit(0);
	}
	else {
		setsid();
//		fclose(stdout);
		if (chdir(argv[1]) != 0)
			exit(1);
		umask(0);
		for(i=0; i<NOFILE;++i){//关闭文件描述符  
			close(i);  
		}
	}	
#endif


	if(!CWWTPGetAPIndex(&gAPIndex)){
		exit(1);
	}
	/*< 双频时，根据此标志位区分，并写不同的log文件*/
	if(gAPIndex == 1){
		CWLogInitFile(WTP_LOG_FILE_NAME_1);
		strcpy(gLogFileName, WTP_LOG_FILE_NAME_1);
	}
	else if(gAPIndex == 2){
		CWLogInitFile(WTP_LOG_FILE_NAME_2);
		strcpy(gLogFileName, WTP_LOG_FILE_NAME_2);
	}else{
		CWLogInitFile(WTP_LOG_FILE_NAME_3);
		strcpy(gLogFileName, WTP_LOG_FILE_NAME_3);
	}
	/*< 共享内存初始化*/
	if(!shareMemInit())
	{
		CWLog("Error Init share memory");
		exit(1);
	}

	/*< 直接加锁，在获取到AP上线方式后，再解锁，为双隧道加锁*/
	APOnlineTypeLock();

	printf("gAPIndex = %d, get lock\n", gAPIndex);

	/*< network文件初始化*/
	networkFileInit();
    wirelessConfInit();
	createEbtablesChain();
	
	CWErrorHandlingInitLib();
	
	if(!CWParseSettingsFile(&g_WtpMaxTxpower)){
		CWLog("Can't start WTP. CWParseSettingsFile failed");
		exit(1);
	}

	CWGetWTPMaxTxpower();

	/* Capwap receive packets list */
	if (!CWErr(CWCreateSafeList(&gPacketReceiveList)))
	{
		CWLog("Can't start WTP. CWCreateSafeList failed");
		exit(1);
	}

	/* Capwap receive frame list */
	if (!CWErr(CWCreateSafeList(&gFrameList)))
	{
		CWLog("Can't start WTP. CWCreateSafeList failed");
		exit(1);
	}

	CWCreateThreadMutex(&gInterfaceMutex);
	CWSetMutexSafeList(gPacketReceiveList, &gInterfaceMutex);
	CWSetMutexSafeList(gFrameList, &gInterfaceMutex);
	CWCreateThreadCondition(&gInterfaceWait);
	CWSetConditionSafeList(gPacketReceiveList, &gInterfaceWait);
	CWSetConditionSafeList(gFrameList, &gInterfaceWait);

	CWCreateThreadMutex(&gOption43Mutex);
	CWCreateThreadCondition(&gDhcpOption43Wait);

	//CWLog("Starting WTP...");
	
	CWRandomInitLib();

	CWThreadSetSignals(SIG_BLOCK, 1, SIGALRM);
	
	if (timer_init() == 0) {
		CWLog("Can't init timer module");
		exit(1);
	}

	if( !CWErr(CWWTPLoadConfiguration()) ) {
		CWLog("Can't start WTP");
		exit(1);
	}
#if 0
	if(!licenseCheck()){
		APOnlineTypeUnLock();
		exit(1);
	}
#endif
	/*< 初始化全局变量，APmac以及次卡mac等*/
	if(!CWErr(CWSetGlobalParam())){
		exit(1);
	}
	CWLog("Starting WTP...");
	/*< 只有第一个进程进行wltp的管理*/
	
	/*< 与内核间通信初始化，以便下发mac地址以及AC的IP地址等*/
	while(kmod_communicate_init(g_DevMAC)){
		/*< 瘦模式下，不管是否是集中转发，都会启动wtp以及kmod，所以，此处等待kmod启动*/
		CWLog("wait for load cloud_wlan_kmod!");
        sleep(1);
		continue;
	}
	if(1 == gAPIndex){
		if(dtt_dispose_pthread_init() < 0){
			CWLog("dtt_dispose_pthread_init pthread init failed!!!");
			exit(1);
		}

		/*< 若未配置静态IP，则等待DHCP的option43，由kmod上报*/
		if(WTP_FOUND_AC_TYPE_INIT == gAPFoundACType)
        {
			CWThreadMutexLock(&gOption43Mutex);
			/*< kmod肯定会发送option信息上来，kmod在拦截到本设备的dhcp信息后，会根据本程序是否已与kmod连接，进行相应处理*/
			if (CWErr(CWWaitThreadCondition(&gDhcpOption43Wait, &gOption43Mutex))){
				CWErrorRaise(CW_ERROR_SUCCESS, NULL);
			}
			CWThreadMutexUnlock(&gOption43Mutex);
			
			if(0 != gCWACCfg->gCWACCount){
				gAPFoundACType = WTP_FOUND_AC_TYPE_OPTION43;
			}
            else
            {
				gCWACCfg->gCWACCount = 1;
				CW_CREATE_ARRAY_ERR(gCWACCfg->gCWACList, gCWACCfg->gCWACCount, CWACDescriptor, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
				
				CW_COPY_MEMORY(gCWACCfg->gCWACList[0].address, "255.255.255.255", strlen("255.255.255.255"));
//				CW_CREATE_STRING_FROM_STRING_ERR(gCWACCfg->gCWACList[0].address, "255.255.255.255", return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
				gAPFoundACType = WTP_FOUND_AC_TYPE_BROADCAST;
			}
		}

	}
    else
    {
		/*< 若非静态的AC IP配置，第二个进程，直接从共享内存里面读取option43信息*/
		if(WTP_FOUND_AC_TYPE_INIT == gAPFoundACType)
        {
			gCWACCfg->gCWACCount = getAPOnlineACCountOption43();
			/*< 先获取option43下发的配置个数，最多4个，若为0，则认为没有开启option43*/
			if(0 != gCWACCfg->gCWACCount){
				gAPFoundACType = WTP_FOUND_AC_TYPE_OPTION43;
				/*< 考虑到AC端可能变更option43配置，这里直接申请4+1个结构*/
	 			CW_CREATE_ARRAY_ERR(gCWACCfg->gCWACList, DHCP_OPTION_43_IP_COUNT+1, CWACDescriptor, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
				getAPOnlineACIPOption43(gCWACCfg->gCWACList);
			}else{
				gCWACCfg->gCWACCount = 1;
				CW_CREATE_ARRAY_ERR(gCWACCfg->gCWACList, gCWACCfg->gCWACCount, CWACDescriptor, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
				CW_COPY_MEMORY(gCWACCfg->gCWACList[0].address, "255.255.255.255", strlen("255.255.255.255"));
//				CW_CREATE_STRING_FROM_STRING_ERR(gCWACCfg->gCWACList[0].address, "255.255.255.255", return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
				gAPFoundACType = WTP_FOUND_AC_TYPE_BROADCAST;
			}
		}
	}
	
	APOnlineTypeUnLock();
	CWLog("##Config AC count is %d, AP online type is %d##", gCWACCfg->gCWACCount, gAPFoundACType);
	if(!CWWTPInitConfiguration())
	{
		CWLog("Error Init Configuration");
		exit(1);
	}
	/*< 集中转发wltp处理已移至kmod中，此处关闭初始化*/
    /***************************************************************************************
	CWThread thread_wltp_sendPkt;
	if(!CWErr(CWCreateThread(&thread_wltp_sendPkt, CWWltpSendPkt, NULL))) {
		CWLog("Error starting Thread that WLTP send packet to data-port");
		exit(1);
	}
	
	CWThread thread_wltp_receivePkt;
	if(!CWErr(CWCreateThread(&thread_wltp_receivePkt, CWWltpReceivePkt, NULL))) {
		CWLog("Error starting Thread that WLTP receive packet on data-port");
		exit(1);
	}
    ***************************************************************************************/
	/*< 开启ACL黑白名单管理线程，因需将sta的认证请求发送到ac端，所以此处开单独线程进行处理*/
	CWThread thread_acl;
    if(!CWErr(CWCreateThread(&thread_acl, CWControlAcl, (void *)&nextState))) 
    {
		CWLog("Error starting Thread that control acl");
        exit(1);
	}
	/* if AC address is given jump Discovery and use this address for Joining */

	/* start CAPWAP state machine */	
	CW_REPEAT_FOREVER {
		switch(nextState) {
			case CW_ENTER_DISCOVERY:
                nextState = CWWTPEnterDiscovery();
				break;
			case CW_ENTER_SULKING:
				nextState = CWWTPEnterSulking();
				/*< discover中长时间不上线处理机制*/
				if(CW_ENTER_DISCOVERY == nextState && gAPFoundACType != WTP_FOUND_AC_TYPE_BROADCAST)
                {
					/*< 在discover的地址列表中添加广播地址*/
					CWLog("## Can't online use the config type, add broadcast addr to discover list, will retry ... ##");
					CWThreadMutexLock(& gCWACCfg->mutex);
					CWWTPChangeOnlineType();
					CWThreadMutexUnlock(& gCWACCfg->mutex);
				}
#if 0
				if(2 == gAPIndex && WTP_FOUND_AC_TYPE_OPTION43 == gAPFoundACType){
					APOnlineTypeLock();
					getAPOnlineACIPOption43(gCWACCfg->gCWACList);
					APOnlineTypeUnLock();
				}
#endif
				break;
			case CW_ENTER_JOIN:
				nextState = CWWTPEnterJoin();
				break;
			case CW_ENTER_CONFIGURE:
				nextState = CWWTPEnterConfigure();
				break;	
			case CW_ENTER_DATA_CHECK:
				nextState = CWWTPEnterDataCheck();
				break;	
			case CW_ENTER_RUN:
				nextState = CWWTPEnterRun();
				break;
			case CW_ENTER_RESET:
				if(1 == gAPIndex)
					WltpKeepAlive_stoptimer();
				CWStopTimers();
				CWNetworkCloseSocket(gWTPSocket);
				CWNetworkCloseSocket(gWTPDataSocket);
				setTrafficLimitFlag();
				/*
				 * CWStopHeartbeatTimer();
				 * CWStopNeighborDeadTimer();
				 * CWNetworkCloseSocket(gWTPSocket);
				 * CWSecurityDestroySession(gWTPSession);
				 * CWSecurityDestroyContext(gWTPSecurityContext);
				 * gWTPSecurityContext = NULL;
				 * gWTPSession = NULL;
				 */
				nextState = CW_ENTER_DISCOVERY;
				break;
			case CW_QUIT:
				CWWTPDestroy();
				return 0;
		}
	}
}

__inline__ unsigned int CWGetSeqNum() {
	static unsigned int seqNum = 0;
	
	if (seqNum==CW_MAX_SEQ_NUM) seqNum=0;
	else seqNum++;
	return seqNum;
}

__inline__ int CWGetFragmentID() {
	static int fragID = 0;
	return fragID++;
}


/* 
 * Parses config file and inits WTP configuration.
 */
CWBool CWWTPLoadConfiguration() {
	int i;
	
	CWLog("WTP Loads Configuration\n");
	
	CW_CREATE_ARRAY_ERR(gCWACCfg, 1, CWACFoundCfg, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	CW_ZERO_MEMORY(gCWACCfg, sizeof(CWACFoundCfg));
	CWCreateThreadMutex(&(gCWACCfg->mutex));
	
	/* get saved preferences */
	if(!CWErr(CWParseConfigFile())) {
		CWLog("Can't Read Config File");
		exit(1);
	}
	
	if(gCWACCfg->gCWACCount == 0){
//		return CWErrorRaise(CW_ERROR_NEED_RESOURCE, "No AC Configured");
		return CW_TRUE;
	}
	else
		gAPFoundACType = WTP_FOUND_AC_TYPE_STATIC;
		
	
	CW_CREATE_ARRAY_ERR(gCWACCfg->gCWACList, 
			    gCWACCfg->gCWACCount+1,
			    CWACDescriptor,
			    return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

	for(i = 0; i < gCWACCfg->gCWACCount; i++) {

		CWLog("Static init Configuration for AC at %s", gCWACAddresses[i]);
		if(!memcmp(gCWACAddresses[i], "255.255.255.255", strlen("255.255.255.255")))
			gCWACCfg->broadcastFlag = 1;
		CW_COPY_MEMORY(gCWACCfg->gCWACList[i].address, gCWACAddresses[i], strlen(gCWACAddresses[i]));
//		CW_CREATE_STRING_FROM_STRING_ERR(gCWACCfg->gCWACList[i].address, gCWACAddresses[i], return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	}
	
	CW_FREE_OBJECTS_ARRAY(gCWACAddresses, gCWACCfg->gCWACCount);
	return CW_TRUE;
}

static void CWWTPChangeOnlineType() {
	if(!gCWACCfg->broadcastFlag){
		CW_COPY_MEMORY(gCWACCfg->gCWACList[gCWACCfg->gCWACCount].address, "255.255.255.255", strlen("255.255.255.255"));
//		CW_CREATE_STRING_FROM_STRING_ERR(gCWACCfg->gCWACList[gCWACCfg->gCWACCount].address, "255.255.255.255", return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		/*< 对gCWACCount+1操作，实际discover时，才会遍历到广播地址*/
		gCWACCfg->gCWACCount ++;
		gCWACCfg->broadcastFlag = 1;
	}
}

void CWWTPDestroy() {
	int i;
	
	CWLog("Destroy WTP");
	
//	for(i = 0; i < gCWACCfg->gCWACCount; i++) {
//		CW_FREE_OBJECT(gCWACCfg->gCWACList[i].address);
//	}
	
	timer_destroy();

	CW_FREE_OBJECT(gCWACCfg->gCWACList);
	CW_FREE_OBJECT(gRadiosInfo.radiosInfo);
}

CWBool CWWTPInitConfiguration() {
	int i;

	CWWTPResetRebootStatistics(&gWTPRebootStatistics);

	gRadiosInfo.radioCount = CWWTPGetMaxRadios();
	CW_CREATE_ARRAY_ERR(gRadiosInfo.radiosInfo, gRadiosInfo.radioCount, CWWTPRadioInfoValues, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	gRadiosInfo.radiosInfo[0].radioID= 0;
	/* gRadiosInfo.radiosInfo[0].numEntries = 0; */
	gRadiosInfo.radiosInfo[0].decryptErrorMACAddressList = NULL;
	gRadiosInfo.radiosInfo[0].reportInterval= CW_REPORT_INTERVAL_DEFAULT;
	gRadiosInfo.radiosInfo[0].adminState= ENABLED;
	gRadiosInfo.radiosInfo[0].adminCause= AD_NORMAL;
	gRadiosInfo.radiosInfo[0].operationalState= ENABLED;
	gRadiosInfo.radiosInfo[0].operationalCause= OP_NORMAL;
	gRadiosInfo.radiosInfo[0].TxQueueLevel= 0;
	gRadiosInfo.radiosInfo[0].wirelessLinkFramesPerSec= 0;
	CWWTPResetRadioStatistics(&(gRadiosInfo.radiosInfo[0].statistics));
	
//	if(!CWWTPInitBinding(0)) {return CW_FALSE;}
	
	for (i=1; i<gRadiosInfo.radioCount; i++)
	{
		gRadiosInfo.radiosInfo[i].radioID= i;
		/* gRadiosInfo.radiosInfo[i].numEntries = 0; */
		gRadiosInfo.radiosInfo[i].decryptErrorMACAddressList = NULL;
		gRadiosInfo.radiosInfo[i].reportInterval= CW_REPORT_INTERVAL_DEFAULT;
		/* Default value for CAPWAP */
		gRadiosInfo.radiosInfo[i].adminState= ENABLED; 
		gRadiosInfo.radiosInfo[i].adminCause= AD_NORMAL;
		gRadiosInfo.radiosInfo[i].operationalState= DISABLED;
		gRadiosInfo.radiosInfo[i].operationalCause= OP_NORMAL;
		gRadiosInfo.radiosInfo[i].TxQueueLevel= 0;
		gRadiosInfo.radiosInfo[i].wirelessLinkFramesPerSec= 0;
		CWWTPResetRadioStatistics(&(gRadiosInfo.radiosInfo[i].statistics));
		if(!CWWTPInitBinding(i)) {return CW_FALSE;}
	}
	
	return CW_TRUE;
}

static CWBool get_selfExeName(char *processname, int len){
	char* path_end;
	char processdir[64] = {0};
	if(readlink("/proc/self/exe", processdir,len) <=0)
			return CW_FALSE;
	path_end = strrchr(processdir,	'/');
	if(path_end == NULL)
			return CW_FALSE;
	++path_end;
	strcpy(processname, path_end);
	*path_end = '\0';

	return CW_TRUE;
}

CWBool CWWTPGetAPIndex(char *CardIndex){
	char processname[16] = {0};
	char cmd[64] = {0};
	char buf[32] = {0};
	FILE *fp = NULL;

	if(!get_selfExeName(processname, sizeof(processname))){
		CWLog("get self exe name failed");
		return CW_FALSE;
	}
	sprintf(cmd, "ps | grep \"%s ./\" | grep -v grep | wc -l", processname);
	fp = popen(cmd, "r");
	if(fp == NULL)
		return CW_FALSE;

	fgets(buf, sizeof(buf), fp);
	buf[strlen(buf)-1] = '\0';
	pclose(fp);
	fp = NULL;

	/*< 第一个进程为2.4G，第二个进程为5.8G*/
	*CardIndex = atoi(buf);
	if(*CardIndex > 2)
		return CW_FALSE;
	
	return CW_TRUE;
}

