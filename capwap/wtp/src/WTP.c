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
#include "CWUciApi.h"

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
				sprintf(cmd, "uci set network.vlan%d.ifname=", id);\
				system(cmd);\
				memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "uci set network.vlan%d.proto=dhcp", id);\
				system(cmd);\
				memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "uci set network.vlan%d.type=bridge", id);\
				system(cmd);\
				memset(cmd, 0, UCI_CMD_LENGTH);\
				sprintf(cmd, "uci set network.vlan%d.disabled=1", id);\
				system(cmd);}

CW_THREAD_RETURN_TYPE CWWltpSendPkt(void *arg);
CW_THREAD_RETURN_TYPE CWWltpReceivePkt(void *arg);
/*< AP·¢ÏÖACµÄ·½Ê½£¬¹²4ÖÖ: 1.¾²Ì¬µØÖ·£»2.Option43£» 3.dns£»4.¹ã²¥µØÖ·*/
int gAPFoundACType = WTP_FOUND_AC_TYPE_INIT;
CWStateTransition wtpState = CW_ENTER_DISCOVERY;
/*< ÒòÎªµ¥ËíµÀ°æ±¾£¬´Ë±êÖ¾Î»ÓÃÓÚ¿ØÖÆµ±Ç°ÉèÖÃµÄradio¿¨£¬0ÎªµÚÒ»ÕÅ¿¨£¬1ÎªµÚ¶þÕÅ¿¨*/
int gRadio = 0;

int 	gEnabledLog;
int 	gMaxLogFileSize;
char 	gLogFileName[32] = {0};

/* addresses of ACs for Discovery */
char	**gCWACAddresses;

int gIPv4StatusDuplicate = 0;
int gIPv6StatusDuplicate = 0;

char *gWTPLocation = NULL;
char *gWTPName = NULL;


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
/*< ³õÊ¼»¯¹ý³ÌÖÐµÈ´ýoption43*/
CWThreadCondition	gDhcpOption43Wait;
CWThreadMutex	gOption43Mutex;

/* infos about the ACs to discover */
/*< ÔÚÉêÇë¸Ã½á¹¹µØÖ·Ê±£¬ÉêÇëÊµ¼ÊÅäÖÃAC¸öÊý+1¸ö£¬Ô¤ÁôÒÔÎª¸ø¹ã²¥µØÖ·£¬gCWACCountÎªÊµ¼Ê¸öÊý£¬
	Ê×ÏÈÊ¹ÓÃoption43»òÕß¾²Ì¬ÅäÖÃµÄIP½øÐÐdiscover²éÕÒ£¬Ò»¶ÎÊ±¼äÄÚÎÞÈÎºÎACÏìÓ¦£¬ÔòÅäÖÃ×îºóÒ»Î»Îª¹ã²¥µØÖ·£¬¶ÔgCWACCount+1£¬ÖØÐÂ½øÐÐdiscover*/
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

CWDTTAllPublicInfo gWtpPublicInfo;

CWPendingRequestMessage gPendingRequestMsgs[MAX_PENDING_REQUEST_MSGS];	

CWBool WTPExitOnUpdateCommit = CW_FALSE;
CWBool CWWTPGetProcessId();
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
							/*< Èç¹û½ÓÊÜµ½µÄ²»ÊÇ response°ü£¬ÔòÖ±½Ó¼ÌÐø½ÓÊÜ£¬ÔÙ´Î³¬Ê±ºó£¬ÖØ·¢ request°ü*/
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

#if 0
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
	
	if(gWtpPublicInfo.cardnum != CW_ONE_CARD && gWtpPublicInfo.cardnum != CW_TWO_CARD){
		CWLog("Can't start WTP, AP Card count parse err! count:%d", gWtpPublicInfo.cardnum);
		return CW_FALSE;
	}

    /* get mode */
	//getConfigbinInfo("model", gWtpPublicInfo.apModel, sizeof(gWtpPublicInfo.apModel), NULL);
    fp = popen("uci get wtp.cfg.device_model | tr -d '\n'", "r");
    if(fp){
        memset(buffer, 0 ,128);
		fgets(buffer, sizeof(buffer), fp);
        snprintf(gWtpPublicInfo.apModel, sizeof(gWtpPublicInfo.apModel), "%s", buffer);
        pclose(fp);
		fp = NULL;
    }
    else
    {
        return CW_FALSE;
    }

    /* get sn */	
	//getConfigbinInfo("sn", gWtpPublicInfo.sn, sizeof(gWtpPublicInfo.sn), NULL);
	fp = popen("uci get wtp.cfg.device_sn", "r");
    if(fp){
        memset(buffer, 0 ,128);
		fgets(buffer, sizeof(buffer), fp);
        snprintf(gWtpPublicInfo.sn, sizeof(gWtpPublicInfo.sn), "%s", buffer);
        pclose(fp);
		fp = NULL;
    }
    else
    {
        return CW_FALSE;
    }
    

    /* get hwmode */	
	//getConfigbinInfo("hwmode", gWtpPublicInfo.hwModel, sizeof(gWtpPublicInfo.hwModel), NULL);
    fp = popen("uci get wtp.cfg.device_hw | tr -d '\n'", "r");
    if(fp){
        memset(buffer, 0 ,128);
		fgets(buffer, sizeof(buffer), fp);
        snprintf(gWtpPublicInfo.hwModel, sizeof(gWtpPublicInfo.hwModel), "%s", buffer);
        pclose(fp);
		fp = NULL;
    }
    else
    {
        return CW_FALSE;
    }

    
    /* get fwmode */
	//getConfigbinInfo("fwmode", gWtpPublicInfo.fwModel, sizeof(gWtpPublicInfo.fwModel), NULL);
	fp = popen("uci get wtp.cfg.device_fw | tr -d '\n'", "r");
    if(fp){
        memset(buffer, 0 ,128);
		fgets(buffer, sizeof(buffer), fp);
        snprintf(gWtpPublicInfo.fwModel, sizeof(gWtpPublicInfo.fwModel), "%s", buffer);
        pclose(fp);
		fp = NULL;
    }
    else
    {
        return CW_FALSE;
    }

	/*
    fp = popen("cat /etc/openwrt_release | grep DISTRIB_DESCRIPTION | cut -d \"'\" -f 2", "r");
	if(fp){
        memset(buffer, 0 ,128);
		fgets(buffer, sizeof(buffer), fp);
		if('\n' == buffer[strlen(buffer)-1])
			buffer[strlen(buffer)-1] = '\0';
		memcpy(gWtpPublicInfo.hideFwMode, buffer, sizeof(buffer));
		pclose(fp);
		fp = NULL;
	}
	*/
	strcpy(gWtpPublicInfo.hideFwMode, "Airocov Openwrt");

	
    /*
    strcpy(g_DevSn, "V334R126A160000001");
    strcpy(g_DevHwMode, "DTT_QCA9558ED2"); //ZDC_MIPS_ZN7100
    strcpy(g_DevFwMode, "AIROCOV_V2.3.0");
    */

    /* eth mac */
    //getConfigbinInfo("mac", gWtpPublicInfo.ethMac, sizeof(gWtpPublicInfo.ethMac), "wan");
    getConfigbinMac("mac", gWtpPublicInfo.ethMac, sizeof(gWtpPublicInfo.ethMac), "wan");

    /* wifi0 mac */
	//getConfigbinInfo("mac", gWtpPublicInfo.wlan0Mac, sizeof(gWtpPublicInfo.wlan0Mac), "wlan0");
	getConfigbinMac("mac", gWtpPublicInfo.wlan0Mac, sizeof(gWtpPublicInfo.wlan0Mac), "wlan0");

    /* wifi1 mac */
	if(gWtpPublicInfo.cardnum == CW_TWO_CARD){
		//getConfigbinInfo("mac", gWtpPublicInfo.wlan1Mac, sizeof(gWtpPublicInfo.wlan1Mac), "wlan1");
		getConfigbinMac("mac", gWtpPublicInfo.wlan1Mac, sizeof(gWtpPublicInfo.wlan1Mac), "wlan1");
    }
		
	while(!CWNetworkGetWTPIP(gWtpPublicInfo.ethIP)){
		/*< ÒòÎªÐèÒª½«Éè±¸µÄIP±¨¸økmodÄ£¿é£¬ËùÒÔÖ±µ½»ñÈ¡µ½IP£¬²Å¼ÌÐø½øÐÐ*/
		sleep(5);
		continue;
	}
    
	return CW_TRUE;

}

/* 
 * ±¾½Ó¿ÚÎªÍ³¼ÆÓÐÏßºÍÎÞÏß¿ÚµÄµ¥²¥ºÍ¹ã²¥°ü£¬Ìí¼Óebtables¹æÔò
 *
 * chain: ²Ù×÷µÄÁ´
 * inout: Í³¼Æ·¢ËÍ1  |  Í³¼Æ½ÓÊÕ0
 */
static void createEbtablesPortStatistic(char *chain, int inout, char index){
	char buf[256] = {0};
	int i = 0;
	char wlan[16] = {0};

	EBTABLES_ADD_UNICAST_STATISTIC_RULE(chain, "eth0");
	EBTABLES_ADD_MULTICAST_STATISTIC_RULE(chain, "eth0");
	EBTABLES_ADD_BROADCAST_STATISTIC_RULE(chain, "eth0");

	for(i = 0; i < MAX_VAP; i++){
		if(index == 1){
			if(i)
				sprintf(wlan, "ath0%d", i);
			else
				sprintf(wlan, "ath0");
		}else{
			if(i)
				sprintf(wlan, "ath1%d", i);
			else
				sprintf(wlan, "ath1");
		}
		
		EBTABLES_ADD_UNICAST_STATISTIC_RULE(chain, wlan);
		EBTABLES_ADD_MULTICAST_STATISTIC_RULE(chain, wlan);
		EBTABLES_ADD_BROADCAST_STATISTIC_RULE(chain, wlan);
	}
	return;
}

static void createEbtablesChain(char APIndex){
	/*< ±¾³ÌÐòÉè¼ÆÉÏ£¬Á÷Á¿±ØÐëÏÈÁ÷¾­¼¯ÖÐ×ª·¢Á´£¬ÔÙÁ÷¾­ÏÞËÙÁ´£¬ÒòÎªÁ½Õß¶¼ÐèÒªmark£¬ËùÒÔÔÚÏÞËÙÁ´ÖÐÊ¹ÓÃ»òÔËËã½øÐÐ±ê¼Ç*/
	/*< ·Ö±ð´´½¨¸÷×ÔµÄ¹æÔòÁ´*/
	if(1 == APIndex){
		system("ebtables -t nat -N 24FORWARD -P RETURN");
		system("ebtables -t nat -D PREROUTING -j 24FORWARD");
		system("ebtables -t nat -A PREROUTING -j 24FORWARD");
		/*< »ùÓÚSSIDÉÏÐÐÏÞËÙ2.4G×¨ÓÃÁ´*/
		system("ebtables -t nat -N QOS_24UPLOAD_CHAIN -P RETURN");
		system("ebtables -t nat -D PREROUTING -j QOS_24UPLOAD_CHAIN");
		system("ebtables -t nat -A PREROUTING -j QOS_24UPLOAD_CHAIN");

		system("ebtables -t nat -N QOS_24DOWNLOAD_CHAIN -P RETURN");
		system("ebtables -t nat -D POSTROUTING -j QOS_24DOWNLOAD_CHAIN");
		system("ebtables -t nat -A POSTROUTING -j QOS_24DOWNLOAD_CHAIN");

		/*< ÎªÍ³¼Æ¸÷¸öÍøÂç½Ó¿ÚÉÏµÄµ¥²¥£¬×é²¥£¬¹ã²¥°üÊý£¬Ôö¼Óebtables¹æÔò½øÐÐÍ³¼Æ*/
		system("ebtables -t filter -N TX_STATISTIC -P RETURN");
		system("ebtables -t filter -N RX_STATISTIC -P RETURN");
		/*< Çå¿ÕÍ³¼ÆÁ´£¬·ÀÖ¹¶à´ÎÌí¼Ó*/
		system("ebtables -F TX_STATISTIC");
		system("ebtables -F RX_STATISTIC");
		/*< ¿¨1ÏÈÆô¶¯£¬ÓÉ¿¨1´´½¨*/
		system("ebtables -D OUTPUT -j TX_STATISTIC");
		system("ebtables -A OUTPUT -j TX_STATISTIC");
		
		system("ebtables -D INPUT -j RX_STATISTIC");
		system("ebtables -A INPUT -j RX_STATISTIC");
	}
    else
    {
		system("ebtables -t nat -N 58FORWARD -P RETURN");
		system("ebtables -t nat -D PREROUTING -j 58FORWARD");
		system("ebtables -t nat -A PREROUTING -j 58FORWARD");
		/*< »ùÓÚSSIDÉÏÐÐÏÞËÙ5.8G×¨ÓÃÁ´*/
		system("ebtables -t nat -N QOS_58UPLOAD_CHAIN -P RETURN");
		system("ebtables -t nat -D PREROUTING -j QOS_58UPLOAD_CHAIN");
		system("ebtables -t nat -A PREROUTING -j QOS_58UPLOAD_CHAIN");
		
		system("ebtables -t nat -N QOS_58DOWNLOAD_CHAIN -P RETURN");
		system("ebtables -t nat -D POSTROUTING -j QOS_58DOWNLOAD_CHAIN");
		system("ebtables -t nat -A POSTROUTING -j QOS_58DOWNLOAD_CHAIN");
	}
	createEbtablesPortStatistic("TX_STATISTIC", 1, 1);
	createEbtablesPortStatistic("RX_STATISTIC", 0, 2);
	/*< »ùÓÚmacÏÞËÙ×¨ÓÃÁ´*/
//	system("ebtables -t nat -N QOS_STA_UPLOAD_CHAIN -P RETURN");
//	system("ebtables -t nat -D PREROUTING -j QOS_STA_UPLOAD_CHAIN");
//	system("ebtables -t nat -A PREROUTING -j QOS_STA_UPLOAD_CHAIN");
	
	return;
}

/*< ³õÊ¼»¯networkÎÄ¼þ£¬À©Õ¹¶à¸övlan*/
static void networkFileInit(void){
	int i = 0;
	char cmd[UCI_CMD_LENGTH] = {0};
	FILE *fp = NULL;
	char buffer[8] = {0};

    memset(cmd, 0, UCI_CMD_LENGTH);
    sprintf(cmd, "cat /etc/config/network | grep \"config interface 'vlan\" | wc -l");
    
    fp=popen(cmd, "r");
    if (NULL != fp)
    {
        fgets(buffer, 8, fp);
        pclose(fp);
        fp = NULL;
    }
    
    if ((MAX_VAP*gWtpPublicInfo.cardnum - strtol(buffer, NULL, 10)) < 1)
    {
        return ;
    }

	for(i = 0;i < (MAX_VAP*gWtpPublicInfo.cardnum); i++){
		memset(cmd, 0, UCI_CMD_LENGTH);
		sprintf(cmd, "cat /etc/config/network | grep vlan%d | wc -l", i+1);
		fp=popen(cmd, "r");
		fgets(buffer, 8, fp);
		pclose(fp);
		fp = NULL;
		if(1 == strtol(buffer, NULL, 10))
			continue;
		UCI_ADD_INTERFACE(cmd, i+1);
	}
    /* save uci config */
    memset(cmd, 0, UCI_CMD_LENGTH);
	sprintf(cmd, "uci commit network");
	fp=popen(cmd, "r");
	pclose(fp);
	fp = NULL;
    
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
    num = MAX_VAP*gWtpPublicInfo.cardnum - strtol(buffer, NULL, 10);

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
    
    for (i = 0;i < MAX_VAP*gWtpPublicInfo.cardnum; i++)
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

    /* save uci config */
    memset(cmd, 0, UCI_CMD_LENGTH);
	sprintf(cmd, "uci commit wireless");
	fp=popen(cmd, "r");
	pclose(fp);
	fp = NULL;
    
    return;
}

#if 0
static unsigned int CWGetWTPMaxTxpower(char APIndex)
{
	FILE *fp = NULL;
	char buf[128] = {0};
	char *p = NULL;
	unsigned int value = 0;
	
	if(APIndex == 1)
		fp = popen("iw phy phy0 info | sed -n '/Frequencies/,/valid interface combinations/p' | sed -e '$d' -e '/disabled/d' | awk 'END {print}'", "r");
	else
		fp = popen("iw phy phy1 info | sed -n '/Frequencies/,/valid interface combinations/p' | sed -e '$d' -e '/disabled/d' | awk 'END {print}'", "r");

	if(fp){
		fgets(buf, 128, fp);
		pclose(fp);
		fp = NULL;
	}
	p = strstr(buf, "(") ? (strstr(buf, "(")+1) : NULL;
	if(p)
		value = strtoul(p, NULL, 10);
	
	return value;
}
#else
static unsigned int CWGetWTPMaxTxpower(char APIndex)
{
	FILE *fp = NULL;
	char buf[128] = {0};
	unsigned int value = 0;

	if(APIndex == 1)
		fp = popen("iwpriv wifi0 getTxPowLim2G | awk -F':' '{print $2/2}'", "r");
	else
		fp = popen("iwpriv wifi1 getTxPowLim5G | awk -F':' '{print $2/2}'", "r");

	if(fp){
		fgets(buf, 128, fp);
		pclose(fp);
		fp = NULL;
	}
    
	value = atoi(buf);
	CWLog("WtpMaxTxpower = %d\n", value);

	return value;
}

#endif

static int CWGetAPCardNum()
{
	FILE *fp = NULL;
	char cmd[64] = {0};
	int value = 0;
	int i = 0;
	char buf[64] = {0};

	while(i < 2){
		sprintf(cmd, UCI_GET_RADIO "%d", i++);
		fp = popen(cmd, "r");
		if(fp){
			fgets(buf, sizeof(buf), fp);
			if(strlen(buf))
				value ++;
			pclose(fp);
			fp = NULL;
			memset(buf, 0, sizeof(buf));
		}
	}
	return value;
}

static void APOnlineTypeInit()
{
	struct timespec timenow;

	timenow.tv_sec = time(0) + 20;	 /* greater than NeighborDeadInterval */
	timenow.tv_nsec = 0;
	/*< ÈôÎ´ÅäÖÃ¾²Ì¬IP£¬ÔòµÈ´ýDHCPµÄoption43£¬ÓÉkmodÉÏ±¨*/
	if(WTP_FOUND_AC_TYPE_INIT == gAPFoundACType){
		printf("wait option 43 from AC ...\n");
		CWThreadMutexLock(&gOption43Mutex);
		/*< kmod¿Ï¶¨»á·¢ËÍoptionÐÅÏ¢ÉÏÀ´£¬kmodÔÚÀ¹½Øµ½±¾Éè±¸µÄdhcpÐÅÏ¢ºó£¬»á¸ù¾Ý±¾³ÌÐòÊÇ·ñÒÑÓëkmodÁ¬½Ó£¬½øÐÐÏàÓ¦´¦Àí*/
		if(CWErr(CWWaitThreadCondition(&gDhcpOption43Wait, &gOption43Mutex))){
//		if (CWErr(CWWaitThreadConditionTimeout(&gDhcpOption43Wait, &gOption43Mutex, &timenow))){
			CWErrorRaise(CW_ERROR_SUCCESS, NULL);
		}
		CWThreadMutexUnlock(&gOption43Mutex);
		
		if(0 != gCWACCfg->gCWACCount){
			gAPFoundACType = WTP_FOUND_AC_TYPE_OPTION43;
		}else{
			gCWACCfg->gCWACCount = 1;
			CW_CREATE_ARRAY_ERR(gCWACCfg->gCWACList, gCWACCfg->gCWACCount, CWACDescriptor, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
			
			CW_COPY_MEMORY(gCWACCfg->gCWACList[0].address, "255.255.255.255", strlen("255.255.255.255"));
//				CW_CREATE_STRING_FROM_STRING_ERR(gCWACCfg->gCWACList[0].address, "255.255.255.255", return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
			gAPFoundACType = WTP_FOUND_AC_TYPE_BROADCAST;
		}
	}

	return;
}

int main(int argc, const char * argv[])
{	
	pid_t pid;
	int i = 0;

	if(!CWWTPGetProcessId()){
        printf("process is running, exit!\n");
		return 0;
    }

//	printf("get ap card num is %d\n", UCIgetRadioCount());
	if (argc <= 1){
		printf("Usage: WTP working_path\n");
	}
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
		for(i=0; i<NOFILE;++i){//¹Ø±ÕÎÄ¼þÃèÊö·û  
            close(i);  
        }
	}	
#endif
	/*< ´ÓUCI»ñÈ¡µ±Ç°Éè±¸µ¥Æµ»òË«Æµ£¬1Îªµ¥Æµ£¬2ÎªË«Æµ*/
	gWtpPublicInfo.cardnum = UCIgetRadioCount();

	/*< ³õÊ¼»¯logÎÄ¼þ*/
	CWLogInitFile(WTP_LOG_FILE_NAME);
	//gWtpPublicInfo.logfile = strdup(WTP_LOG_FILE_NAME);

	gWtpPublicInfo.maxtxpower[0] = CWGetWTPMaxTxpower(1);
	if(2 == gWtpPublicInfo.cardnum)
		gWtpPublicInfo.maxtxpower[1] = CWGetWTPMaxTxpower(2);
#if 0
	/*< ¹²ÏíÄÚ´æ³õÊ¼»¯*/
	if(!shareMemInit())
	{
		CWLog("Error Init share memory");
		exit(1);
	}
#endif
	/*< networkÎÄ¼þ³õÊ¼»¯*/
	networkFileInit();
    /* wireless conf init */
    wirelessConfInit();
    
	/*< ebtables¹æÔòÁ´³õÊ¼»¯*/
	createEbtablesChain(0);
	createEbtablesChain(1);
	
	CWErrorHandlingInitLib();
	
	if(!CWParseSettingsFile()){
		CWLog("Can't start WTP. CWParseSettingsFile failed");
		exit(1);
	}

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

	CWLog("Starting WTP...");
	
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
	/*< ³õÊ¼»¯È«¾Ö±äÁ¿£¬APmacÒÔ¼°´Î¿¨macµÈ*/
	if(!CWErr(CWSetGlobalParam())){
        CWLog("CWSetGlobalParam error!");
		exit(1);
	}
	/*< Ö»ÓÐµÚÒ»¸ö½ø³Ì½øÐÐwltpµÄ¹ÜÀí*/
	
	/*< ÓëÄÚºË¼äÍ¨ÐÅ³õÊ¼»¯£¬ÒÔ±ãÏÂ·¢macµØÖ·ÒÔ¼°ACµÄIPµØÖ·µÈ*/
	while(kmod_communicate_init(gWtpPublicInfo.ethMac)){
		/*< ÊÝÄ£Ê½ÏÂ£¬²»¹ÜÊÇ·ñÊÇ¼¯ÖÐ×ª·¢£¬¶¼»áÆô¶¯wtpÒÔ¼°kmod£¬ËùÒÔ£¬´Ë´¦µÈ´ýkmodÆô¶¯*/
        CWLog("wait for load cloud_wlan_kmod!");
		sleep(1);
		continue;
	}

	if(dtt_dispose_pthread_init() < 0){
		CWLog("dtt_dispose_pthread_init pthread init failed!!!");
		exit(1);
	}
	
	APOnlineTypeInit();

	CWLog("##Config AC count is %d, AP online type is %d##", gCWACCfg->gCWACCount, gAPFoundACType);
	if(!CWWTPInitConfiguration())
	{
		CWLog("Error Init Configuration");
		exit(1);
	}

	/*< ¿ªÆôACLºÚ°×Ãûµ¥¹ÜÀíÏß³Ì£¬ÒòÐè½«staµÄÈÏÖ¤ÇëÇó·¢ËÍµ½ac¶Ë£¬ËùÒÔ´Ë´¦¿ªµ¥¶ÀÏß³Ì½øÐÐ´¦Àí*/
	CWThread thread_acl;
	if(!CWErr(CWCreateThread(&thread_acl, CWControlAcl, (void *)&wtpState))) {
		CWLog("Error starting Thread that control acl");
		exit(1);
	}
	/* if AC address is given jump Discovery and use this address for Joining */

	/* start CAPWAP state machine */	
	CW_REPEAT_FOREVER {
		switch(wtpState) {
			case CW_ENTER_DISCOVERY:
				wtpState = CWWTPEnterDiscovery();
				break;
			case CW_ENTER_SULKING:
				wtpState = CWWTPEnterSulking();
				/*< discoverÖÐ³¤Ê±¼ä²»ÉÏÏß´¦Àí»úÖÆ*/
				if(0 && CW_ENTER_DISCOVERY == wtpState && gAPFoundACType != WTP_FOUND_AC_TYPE_BROADCAST){
					/*< ÔÚdiscoverµÄµØÖ·ÁÐ±íÖÐÌí¼Ó¹ã²¥µØÖ·*/
					CWLog("## Can't online use the config type, add broadcast addr to discover list, will retry ... ##");
					CWThreadMutexLock(& gCWACCfg->mutex);
					CWWTPChangeOnlineType();
					CWThreadMutexUnlock(& gCWACCfg->mutex);
				}
				break;
			case CW_ENTER_JOIN:
				wtpState = CWWTPEnterJoin();
				break;
			case CW_ENTER_CONFIGURE:
				wtpState = CWWTPEnterConfigure();
				break;	
			case CW_ENTER_DATA_CHECK:
				wtpState = CWWTPEnterDataCheck();
				break;	
			case CW_ENTER_RUN:
				gWtpPublicInfo.onlinetoACtime = time(NULL);
				wtpState = CWWTPEnterRun();
				break;
			case CW_ENTER_RESET:
				WltpKeepAlive_stoptimer();
				CWStopTimers();
				CWNetworkCloseSocket(gWTPSocket);
				CWNetworkCloseSocket(gWTPDataSocket);
				CWNetResetSockPort();
				CWWTPSetDiscoverCount();
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
				wtpState = CW_ENTER_DISCOVERY;
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
		/*< ÈôÅäÖÃÎÄ¼þÖÐÅäÖÃÁË¹ã²¥µØÖ·£¬Ôò½«¸Ã±êÖ¾Î»ÖÃ1£¬·ÀÖ¹ÔÚ²»ÉÏÏßµÄÊ±ºò£¬ÔÙ´Î×Ô¶¯Ìí¼Ó¹ã²¥µØÖ·*/
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
		/*< ¶ÔgCWACCount+1²Ù×÷£¬Êµ¼ÊdiscoverÊ±£¬²Å»á±éÀúµ½¹ã²¥µØÖ·*/
		gCWACCfg->gCWACCount ++;
		gCWACCfg->broadcastFlag = 1;
	}
}

void CWWTPDestroy() {
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
		/* Default value for CAPWAï¿½ */
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

CWBool CWWTPGetProcessId(){
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

	/*< µ¥ËíµÀÏÂ£¬ÈôÆô¶¯ÁËµÚ¶þ¸ö½ø³Ì£¬Ö±½ÓÍË³ö*/
	if(atoi(buf) > 1)
		return CW_FALSE;
	
	return CW_TRUE;
}

