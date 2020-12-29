/*******************************************************************************************
 * Copyright (c) 2006-7 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica *
 *                      Universita' Campus BioMedico - Italy                               *
 *                                                                                         *
 * This program is free software; you can redistribute it and/or modify it under the terms *
 * of the GNU General Public License as published by the Free Software Foundation; either  *
 * version 2 of the License, or (at your option) any later version.                        *
 *                                                                                         *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY         *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 	   *
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.                *
 *                                                                                         *
 * You should have received a copy of the GNU General Public License along with this       *
 * program; if not, write to the:                                                          *
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,                    *
 * MA  02111-1307, USA.                                                                    *
 *                                                                                         *
 * --------------------------------------------------------------------------------------- *
 * Project:  Capwap                                                                        *
 *                                                                                         *
 * Author :  Ludovico Rossi (ludo@bluepixysw.com)                                          *  
 *           Del Moro Andrea (andrea_delmoro@libero.it)                                    *
 *           Giovannini Federica (giovannini.federica@gmail.com)                           *
 *           Massimo Vellucci (m.vellucci@unicampus.it)                                    *
 *           Mauro Bisson (mauro.bis@gmail.com)                                            *
 *******************************************************************************************/


#include "CWWTP.h"
#include "DTTConfigUpdate.h"

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

extern CWTimerID gCWWTPEventTimerID;
extern int gEventInterval;

CWBool CWWTPCheckForWTPEventStaInfo(unsigned short msgElemType);
CWBool CWWTPCheckForWTPEventAPInfo(unsigned short msgElemType, char index);

#if defined(__BYTE_ORDER)

#if __BYTE_ORDER == __BIG_ENDIAN
#       define __ntohll(x) (x)
#       define __ntohll(x) (x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#       define __ntohll(x)  bswap_64(x)
#       define __ntohll(x)  bswap_64(x)
#else
#       error "Could not determine byte order: __BYTE_ORDER uncorrectly defined"
#endif

#endif

#define	BSWAP_8(x)	((x) & 0xff)
#define	BSWAP_16(x)	((BSWAP_8(x) << 8) | BSWAP_8((x) >> 8))
#define	BSWAP_32(x)	((BSWAP_16(x) << 16) | BSWAP_16((x) >> 16))
#define	BSWAP_64(x)	((BSWAP_32(x) << 32) | BSWAP_32((x) >> 32))
/*_______________________________________________________________*/
/*  *******************___CHECK FUNCTIONS___*******************  */

CWBool CWWTPCheckForBindingFrame()
{
	//	
	CWLockSafeList(gFrameList);
	
	while (CWGetCountElementFromSafeList(gFrameList) > 0)
	{
		CWBindingDataListElement* dataFirstElem = CWRemoveHeadElementFromSafeList(gFrameList, NULL);
		if (dataFirstElem)
		{
			int k;
			int fragmentsNum = 0;
			CWProtocolMessage *completeMsgPtr = NULL;
	
			if (!CWAssembleDataMessage(&completeMsgPtr, 
						   &fragmentsNum, 
						   gWTPPathMTU, 
						   dataFirstElem->frame, 
						   dataFirstElem->bindingValues,
#ifdef CW_NO_DTLS
			       			   CW_PACKET_PLAIN
#else			       
			       			   CW_PACKET_CRYPT
#endif
						   ))
			{	
				for(k = 0; k < fragmentsNum; k++)
				{
					CW_FREE_PROTOCOL_MESSAGE(completeMsgPtr[k]);
				}
				
				CW_FREE_OBJECT(completeMsgPtr);
				CW_FREE_PROTOCOL_MESSAGE(*(dataFirstElem->frame));
				CW_FREE_OBJECT(dataFirstElem->frame);
				CW_FREE_OBJECT(dataFirstElem->bindingValues);
				CW_FREE_OBJECT(dataFirstElem);
				continue;
			}
								
			for (k = 0; k < fragmentsNum; k++) 
			{
#ifdef CW_NO_DTLS
				if (!CWNetworkSendUnsafeConnected(gWTPSocket, completeMsgPtr[k].msg, completeMsgPtr[k].offset)) {
#else
				if (!CWSecuritySend(gWTPSession, completeMsgPtr[k].msg, completeMsgPtr[k].offset)) {
#endif
					CWDebugLog("Failure sending Request");
					break;
				}
			}
			
			for (k = 0; k < fragmentsNum; k++)
			{
				CW_FREE_PROTOCOL_MESSAGE(completeMsgPtr[k]);
			}
			
			CW_FREE_OBJECT(completeMsgPtr);				
			CW_FREE_PROTOCOL_MESSAGE(*(dataFirstElem->frame));
			CW_FREE_OBJECT(dataFirstElem->frame);
			CW_FREE_OBJECT(dataFirstElem->bindingValues);
			CW_FREE_OBJECT(dataFirstElem);
		}	
	}

	CWUnlockSafeList(gFrameList);	
	
	return CW_TRUE;
}

void CWWTPCheckForWTPEventRequest(void *arg){

	CWLog("\n");
	CWLog("#________ WTP Event Request Message (Run) ________#");
	timer_rem(gCWWTPEventTimerID, NULL);

	CWWTPCheckForWTPEventAPInfo(CW_MSG_WTP_EVENT_AP_INFO, gAPIndex);
    /* need fix */
	CWWTPCheckForWTPEventStaInfo(CW_MSG_WTP_EVENT_STA_INFO);
    CWLog("***************************************************");
	gCWWTPEventTimerID = timer_add(gEventInterval, 0, &CWWTPCheckForWTPEventRequest, NULL); 
	if (gCWWTPEventTimerID == -1)	return;
}

void CWProtocolDestroyElem(void *f) {
	CW_FREE_OBJECT(f);
} 

static void CWWTPGetFlashUsage(char *strValue, int len)
{
	char cmd[64] = {0};
	FILE *fp = NULL;

	strcpy(cmd, "df | grep mtdblock | awk '{printf \"%s\", $5}'");
	fp = popen(cmd, "r");
    if(fp){
            fgets(strValue, len, fp);
            pclose(fp);
            fp = NULL;
    }
}

static void CWWTPGetUptime(char *strValue)
{
	FILE *fp = NULL;
    char buffer[64] = {0};
	int value = 0;

	fp = fopen("/proc/uptime", "r");
    if(fp){
		fgets(buffer, sizeof(buffer), fp);
		value=strtod(buffer, NULL);
		value = htonl(value);
		memcpy(strValue, (char *)&value, sizeof(value));
//		sprintf(strValue, "%d", value);
		fclose(fp);
		fp = NULL;
    }
//	CWDTTLog("uptime:%d", value);
}

static void CWWTPGetCPUUsage(char *strValue, int len)
{
	char cmd[64] = {0};
	FILE *fp = NULL;
	
	//strcpy(cmd, "top -n 1 | grep -v grep | grep CPU: | awk '{printf\"%s\", $2}'");
    strcpy(cmd, "top -n 1 | grep -v grep | grep CPU: | awk '{printf\"%s\", $8}' | awk -F'%' '{print (100-$1)\"%\"}'");
    
	fp = popen(cmd, "r");
	if(fp){
			fgets(strValue, len, fp);
			pclose(fp);
			fp = NULL;
	}

#if 0
	FILE *fp = NULL;
	char buffer[128],name[15];
	long user1, nice1, system1, idle1,user2, nice2, system2, idle2,sum1,sum2;
	float util;

	if( (fp=fopen("/proc/stat","r") )==NULL)
	{
		CWDTTLog("Can not open file!: /proc/stat");
		exit(1);
	}

	fgets (buffer, sizeof(buffer),fp);
	sscanf (buffer, "%s  %ld  %ld  %ld  %ld", name, &user1,&nice1,&system1, &idle1);
	sum1=user1+ nice1+system1+idle1;
	fclose(fp);

	sleep(1);

	if( (fp=fopen("/proc/stat","r") )==NULL)
	{
		CWDTTLog("Can not open file!");
		exit(1);
	}

	fgets (buffer, sizeof(buffer),fp);
	sscanf (buffer, "%s  %ld  %ld  %ld  %ld", name, &user2,&nice2,&system2, &idle2);
	sum2=user2+ nice2+system2+idle2;
	util=(float)100.0*(user2-user1+system2-system1)/(sum2-sum1);
	fclose(fp);
	fp = NULL;

	sprintf(strValue, "%.3f%%", util);
#endif
}
static void CWWTPGetRAMUsage(char *strValue, int len)
{
	char cmd[64] = {0};
	FILE *fp = NULL;
	
	strcpy(cmd, "free | sed -n '2p' | awk '{printf \"%.2f%%\", ($3/$2*100)}'");
	fp = popen(cmd, "r");
	if(fp){
		fgets(strValue, len, fp);
		pclose(fp);
		fp = NULL;
	}
}

static void CWWTPGetWirelessChan(char *strValue){

	char cmd[64] = {0};
	FILE *fp = NULL;
    char buffer[64] = {0};
	int value = 0;

	sprintf(cmd, "uci get wireless.@wifi-device[%d].channel", gAPIndex-1);
	fp = popen(cmd, "r");
	if(fp){
		fgets(buffer, sizeof(buffer), fp);
		value = strtod(buffer, NULL);
		value = htonl(value);
		memcpy(strValue, (char *)&value, sizeof(value));
		pclose(fp);
		fp = NULL;
	}
	
	return;
}

static void CWWTPGetCardType(char *value)
{
	char cmd[128] = {0};
	FILE *fp = NULL;
    char buffer[64] = {0};

    value[0] = 0;
    
	if(gAPIndex == 1)
		//sprintf(cmd, "iwinfo wifi0 info | grep wifi0 -A 7 | grep \"qcawifi\" | cut -d \":\" -f 3");
		strcpy(cmd, "/sys/class/net/wifi0/hwcaps");
	else
		//sprintf(cmd, "iwinfo wifi1 info | grep wifi1 -A 7 | grep \"qcawifi\" | cut -d \":\" -f 3");
		strcpy(cmd, "/sys/class/net/wifi1/hwcaps");

	fp = fopen(cmd, "r");
    
	if(fp){
		fgets(buffer, 128, fp);
		/*< 与AC端的代码一致*/
		
        if(strchr(buffer, 'a') && strchr(buffer, 'b') && strchr(buffer, 'g') && strchr(buffer, 'n'))
			value[0] = WIRELESSMODE_11A|WIRELESSMODE_11B|WIRELESSMODE_11G|WIRELESSMODE_11BGN;
		else if(strchr(buffer, 'b') && strchr(buffer, 'g') && strchr(buffer, 'n'))
			value[0] = WIRELESSMODE_11B|WIRELESSMODE_11G|WIRELESSMODE_11BGN;
		else if(strchr(buffer, 'b') && strchr(buffer, 'g'))
			value[0] = WIRELESSMODE_11B|WIRELESSMODE_11G;
		else if(strchr(buffer, 'a') && strchr(buffer, 'n') && strchr(buffer, 'c'))
			value[0] = WIRELESSMODE_11A|WIRELESSMODE_11AN|WIRELESSMODE_11AC;
		else if(strchr(buffer, 'a') && strchr(buffer, 'n'))
			value[0] = WIRELESSMODE_11A|WIRELESSMODE_11AN;
		else if(strchr(buffer, 'a') && strchr(buffer, 'b'))
			value[0] = WIRELESSMODE_11A|WIRELESSMODE_11B;
		else
			value[0] = 0;
			
		fclose(fp);
		fp = NULL;
	}
    
	return;
}

CWBool CWWTPCheckForWTPEventAPInfo(unsigned short msgElemType, char index){
	CWLog("#__ WTP Event Request Message (AP Info) ___#");
	
	/* Send WTP Event Request */
	CWList msgElemList = NULL;
	CWProtocolMessage *messages = NULL;
	int fragmentsNum = 0;
	int seqNum;
//	int *pendingReqIndex;
	char strValue[1024] = {0};
	unsigned int countrycode = 0;
	char tmp_FwMode[64] = {0};
	char tmp_sn[64] = {0};
	char tmp_model[64] = {0};
		
	seqNum = CWGetSeqNum();

/*	CW_CREATE_OBJECT_ERR(pendingReqIndex, int, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	if(getWTPMac(strValue))
	{
		CW_ZERO_MEMORY(strValue, 1024);
	}
*/
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_MAC, g_DevMAC, 6);
    CWLog("---------------------g_DevMAC %02x:%02x:%02x:%02x:%02x:%02x ", MAC2STR((unsigned char *)g_DevMAC));
    
    //CW_ZERO_MEMORY(strValue, 1024);
	/*< 当ip为0.0.0.0时，说明初始化时，IP获取失败，重新获取IP*/
	if(g_DevIP[0] == 0 && g_DevIP[1] == 0 && g_DevIP[2] == 0 && g_DevIP[3] == 0){
		CWNetworkGetWTPIP(g_DevIP);
	}
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_IP, g_DevIP, 4);

    CW_ZERO_MEMORY(strValue, 1024);
	getWTPName(NULL, (char *)strValue, 32);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_NAME, strValue, 65);
    CWLog("------------------------------WTP_NAME %s", strValue);
	
    countrycode = getCountryCodeCfg();
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_COUNTRYCODE, &countrycode, 4);
    CWLog("------------------------------countrycode %d", countrycode);


    CW_ZERO_MEMORY(strValue, 1024);
	CWWTPGetWirelessChan(strValue);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_CHANNEL, strValue, 4);
    CWLog("------------------------------wtp channel %s", strValue);
	
    CW_ZERO_MEMORY(strValue, 1024);
	CWWTPGetUptime(strValue);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_UPTIME, strValue, 4);
    CWLog("------------------------------uptime %s", strValue);

    CW_ZERO_MEMORY(strValue, 1024);
	CWWTPGetCPUUsage(strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_CPU_USAGE, strValue, 10);
	CWLog("------------------------------cpu %s", strValue);

    //getConfigbinInfo("sn", tmp_sn, 64, NULL);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_SERIAL_NUMBER, g_DevSn, 32);
    CWLog("------------------------------wtp sn %s", g_DevSn);
	
    CW_ZERO_MEMORY(strValue, 1024);
	CWWTPGetFlashUsage(strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_FLASH_USAGE, strValue, 10);
	CWLog("------------------------------flash usage %s", strValue);
	
    //getConfigbinInfo("model", tmp_model, 64, NULL);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_PRODUCT_NAME, g_DevModel, 32);
    CWLog("------------------------------wtp model %s", g_DevModel);
	
    CW_ZERO_MEMORY(strValue, 1024);
	CWWTPGetRAMUsage(strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_MEM_USAGE, strValue, 10);
    CWLog("------------------------------wtp mem %s", strValue);

    /* fixed */
	CW_ZERO_MEMORY(strValue, 1024);
    CWWTPGetCardType(strValue);
    CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_CARDMODE, strValue, 1);
    CWLog("------------------------------wtp_cardtype %d", strValue[0]);
	
    CW_ZERO_MEMORY(strValue, 1024);
	strValue[0] = getWirelessMode();
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WIRELESS_MODE, strValue, 1);
    CWLog("------------------------------wtp wlan mode %d", strValue[0]);
	
    if(gCWAPCardCount == CW_TWO_CARD){
		CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_CARD_INDEX, &index, 1);
		CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_OTHER_CARD_MAC, g_SlaveDevMAC, 6);
	}

	//getConfigbinInfo("fwmode", tmp_FwMode, 48, NULL);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_FIRMWARE_VERSION, g_DevFwMode, 40);
    CWLog("------------------------------wtp fwmode %s", g_DevFwMode);

	CW_ZERO_MEMORY(strValue, 1024);
	if(gAPIndex == 1){
		sprintf(strValue, MACSTR, MAC2STR((unsigned char *)g_DevMAC));
	}else{
		sprintf(strValue, MACSTR, MAC2STR((unsigned char *)g_SlaveDevMAC));
	}
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_NETWORK_CODE, strValue, 32);



	CW_ZERO_MEMORY(strValue, 1024);
	if(!CWAssembleWTPEventRequest(&messages, &fragmentsNum, gWTPPathMTU, seqNum, msgElemList, msgElemType, 0))
    {
		int i;
		if(messages){
			for(i = 0; i < fragmentsNum; i++) 
            {
				CW_FREE_PROTOCOL_MESSAGE(messages[i]);
			}	
        }
		CW_FREE_OBJECT(messages);
		CWDeleteList(&msgElemList, CWProtocolDestroyElem);
        
		return CW_FALSE;
	}
	CWDeleteList(&msgElemList, CWProtocolDestroyElem);

	int i;
	for(i = 0; i < fragmentsNum; i++) 
    {
		if(!CWNetworkSendUnsafeConnected(gWTPSocket, messages[i].msg, messages[i].offset)) 
        {
			CWLog("CWNetworkSendUnsafeConnected fail !");
            return -1;
		}
		CW_FREE_PROTOCOL_MESSAGE(messages[i]);
	}
	CW_FREE_OBJECT(messages);

    CWLog("-------------------------------------------------");   
	return CW_TRUE;
}

static void getStaIP(char *mac, staInfo *sta)
{
	char cmd[128] = {0};
	FILE *fp = NULL;
	char buffer[64] = {0};
	unsigned int ip[4] = {0};
	/*< 这个主要用于查找本地转发时，静态IP，由crontab完成*/
	sprintf(cmd, "cat /tmp/capwap/ip-mac | grep -i %s | cut -d \"-\" -f 1", mac);
	fp = popen(cmd, "r");
	if(fp){
		fgets(buffer, sizeof(buffer), fp);
		buffer[strlen(buffer)-1] = '\0';
		pclose(fp);
		fp = NULL;
	}
	if(strlen(buffer) <= 1){
		memset(cmd, 0, sizeof(cmd));
		/*< 这个用于查找本地和集中时，用户通过DHCP获取的IP，由内核态完成*/
		sprintf(cmd, "cat /tmp/capwap/kmod-ip-mac | grep -i %s | cut -d \"-\" -f 1", mac);
		fp = popen(cmd, "r");
		if(fp){
			fgets(buffer, sizeof(buffer), fp);
			buffer[strlen(buffer)-1] = '\0';
			pclose(fp);
			fp = NULL;
		}
	}

	sscanf(buffer, "%d.%d.%d.%d", ip, ip+1, ip+2, ip+3);
	sta->ip[0] = ip[0];sta->ip[1] = ip[1];sta->ip[2] = ip[2];sta->ip[3] = ip[3];

	CWDebugLog("get ip:%s-%d.%d.%d.%d#\n", mac , sta->ip[0], sta->ip[1], sta->ip[2], sta->ip[3]);

	return ;
}

/*< card为当前查找的wlan，index为此wlan是第几个vap，便于查找vlan*/
static stalist *getOneWlanStaInfo(char *card, stalist *list, int index)
{
	char cmd[64] = {0};
	FILE* tmp = NULL;
	char buffer[1024] = {0};
	char tmpbuffer[64] = {0};
	unsigned int tmpaddr[6] = {0};
	char *p = NULL;
	staInfo *sta = NULL;
	char ssid[32] = {0};
    int i = 1;

	CW_ZERO_MEMORY(cmd, sizeof(cmd));
	//sprintf(cmd, "iw dev %s info | grep ssid", card);
	//strcat(cmd,  " | awk '{printf \"%s\",$2}'");
    sprintf(cmd, "iwconfig %s | grep ESSID:", card);
	strcat(cmd,  " | awk -F'\"' '{printf $2}'");
//	CWDTTLog("info cmd is:%s", cmd);
	tmp = popen(cmd,"r");
	CW_ZERO_MEMORY(buffer, sizeof(buffer));
	if(tmp)
	{
		while(fgets(buffer, sizeof(buffer), tmp))
		{
			CW_COPY_MEMORY(ssid, buffer, sizeof(ssid));
//			CWDTTLog("ssid buffer:%s", buffer);
			
			CW_ZERO_MEMORY(buffer, sizeof(buffer));
		}
		pclose(tmp);
		tmp = NULL;
	}

	CW_ZERO_MEMORY(cmd, sizeof(cmd));
    
#if 0
	sprintf(cmd, "iw dev %s station dump", card);
	tmp = popen(cmd,"r");

	if(tmp)
	{
		while(fgets(buffer, sizeof(buffer), tmp))
		{
			buffer[strlen(buffer)-1] = '\0';
			if(!strncmp("Station", buffer, 7))
			{
				CW_CREATE_OBJECT_ERR(sta, staInfo, return NULL;);
				CW_ZERO_MEMORY(sta, sizeof(staInfo));
				sta->next = list->info;
				list->info = sta;
				list->count ++;

				snprintf(tmpbuffer, 18, "%s", buffer+8);
				sscanf(tmpbuffer, "%2x:%2x:%2x:%2x:%2x:%2x", tmpaddr, tmpaddr+1, tmpaddr+2, tmpaddr+3,tmpaddr+4, tmpaddr+5);
//				CWLog("tmpbuffer:%s", tmpbuffer);
				sta->mac[0] = tmpaddr[0];sta->mac[1] = tmpaddr[1];sta->mac[2] = tmpaddr[2];
				sta->mac[3] = tmpaddr[3];sta->mac[4] = tmpaddr[4];sta->mac[5] = tmpaddr[5];
				getStaIP(tmpbuffer, sta);
				CW_ZERO_MEMORY(tmpbuffer, sizeof(tmpbuffer));
				sta->vlanID = htonl(getVapVlanID(index));
				continue;
			}
			if(strstr(buffer, "inactive time"))
			{
				p = strstr(buffer, ":")+1;
				sta->savePowerMode = strtoul(p, NULL, 10);
				/*< 暂且认为inactive time值大于100ms，则为节电模式*/
				if(sta->savePowerMode > 200)
					sta->savePowerMode = htonl(1);
				else
					sta->savePowerMode = htonl(0);
			}
			if(strstr(buffer, "tx bitrate"))
			{
				p = strstr(buffer, ":")+1;
				sta->txBitrate = htonl((unsigned int)(strtof(p, NULL)*1024));
			}
			if(strstr(buffer, "rx packets"))
			{
				p = strstr(buffer, ":")+1;
				sta->packageRx = strtoull(p, NULL, 10);
				sta->packageRx = __ntohll(sta->packageRx);
			}
			if(strstr(buffer, "tx packets"))
			{
				p = strstr(buffer, ":")+1;
				sta->packageTx = strtoull(p, NULL, 10);
				sta->packageTx = __ntohll(sta->packageTx);
			}
			if(strstr(buffer, "rx bytes"))
			{
				p = strstr(buffer, ":")+1;
				sta->bytesRx = strtoull(p, NULL, 10);
				sta->bytesRx = __ntohll(sta->bytesRx);
			}
			if(strstr(buffer, "tx bytes"))
			{
				p = strstr(buffer, ":")+1;
				sta->bytesTx = strtoull(p, NULL, 10);
				sta->bytesTx = __ntohll(sta->bytesTx);
			}
			if(strstr(buffer, "tx retries"))
			{
				p = strstr(buffer, ":")+1;
				sta->resendPackage = strtoull(p, NULL, 10);
				sta->resendPackage = __ntohll(sta->resendPackage);
			}
			if(strstr(buffer, "WMM/WME"))
			{
				if(strstr(buffer, "yes"))
				{
					sta->WMM = htonl(1);
				}
				else
				{
					sta->WMM = htonl(0);
				}
			}
			if(strstr(buffer, "signal avg"))
			{
				p = strstr(buffer, ":")+1;
				sta->signal = htonl(strtol(p, NULL, 10));
			}
			CW_COPY_MEMORY(sta->ssid, ssid, sizeof(ssid));
			CW_ZERO_MEMORY(buffer, sizeof(buffer));
		}
		pclose(tmp);
		tmp = NULL;
	}
    
#else
    
    char str_tmp[8] = {0};
    sprintf(cmd, "wlanconfig %s list", card);
    tmp = popen(cmd,"r");

    if(tmp)
    {
        /* skip line 1 */
        /*****************************
        ADDR               AID CHAN TXRATE RXRATE RSSI IDLE  TXSEQ  RXSEQ  CAPS        ACAPS     ERP    STATE MAXRATE(DOT11) E
        38:37:8b:03:93:82    1    1   0M      4M   46   15      0   65535   ESs         0       1005              0           
        ******************************/
        fgets(buffer, sizeof(buffer), tmp);
        
        while(fgets(buffer, sizeof(buffer), tmp))
        {
            //buffer[strlen(buffer)-1] = '\0';
            /* MAC */
            {
                CW_CREATE_OBJECT_ERR(sta, staInfo, return NULL;);
                CW_ZERO_MEMORY(sta, sizeof(staInfo));
                sta->next = list->info;
                list->info = sta;
                list->count ++;

                snprintf(tmpbuffer, 18, "%s", buffer);
                sscanf(tmpbuffer, "%2x:%2x:%2x:%2x:%2x:%2x", tmpaddr, tmpaddr+1, tmpaddr+2, tmpaddr+3,tmpaddr+4, tmpaddr+5);
                CWLog("STA:%s", tmpbuffer);
                sta->mac[0] = tmpaddr[0];sta->mac[1] = tmpaddr[1];sta->mac[2] = tmpaddr[2];
                sta->mac[3] = tmpaddr[3];sta->mac[4] = tmpaddr[4];sta->mac[5] = tmpaddr[5];
                getStaIP(tmpbuffer, sta);
                CW_ZERO_MEMORY(tmpbuffer, sizeof(tmpbuffer));
                sta->vlanID = htonl(getVapVlanID(index));
            }

            p = strtok(buffer," ");
            i = 1;
            while(p)
            {                
                if ( i == 4 )
                {
                    CWLog("rxrate %s", p);
                    CW_ZERO_MEMORY(str_tmp, sizeof(str_tmp));
                    strcpy(str_tmp,p);
                    str_tmp[(strlen(str_tmp) - 1)] = '\0';
                    sta->txBitrate = htonl((unsigned int)(strtol(str_tmp, NULL, 10)*1024));
                }
                else if( i == 6 )
                {
                    CWLog("rssi %s", p);
                    sta->signal = htonl((strtol(p, NULL, 10) - 95 ));  /*ATH_DEFAULT_NOISE_FLOOR     -95*/
                }
                else if ( i == 7 ) 
                {
                    CWLog("idel %s", p); 
                    sta->savePowerMode = strtoul(p, NULL, 10);
                    /* idel > 0，则为节电模式*/
                    if(sta->savePowerMode > 200)
                        sta->savePowerMode = htonl(1);
                    else
                        sta->savePowerMode = htonl(0);
                    break;
                }
                
                p = strtok(NULL," ");
                i ++;
            }

                  
            CW_COPY_MEMORY(sta->ssid, ssid, sizeof(ssid));
            CW_ZERO_MEMORY(buffer, sizeof(buffer));
        }
        pclose(tmp);
        tmp = NULL;
    }
#endif

	return NULL;
}

static stalist *getAllWlanStaInfo()
{
	FILE* cardfp = NULL;

    char cmd[128] = {0};
    char buffer[256] = {0};

    char card[16] = {0};
    int i = 0;
	int flag = 0;
	
	stalist *list = NULL;
	CW_CREATE_OBJECT_ERR(list, stalist, return NULL;);
	list->info = NULL;
	list->count = 0;
#if 0
    strcpy(cmd, "iwinfo");
    cardfp = popen(cmd,"r");
    if(cardfp){
		while(fgets(buffer, sizeof(buffer), cardfp)){
		    if('\t' == buffer[0] || '\n' == buffer[0]|| ' ' == buffer[0])
		        continue;
		    while(buffer[i] != ' ')
		        i ++;
		    strncpy(card, buffer, i);
			
			if((gAPIndex == 2 && strstr(card, "wlan0")) || (gAPIndex == 1 && strstr(card, "wlan1")))
				continue;
		    CWDebugLog("card:%s#\n", card);
			
		    getOneWlanStaInfo(card, list);
			
		    memset(buffer, 0, sizeof(buffer));
		    memset(card, 0, sizeof(card));
		    i = 0;
		}
		pclose(cardfp);
		cardfp = NULL;
    }else{
            CWDTTLog("The \"iwinfo\" cmd do failed : %s\n", strerror(errno));
    }
#endif
	for(i = 0;i < MAX_VAP;i ++){
		if(getVapSwitch(i) == 1){
			if(gAPIndex == 1){
				if(flag)
					sprintf(card, "ath0%d", flag);
				else
					sprintf(card, "ath0");
			}else{
				if(flag)
					sprintf(card, "ath1%d", flag);
				else
					sprintf(card, "ath1");
			}
			getOneWlanStaInfo(card, list, i+(gAPIndex-1)*8);
			flag ++;
		}
	}

	return list;
}

static void delStaInfo(stalist *list)
{
	staInfo *sta = NULL;
	int i = 0;

	for(i = 0;i < list->count;i ++)
	{
		sta = list->info;
		list->info = sta->next;
		CW_FREE_OBJECT(sta);
	}
	CW_FREE_OBJECT(list);

	return;
}

CWBool CWWTPCheckForWTPEventStaInfo(unsigned short msgElemType)
{
	CWLog("#___ WTP Event Request Message (Sta Info) ___#");
    
	//return CW_FALSE;
    
	/* Send WTP Event Request */
	CWList msgElemList = NULL;
	CWProtocolMessage *messages = NULL;
	int fragmentsNum = 0;
	int seqNum;
//	int *pendingReqIndex;
	int i = 0;
	int count = 0;
	unsigned long long throughput = 0;
		
	seqNum = CWGetSeqNum();

//	CW_CREATE_OBJECT_ERR(pendingReqIndex, int, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

	staInfo *sta = NULL;
	/*< 通过iwinfo获取到所有虚拟节点的sta信息*/
	stalist *list = getAllWlanStaInfo();

	staInfoList AllStaList;
	CW_ZERO_MEMORY(&AllStaList, sizeof(staInfoList));

	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.mac, 6*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.mac, 6*list->count);
	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.ip, 4*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.ip, 4*list->count);
	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.ssid, 33*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.ssid, 33*list->count);
	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.signal, 4*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.signal, 4*list->count);
	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.txBitrate, 4*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.txBitrate, 4*list->count);
	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.savePowerMode, 4*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.savePowerMode, 4*list->count);
	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.vlanID, 4*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.vlanID, 4*list->count);
	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.packageTx, 8*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.packageTx, 8*list->count);
	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.packageRx, 8*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.packageRx, 8*list->count);
	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.bytesTx, 8*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.bytesTx, 8*list->count);
	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.bytesRx, 8*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.bytesRx, 8*list->count);
	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.WMM, 4*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.WMM, 4*list->count);
	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.resendPackage, 8*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.resendPackage, 8*list->count);
	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.throughput, 8*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.throughput, 8*list->count);

	sta = list->info;
	/*< 将sta链的信息转换为mac链,ip链,signal链等
	 *  capwap的sta上报包中，若有多个sta，每一类信息应放在一起，比如mac地址，应该连续.
	*/
	while(sta)
	{
//		CWLog("list->count is %d, list->ssid is %s, sta->mac:%02x:%02x:%02x:%02x:%02x:%02x, wmm:%d, packageRx:%lld", list->count, sta->ssid, sta->mac[0], sta->mac[1],sta->mac[2],
//			sta->mac[3],sta->mac[4],sta->mac[5], sta->WMM, sta->packageRx);
		memcpy((char *)AllStaList.mac+6*count, sta->mac, 6);
		memcpy((char *)AllStaList.ip+4*count, sta->ip, 4);
		memcpy((char *)AllStaList.ssid+33*count, sta->ssid, 33);
		memcpy((char *)AllStaList.signal+4*count, &sta->signal, 4);
		memcpy((char *)AllStaList.txBitrate+4*count, &sta->txBitrate, 4);
		memcpy((char *)AllStaList.savePowerMode+4*count, &sta->savePowerMode, 4);
		memcpy((char *)AllStaList.vlanID+4*count, &sta->vlanID, 4);
		memcpy((char *)AllStaList.packageTx+8*count, &sta->packageTx, 8);
		memcpy((char *)AllStaList.packageRx+8*count, &sta->packageRx, 8);
		memcpy((char *)AllStaList.bytesTx+8*count, &sta->bytesTx, 8);
		memcpy((char *)AllStaList.bytesRx+8*count, &sta->bytesRx, 8);
		memcpy((char *)AllStaList.WMM+4*count, &sta->WMM, 4);
		memcpy((char *)AllStaList.resendPackage+8*count, &sta->resendPackage, 8);
		throughput = __ntohll(sta->bytesTx+sta->bytesRx);
		memcpy((char *)AllStaList.throughput+8*count, &throughput, 8);
//		CWLog("list->count is %d, list->ssid is %s, AllStaList->mac:%02x:%02x:%02x:%02x:%02x:%02x, wmm[0]:%d", list->count, sta->ssid, AllStaList.mac[0], AllStaList.mac[1],AllStaList.mac[2],
//			AllStaList.mac[3],AllStaList.mac[4],AllStaList.mac[5], AllStaList.WMM[0]);
		count ++;
		sta = sta->next;
	}
//	CWLog("list->count is %d, list->ssid is %s, AllStaList->mac:%02x:%02x:%02x:%02x:%02x:%02x, wmm[0]:%d, wmm[1]:%d, packageRx[0]:%d, packageRx[1]:%d", list->count, sta->ssid, AllStaList.mac[0], AllStaList.mac[1],AllStaList.mac[2],
//		AllStaList.mac[3],AllStaList.mac[4],AllStaList.mac[5], AllStaList.WMM[0], AllStaList.WMM[1], AllStaList.packageRx[0], AllStaList.packageRx[1]);

//	int vlanid = 1001;
	/*< 封装sta信息，sta的宏直接使用了WTP的宏，所以命名会不一致*/
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_MAC, (char *)AllStaList.mac, 6*list->count);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_IP, (char *)AllStaList.ip, 4*list->count);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_NAME, (char *)AllStaList.txBitrate, 4*list->count);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_COUNTRYCODE, (char *)AllStaList.savePowerMode, 4*list->count);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_CARDMODE, (char *)AllStaList.ssid, 33*list->count);
//	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLANFLOW, NULL, 8*list->count);//6
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_SIGNAL, (char *)AllStaList.signal, 4*list->count);
//	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_MTU, NULL, 4*list->count);//8
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_CHANNEL, (char *)AllStaList.packageTx, 8*list->count);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_BSSID_COUNT, (char *)AllStaList.packageRx, 8*list->count);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_BSSID_COUNT, (char *)AllStaList.bytesTx, 8*list->count);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_CONNECT_AC_DURATION, (char *)AllStaList.bytesRx, 8*list->count);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_BSSID_NAME, (char *)AllStaList.WMM, 4*list->count);//14
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_CUBSSID_NAME, (char *)AllStaList.throughput, 8*list->count);//15
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_FIRMWARE_VERSION, (char *)AllStaList.vlanID, 4*list->count);
	
//	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_CPU_USAGE, NULL, 4*list->count);//17
//	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_NETWORK_CODE, NULL, 4*list->count);//18
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_GATEWAY, (char *)AllStaList.resendPackage, 8*list->count);
//	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_SYSLOG_SERVER, NULL, 4*list->count);//24
//	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_MEM_USAGE, NULL, 4*list->count);//25
//	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_FLASH_USAGE, NULL, 4*list->count);//26
//	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_NETWORK_MASK, NULL, 4*list->count);//27
	
	while(list->count)
	{
		sta = list->info;
		CW_FREE_OBJECT(sta);
		list->info = list->info->next;
		list->count --;
	}
	CW_FREE_OBJECT(list);
	CW_FREE_OBJECT(AllStaList.mac);
	CW_FREE_OBJECT(AllStaList.ip);
	CW_FREE_OBJECT(AllStaList.savePowerMode);
	CW_FREE_OBJECT(AllStaList.txBitrate);
	CW_FREE_OBJECT(AllStaList.vlanID);
	CW_FREE_OBJECT(AllStaList.ssid);
	CW_FREE_OBJECT(AllStaList.signal);
	CW_FREE_OBJECT(AllStaList.packageTx);
	CW_FREE_OBJECT(AllStaList.packageRx);
	CW_FREE_OBJECT(AllStaList.bytesTx);
	CW_FREE_OBJECT(AllStaList.bytesRx);
	CW_FREE_OBJECT(AllStaList.WMM);
	CW_FREE_OBJECT(AllStaList.resendPackage);
	CW_FREE_OBJECT(AllStaList.throughput);

	/*< count为查询到的sta总个数, msgElemType表示为WTP上报还是sta info上报*/
	if(!CWAssembleWTPEventRequest(&messages, &fragmentsNum, gWTPPathMTU, seqNum, msgElemList, msgElemType, count)){
		int i;
		if(messages)
			for(i = 0; i < fragmentsNum; i++) {
				CW_FREE_PROTOCOL_MESSAGE(messages[i]);
			}	
		CW_FREE_OBJECT(messages);
		CWDeleteList(&msgElemList, CWProtocolDestroyElem);
		return CW_FALSE;
	}
	CWDeleteList(&msgElemList, CWProtocolDestroyElem);
	
	for(i = 0; i < fragmentsNum; i++) {
//#ifdef CW_NO_DTLS
		if(!CWNetworkSendUnsafeConnected(gWTPSocket, messages[i].msg, messages[i].offset)) {
//#else
//		if(!CWSecuritySend(gWTPSession, messages[i].msg, messages[i].offset)){
//#endif
			return CW_FALSE;
		}
		CW_FREE_PROTOCOL_MESSAGE(messages[i]);
	}
	CW_FREE_OBJECT(messages);
	
#if 0
	*pendingReqIndex = CWSendPendingRequestMessage(gPendingRequestMsgs,messages,fragmentsNum);
	if (*pendingReqIndex<0) {
		CWDebugLog("Failure sending WTP Event Request");
		int k;
		for(k = 0; k < fragmentsNum; k++) {
			CW_FREE_PROTOCOL_MESSAGE(messages[k]);
		}
		CW_FREE_OBJECT(messages);
		return CW_FALSE;
	}

	CWUpdatePendingMsgBox(&(gPendingRequestMsgs[*pendingReqIndex]),
			      CW_MSG_TYPE_VALUE_WTP_EVENT_RESPONSE,
			      seqNum,
			      gCWRetransmitTimer,
			      pendingReqIndex,
			      CWWTPRetransmitTimerExpiredHandler,
			      0,
			      messages,
			      fragmentsNum);
#endif
//	CWDeleteList(&msgElemList, CWProtocolDestroyMsgElemData);

	return CW_TRUE;
}


/*
void CWWTPRetransmitTimerExpiredHandler(CWTimerArg arg, CWTimerID id)
{
	CWThreadSetSignals(SIG_BLOCK, 1, SIGALRM);

	CWDebugLog("Retransmit Timer Expired for Thread: %08x", (unsigned int)CWThreadSelf());
	
	if(gPendingRequestMsgs[arg].retransmission == gCWMaxRetransmit) {
		CWDebugLog("Peer is Dead");
		CWThreadSetSignals(SIG_UNBLOCK, 1, SIGALRM);
		//_CWCloseThread(*iPtr);
		return;
	}

	CWDebugLog("Retransmission Count increases to %d", gPendingRequestMsgs[arg].retransmission);
	
	int i;
	for(i = 0; i < gPendingRequestMsgs[arg].fragmentsNum; i++) {
		if(!CWSecuritySend(gWTPSession, gPendingRequestMsgs[arg].msgElems[i].msg, gPendingRequestMsgs[arg].msgElems[i].offset)){
			CWDebugLog("Failure sending Request");
			int k;
			for(k = 0; k < gPendingRequestMsgs[arg].fragmentsNum; k++) {
				CW_FREE_PROTOCOL_MESSAGE(gPendingRequestMsgs[arg].msgElems[k]);
			}	
			CW_FREE_OBJECT(gPendingRequestMsgs[arg].msgElems);
			CWThreadSetSignals(SIG_UNBLOCK, 1, SIGALRM);
			return;
		}
	}	
	gPendingRequestMsgs[arg].retransmission++;

	if(!CWTimerCreate(gPendingRequestMsgs[arg].timer_sec, &(gPendingRequestMsgs[arg].timer), gPendingRequestMsgs[arg].timer_hdl, gPendingRequestMsgs[arg].timer_arg)) {
		CWThreadSetSignals(SIG_UNBLOCK, 1, SIGALRM);
		return;
	}	

	CWThreadSetSignals(SIG_UNBLOCK, 1, SIGALRM);

	return;
}
*/

void CWWTPRetransmitTimerExpiredHandler(CWTimerArg hdl_arg)
{
	int index = *((int *)hdl_arg);

	CWLog("Retransmit Timer Expired for Thread: %08x", (unsigned int)CWThreadSelf());
	
	if(gPendingRequestMsgs[index].retransmission == gCWMaxRetransmit) {
		CWLog("Peer is Dead");
		//_CWCloseThread(*iPtr);
		return;
	}

	CWLog("Retransmission Count increases to %d", gPendingRequestMsgs[index].retransmission);
	
	int i;
	for(i = 0; i < gPendingRequestMsgs[index].fragmentsNum; i++) {
#ifdef CW_NO_DTLS
		if (!CWNetworkSendUnsafeConnected(gWTPSocket, 
						  gPendingRequestMsgs[index].msgElems[i].msg,
						  gPendingRequestMsgs[index].msgElems[i].offset)) {
#else
		if (!CWSecuritySend(gWTPSession, 
				    gPendingRequestMsgs[index].msgElems[i].msg,
				    gPendingRequestMsgs[index].msgElems[i].offset)){
#endif
			CWDebugLog("Failure sending Request");
			int k;
			for(k = 0; k < gPendingRequestMsgs[index].fragmentsNum; k++) {
				CW_FREE_PROTOCOL_MESSAGE(gPendingRequestMsgs[index].msgElems[k]);
			}	
			CW_FREE_OBJECT(gPendingRequestMsgs[index].msgElems);
			CW_FREE_OBJECT(hdl_arg);
			return;
		}
	}	
	gPendingRequestMsgs[index].retransmission++;

	gPendingRequestMsgs[index].timer = timer_add(gPendingRequestMsgs[index].timer_sec, 
						   0, 
						   gPendingRequestMsgs[index].timer_hdl,
						   gPendingRequestMsgs[index].timer_arg);
	CW_FREE_OBJECT(hdl_arg);
	return;
}

