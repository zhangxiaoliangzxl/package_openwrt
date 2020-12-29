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
#include "WTPRunStateCheck.h"
#include "DTTKmodCommunicate.h"

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

extern CWTimerID gCWWTPEventTimerID;
extern int gEventInterval;

CWBool CWWTPCheckForWTPEventStaInfo(unsigned short msgElemType);
CWBool CWWTPCheckForWTPEventAPInfo(unsigned short msgElemType, char index);
CWBool CWWTPCheckForWTPEventPublicInfo(unsigned short msgElemType);
CWBool CWWTPCheckForWTPEventPrivateInfo(unsigned short msgElemType, char index);


#if defined(__BYTE_ORDER)

#if __BYTE_ORDER == __BIG_ENDIAN
#       define __ntohll(x) (x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#       define __ntohll(x)  bswap_64(x)
#else
#       error "Could not determine byte order: __BYTE_ORDER uncorrectly defined"
#endif

#endif

#define	BSWAP_8(x)	((x) & 0xff)
#define	BSWAP_16(x)	((BSWAP_8(x) << 8) | BSWAP_8((x) >> 8))
#define	BSWAP_32(x)	((BSWAP_16(x) << 16) | BSWAP_16((x) >> 16))
#define	BSWAP_64(x)	((BSWAP_32(x) << 32) | BSWAP_32((x) >> 32))

char xCAST_info_cmd[]={\
"ebtables -L %s --Lc|grep -i %s|grep -i %s|grep -i %s| awk -v pcnt_or_bcnt=%s -v has_one=0 '\n"
"	BEGIN{\n"
"		has_one = 0\n"
"	}\n"
"	#body\n"
"	{\n"
"		cnt = 0\n"
"		for(i = 1; i < NF-1; i++)\n"
"		{\n"
"			if(pcnt_or_bcnt == $i)\n"
"			{\n"
"				if(NF < (i+2))\n"
"				{\n"
"					break\n"
"				}\n"
"				\n"
"				cnt = $(i+2)\n"
"				break\n"
"			}\n"
"		}\n"
"		if(0 == has_one)\n"
"		{\n"
"			print cnt\n"
"			has_one = 1\n"
"		}\n"
"	}\n"
"	END{\n"
"		if(0 == NR)\n"
"		{\n"
"			print 0\n"
"		}\n"
"	}\n"
"'\n"
};

/*CWWTPCheckForWTPEventAPInfo*/
#define GET_WTP_ETH_RT_INFO(strValue, len_strValue, paraFileName, paraBytes)		{	\
	int len_strTmp;	\
	char strTmp[100]; \
	unsigned long *paraVal_4; \
	unsigned long long *paraVal_8; \
	\
	char paraFullFileName[280] = "cat /sys/class/net/eth0/statistics/";	\
	strcat(paraFullFileName, paraFileName);	\
	FILE *fp = popen(paraFullFileName, "r");	\
	fgets(strTmp, 100, fp);	\
	pclose(fp);	\
	\
	len_strTmp = strlen(strTmp); \
	if(strlen(strTmp))\
		strTmp[len_strTmp - 1] = '\0'; \
	CW_ZERO_MEMORY(strValue, len_strValue);	\
	\
	switch(paraBytes) \
	{ \
	case 4: \
		paraVal_4 = (unsigned long *)&strValue[0];\
		*paraVal_4 = strtoul(strTmp, NULL, 10); \
		*paraVal_4 = ntohl(*paraVal_4); \
		break; \
	case 8: \
		paraVal_8 = (unsigned long long *)&strValue[0];\
		*paraVal_8 = strtoull(strTmp, NULL, 10); \
		*paraVal_8 = __ntohll(*paraVal_8); \
		break; \
	default: \
		break; \
	} \
}

#define GET_INTERFACE_xCAST_INFO(strValue, len_strValue, EbtablesName, IntfaceName, xCAST, PktCnt_or_ByteCnt)		{	\
	int len_strTmp;	\
	char strTmp[100]; \
	char cmd[490] = "";	\
	unsigned long long *paraVal; \
	\
	sprintf(cmd, xCAST_info_cmd, EbtablesName, IntfaceName, xCAST, PktCnt_or_ByteCnt, PktCnt_or_ByteCnt);	\
    FILE *fp = popen(cmd, "r");	\
	fgets(strTmp, 100, fp);	\
	pclose(fp);	\
	\
	paraVal = (unsigned long long *)&strValue[0];\
	len_strTmp = strlen(strTmp); \
	strTmp[len_strTmp - 1] = '\0'; \
	CW_ZERO_MEMORY(strValue, len_strValue);	\
	*paraVal = strtoull(strTmp, NULL, 10); \
	*paraVal = __ntohll(*paraVal); \
}

#define GET_WTP_ETH_RT_xCAST_INFO(strValue, len_strValue, EbtablesName, xCAST, PktCnt_or_ByteCnt) GET_INTERFACE_xCAST_INFO \
	(strValue, len_strValue, EbtablesName, "eth0", xCAST, PktCnt_or_ByteCnt)
#define GET_WTP_WLAN_RT_xCAST_INFO_ForOneSSID                                                     GET_INTERFACE_xCAST_INFO


#define GET_WTP_WLAN_RT_INFO_ForOneSSID(strValue, len_strValue, paraFileName, paraBytes, wlanname)		{	\
	int len_strTmp;	\
	char strTmp[100] = {0}; \
	unsigned long *paraVal_4; \
	unsigned long long *paraVal_8; \
	\
	char paraFullFileName[280] = "cat /sys/class/net/";	\
	strcat(paraFullFileName, wlanname);	\
	strcat(paraFullFileName, "/statistics/");	\
	strcat(paraFullFileName, paraFileName);	\
	FILE *fp = popen(paraFullFileName, "r");	\
	fgets(strTmp, 100, fp);	\
	pclose(fp);	\
	\
	len_strTmp = strlen(strTmp); \
	if(strlen(strTmp))\
		strTmp[len_strTmp - 1] = '\0'; \
	CW_ZERO_MEMORY(strValue, len_strValue);	\
	\
	switch(paraBytes) \
	{ \
	case 4: \
		paraVal_4 = (unsigned long *)&strValue[0];\
		*paraVal_4 = strtoul(strTmp, NULL, 10); \
		*paraVal_4 = ntohl(*paraVal_4); \
		break; \
	case 8: \
		paraVal_8 = (unsigned long long *)&strValue[0];\
		*paraVal_8 = strtoull(strTmp, NULL, 10); \
		*paraVal_8 = __ntohll(*paraVal_8); \
		break; \
	default: \
		break; \
	} \
}

#define GET_WTP_WLAN_RT_INFO(strValue, len_strValue, paraFileName, paraBytes)		{	\
	unsigned short vap_idx = 0; \
	unsigned short wlan_idx = 0; \
	unsigned long long ull_paraVal_tal = 0; \
	unsigned long long *ullp_paraVal_one = NULL; \
	\
	for(vap_idx = 0; vap_idx < (MAX_VAP + 1); vap_idx++){ \
		char wlan_name[16] = {0}; \
		\
		switch(vap_idx) \
		{ \
		case 0: \
			ull_paraVal_tal = 0; \
			ullp_paraVal_one = (unsigned long long *)&strValue[0]; \
			CW_ZERO_MEMORY(strValue, len_strValue); \
			break; \
		case MAX_VAP: \
			ull_paraVal_tal += *ullp_paraVal_one; \
			CW_ZERO_MEMORY(strValue, len_strValue); \
			*ullp_paraVal_one += ull_paraVal_tal; \
			break; \
		default: \
			ull_paraVal_tal += *ullp_paraVal_one; \
			CW_ZERO_MEMORY(strValue, len_strValue); \
			break; \
		} \
		\
		if(vap_idx >= MAX_VAP || 1 != getVapSwitch(vap_idx+(index-1)*8)) \
			continue; \
		\
		memset(wlan_name,'\0',sizeof(wlan_name)); \
		 \
		if(index == 1){ \
			if(wlan_idx) \
				sprintf(wlan_name, "ath0%d", wlan_idx); \
			else \
				sprintf(wlan_name, "ath0"); \
		}else{ \
			if(wlan_idx) \
				sprintf(wlan_name, "ath1%d", wlan_idx); \
			else \
				sprintf(wlan_name, "ath1"); \
		} \
		\
		wlan_idx += 1; \
		GET_WTP_WLAN_RT_INFO_ForOneSSID(strValue, len_strValue, paraFileName, paraBytes, wlan_name); \
	} \
}

#define GET_WTP_WLAN_RT_xCAST_INFO(strValue, len_strValue, EbtablesName, xCAST, PktCnt_or_ByteCnt)		{	\
	unsigned short vap_idx = 0; \
	unsigned short wlan_idx = 0; \
	unsigned long long ull_paraVal_tal = 0; \
	unsigned long long *ullp_paraVal_one = NULL; \
	\
	for(vap_idx = 0; vap_idx < (MAX_VAP + 1); vap_idx++){ \
		char wlan_name[16] = {0}; \
		\
		switch(vap_idx) \
		{ \
		case 0: \
			ull_paraVal_tal = 0; \
			ullp_paraVal_one = (unsigned long long *)&strValue[0]; \
			CW_ZERO_MEMORY(strValue, len_strValue); \
			break; \
		case MAX_VAP: \
			ull_paraVal_tal += *ullp_paraVal_one; \
			CW_ZERO_MEMORY(strValue, len_strValue); \
			*ullp_paraVal_one += ull_paraVal_tal; \
			break; \
		default: \
			ull_paraVal_tal += *ullp_paraVal_one; \
			CW_ZERO_MEMORY(strValue, len_strValue); \
			break; \
		} \
		\
		if(vap_idx >= MAX_VAP || 1 != getVapSwitch(vap_idx+(index-1)*8)) \
			continue; \
		\
		memset(wlan_name,'\0',sizeof(wlan_name)); \
		 \
		if(index == 1){ \
			if(wlan_idx) \
				sprintf(wlan_name, "ath0%d", wlan_idx); \
			else \
				sprintf(wlan_name, "ath0"); \
		}else{ \
			if(wlan_idx) \
				sprintf(wlan_name, "ath1%d", wlan_idx); \
			else \
				sprintf(wlan_name, "ath1"); \
		} \
		\
		wlan_idx += 1; \
		GET_WTP_WLAN_RT_xCAST_INFO_ForOneSSID(strValue, len_strValue, EbtablesName, wlan_name, xCAST, PktCnt_or_ByteCnt); \
	} \
}

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

    /* update wtp ap info */
	CWWTPCheckForWTPEventPublicInfo(CW_MSG_WTP_EVENT_PUBLIC_INFO);
    /* update sta info */
	CWWTPCheckForWTPEventPrivateInfo(CW_MSG_WTP_EVENT_PRIVATE_INFO, 1);
	CWWTPCheckForWTPEventPrivateInfo(CW_MSG_WTP_EVENT_PRIVATE_INFO, 2);
    
    CWLog("**************************************************************");

	gCWWTPEventTimerID = timer_add(gEventInterval, 0, &CWWTPCheckForWTPEventRequest, NULL); 
	if (gCWWTPEventTimerID == -1)	return;
}

void CWProtocolDestroyElem(void *f) {
	CW_FREE_OBJECT(f);
} 

static void CWWTPCopyIntToStr(int value, char *strValue, int len){
	memset(strValue, 0, len);
	value = htonl(value);
	memcpy(strValue, &value, sizeof(int));
}
static void CWWTPCopyStrToStr(char *pString, char *strValue, int len){
	memset(strValue, 0, len);
	memcpy(strValue, pString, strlen(pString));
}

static void CWWTPGetIntValueFromFile(char *strValue, int len, const char *file)
{
	char buf[64] = {0};
	FILE *fp = NULL;

	fp = fopen(file, "r");
    if(fp){
            fgets(buf, sizeof(buf), fp);
            fclose(fp);
            fp = NULL;
    }
	CWWTPCopyIntToStr(atoi(buf), strValue, len);
}
static void CWWTPGetStringFromFile(char *strValue, int len, const char *file)
{
	char buf[64] = {0};
	FILE *fp = NULL;

	memset(strValue, 0, len);

	fp = fopen(file, "r");
    if(fp){
            fgets(buf, sizeof(buf), fp);
            fclose(fp);
            fp = NULL;
    }
	if(strlen(buf) && buf[strlen(buf)-1] == '\n'){
		buf[strlen(buf)-1] = '\0';
	}
	memcpy(strValue, buf, (len>strlen(buf))?strlen(buf):len);
}

static void CWWTPGetIntValueFromShellCmd(char *strValue, int len, const char *cmd)
{
	char buf[64] = {0};
	FILE *fp = NULL;

	fp = popen(cmd, "r");
    if(fp){
            fgets(buf, sizeof(buf), fp);
            pclose(fp);
            fp = NULL;
    }
	CWWTPCopyIntToStr(atoi(buf), strValue, len);
}
static void CWWTPGetStringFromShellCmd(char *strValue, int len, const char *cmd)
{
	char buf[256] = {0};
	FILE *fp = NULL;

//	printf("%s\n", cmd);
	memset(strValue, 0, len);
	fp = popen(cmd, "r");
    if(fp){
            fgets(buf, sizeof(buf), fp);
            pclose(fp);
            fp = NULL;
    }
	if(strlen(buf) && buf[strlen(buf)-1] == '\n'){
		buf[strlen(buf)-1] = '\0';
	}
	memcpy(strValue, buf, (len>strlen(buf))?strlen(buf):len);
}

static void CWWTPGetWTPTxpower(char *strValue, int len, const char *cmd)
{
	char buf[128] = {0};
	char *p = NULL;
	int value = 0;
	int strLength = 0;

	memset(strValue, 0, len);
	CWWTPGetStringFromShellCmd(buf, sizeof(buf), cmd);
	if(strlen(buf)){
		p = strstr(buf, ":") + 1;
		value = strtod(p, NULL);
		sprintf(strValue, "%d", value);
		strLength = strlen(strValue);
		/*< ZDC上报当前发射功率为5字节，ZDC发射功率步长为0.5，而openwrt为1,为兼容，后面以字符串添加.0*/
		strValue[strLength] = '.';
		strValue[strLength+1] = '0';
	}
}
static void CWWTPGetWTPMaxTxpower(char *strValue, int len, int value)
{
	int strLength = 0;

	memset(strValue, 0, len);
	
	sprintf(strValue, "%d", value);
	strLength = strlen(strValue);
	/*< ZDC上报当前发射功率为5字节，ZDC发射功率步长为0.5，而openwrt为1,为兼容，后面以字符串添加.0*/
	strValue[strLength] = '.';
	strValue[strLength+1] = '0';
}

static void CWWTPGetWTPLanProto(char *strValue, int len, const char *cmd)
{
	char buf[64] = {0};

	memset(strValue, 0, len);
	CWWTPGetStringFromShellCmd(buf, sizeof(buf), cmd);
	if(!strcmp(buf, "static")){
		CWWTPCopyIntToStr(0, strValue, len);
	}else if(!strcmp(buf, "dhcp")){
		CWWTPCopyIntToStr(1, strValue, len);
	}else if(!strcmp(buf, "dhcpv6")){
		CWWTPCopyIntToStr(2, strValue, len);
	}else if(!strcmp(buf, "pppoe")){
		CWWTPCopyIntToStr(3, strValue, len);
	}else{
		CWWTPCopyIntToStr(4, strValue, len);
	}
}

static void CWWTPGetWTPNetMask(char *strValue, int len, const char *cmd)
{
	char buf[64] = {0};
	char *p = NULL;
	int i = 0;
	
	memset(strValue, 0, len);
	CWWTPGetStringFromShellCmd(buf, sizeof(buf), cmd);
	p = strtok(buf, ".");
	while(NULL != p){
		strValue[i++] = atoi(p);
//		printf("%d\n", (unsigned char)strValue[i]);
		p = strtok(NULL, ".");
	}
}

static void CWWTPGetBssidName(char *strValue, int len, const char *filepath, char index)
{
	char file[128] = {0};
	int i = 0, flag = 0;
    char wlan[16] = {0};
	
	for(i = 0;i < MAX_VAP;i ++){
		if(getVapSwitch(i+(index-1)*8) == 1){
			if(index == 1){
				if(flag)
					sprintf(wlan, "ath0%d", flag);
				else
					sprintf(wlan, "ath0");
			}else{
				if(flag)
					sprintf(wlan, "ath1%d", flag);
				else
					sprintf(wlan, "ath1");
			}
			flag ++;
			sprintf(file, filepath, wlan);
//			CWWTPGetStringFromFile(strValue+strlen(strValue), len-strlen(strValue), file);
			CWWTPGetStringFromFile(strValue+i*18, len-i*18, file);
//			strValue[strlen(strValue)] = ';';
//			printf("cmdbuf=%s\n", cmdbuf);
		}else{
			CWWTPCopyStrToStr("00:00:00:00:00:00", strValue+i*18, len-i*18);
		}
		strValue[(i+1)*18-1] = ';';
	}
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
	CWDTTLog("AP uptime:%d", value);
}
static void CWWTPGetConnecttime(char *strValue)
{
	time_t connecttime = 0, time_now = 0;

	time_now = time(NULL);

	connecttime = time_now > gWtpPublicInfo.onlinetoACtime ? (time_now-gWtpPublicInfo.onlinetoACtime) : 0;
	memcpy(strValue, (char *)&connecttime, sizeof(time_t));
	CWLog("AP connect to AC time = %d", connecttime);
//		sprintf(strValue, "%d", value);
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

static void CWWTPGetWirelessChan(char *strValue, char index){

	char cmd[64] = {0};
	FILE *fp = NULL;
    char buffer[64] = {0};
	int value = 0;

	sprintf(cmd, "uci get wireless.@wifi-device[%d].channel", index-1);
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

static void CWWTPGetCardType(char *value, char index){
	char cmd[128] = {0};
	FILE *fp = NULL;
    char buffer[128] = {0};

    value[0] = 0;
	
	if(index == 1){
		//sprintf(cmd, "iwinfo | grep wlan0 -A 7 | grep \"nl80211\" | cut -d \":\" -f 3");
        strcpy(cmd, "/sys/class/net/wifi0/hwcaps");
    }
	else{
		//sprintf(cmd, "iwinfo | grep wlan1 -A 7 | grep \"nl80211\" | cut -d \":\" -f 3");
		strcpy(cmd, "/sys/class/net/wifi1/hwcaps");
    }
	fp = fopen(cmd, "r");
	if(fp){
		fgets(buffer, sizeof(buffer), fp);
		if(strlen(buffer) > 0){
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
		}
		fclose(fp);
		fp = NULL;
	}
	
	return;
}

static void CWWTPGetVapConntStaNum(char *strValue, int len, const char *cmd, char index)
{
	char cmdbuf[128] = {0};
	int i = 0, flag = 0;
    char wlan[16] = {0};
	
	for(i = 0;i < MAX_VAP;i ++){
		if(getVapSwitch(i+(index-1)*8) == 1){
			if(index == 1){
				if(flag)
					sprintf(wlan, "ath0%d", flag);
				else
					sprintf(wlan, "ath0");
			}else{
				if(flag)
					sprintf(wlan, "ath1%d", flag);
				else
					sprintf(wlan, "ath1");
			}
			flag ++;
			sprintf(cmdbuf, cmd, wlan);
//			printf("cmdbuf=%s\n", cmdbuf);
			CWWTPGetIntValueFromShellCmd(strValue+i*sizeof(int), len-i*sizeof(int), cmdbuf);
		}
	}
}

/*
 * CWWTPGetAllVapOneStatDetail获取单张射频卡上所统计的所用用户的关联情况
 *
 * wlanStat为从hostapd的输出文件中读取的所有统计信息
 * type为统计的类型，0:invalid 1:timeout 2:reject 3:other
 */
static void CWWTPGetAllVapOneStatDetail(char *strValue, int len, struct hostapd_stat_sta_cfg *wlanStat, char *member, int type)
{
	int value = 0;

	memset(strValue, 0, len);

	switch(type){
		case -1:
			value = wlanStat->radio_deauth;
			break;
		case HOSTAPD_STATISTIC_INVALID:
			if(!strcmp(member, "assoc")){
				/*< 此处认为 无效的关联次数，是用户的关联请求次数减去AP响应关联的次数*/
				value = wlanStat->radio_assoc_req - wlanStat->radio_assoc_resp;
			}else if(!strcmp(member, "auth")){
				/*< 此处认为 无效的认证次数，是认证次数减去响应认证的次数*/
				value = wlanStat->radio_auth_req - wlanStat->radio_auth_resp;
			}else if(!strcmp(member, "reassoc")){
				/*< 此处认为 无效的认证次数，是重关联次数减去响应重认证的次数*/
				value = wlanStat->radio_reassoc_req - wlanStat->radio_reassoc_resp;
			}
			break;
		case HOSTAPD_STATISTIC_TIMEOUT:
			/*< 不做处理，固定为0*/
			break;
		case HOSTAPD_STATISTIC_REJECT:
			if(!strcmp(member, "assoc")){
				/*< 此处认为 无效的关联次数，是AP响应关联的次数减去关联成功次数*/
				value = wlanStat->radio_assoc_resp - wlanStat->radio_assoc_success;
			}else if(!strcmp(member, "auth")){
				/*< 此处认为 无效的关联次数，是AP响应的次数减去成功次数*/
				value = wlanStat->radio_auth_resp - wlanStat->radio_auth_success;
			}else if(!strcmp(member, "reassoc")){
				/*< 此处认为 无效的关联次数，是AP响应的次数减去成功次数*/
				value = wlanStat->radio_reassoc_resp - wlanStat->radio_reassoc_success;
			}
			break;
		case HOSTAPD_STATISTIC_OTHER:
			/*< 不做处理，固定为0*/
			break;
			/*< 协议中描述为用户离开，暂时理解为用户主动断开*/
		case HOSTAPD_STATISTIC_DE_USER_LEAVE:
			if(!strcmp(member, "disassoc")){
				value = wlanStat->radio_active_disassoc;
			}else if(!strcmp(member, "deauth")){
				/*< 无论是否是用户主动断开，deauth都会+1，但active_disassoc只在用户主动断开时+1*/
				value = wlanStat->radio_active_disassoc;
			}
			break;
		case HOSTAPD_STATISTIC_DE_WTP_CAPABILITY:
			/*< 不做处理，固定为0*/
			break;
		case HOSTAPD_STATISTIC_DE_EXCEPTION:
			/*< 不做处理，固定为0*/
			break;
		case HOSTAPD_STATISTIC_DE_OTHER:
			value = wlanStat->radio_deauth - wlanStat->radio_active_disassoc;
			break;
	}
	value = htonl(value);
	
	memcpy(strValue, (char *)&value, sizeof(value));
}

/*
 * CWWTPGetOneVapStatFromFile从hostapd的统计文件中读取结果
 *
 * file_name为要读取的文件名
 * pathid:因单张卡最多可设置8个vap，而hostapd中输出的文件格式均是wlan0,wlan1...格式，和第几个vap无关，此处pathid是根据vap启用情况赋值
 */
static int CWWTPGetOneVapStatFromFile(const char *file_name, int pathid, char index){
	char stat_file[128] = {0};
	FILE *fp = NULL;
	char buffer[8] = {0};
	int value = 0;
	
	sprintf(stat_file, "/tmp/wlan_statistic/statistic_phy%d/wlan%d/%s", index-1, pathid, file_name);
//			printf("statistic_file=%s\n", statistic_file);
	fp = fopen(stat_file, "r");
	if(fp){
		fgets(buffer, sizeof(buffer), fp);
		value=atoi(buffer);
//				printf("value = %d\n", value);
		fclose(fp);
		fp = NULL;
	}
	return value;
}
/*
 * CWWTPGetStaStatisticTimes从hostapd的统计文件中获取结果保存在栈空间
 *
 * wlanStat栈结构，用于保存读取的信息
 */
static void CWWTPGetStaStatisticTimes(struct hostapd_stat_sta_cfg *wlanStat, char index)
{
	int i = 0, pathid = 0;
	
	memset(wlanStat, 0, sizeof(struct hostapd_stat_sta_cfg));

	for(i = 0; i < MAX_VAP;i ++){
		if(getVapSwitch(i+(index-1)*8)){
			/*< 结构改为栈，每次固定大小8个结构*/
//			wlanStat->vap_stat[i] = wtp_malloc(sizeof(struct vap_stat_cfg));
//			if(!wlanStat->vap_stat[i])
//				continue;
			wlanStat->vap_stat[i].auth_req = CWWTPGetOneVapStatFromFile("auth_req", pathid, index);
			wlanStat->radio_auth_req += wlanStat->vap_stat[i].auth_req;
			wlanStat->vap_stat[i].auth_resp = CWWTPGetOneVapStatFromFile("auth_resp", pathid, index);
			wlanStat->radio_auth_resp += wlanStat->vap_stat[i].auth_resp;
			wlanStat->vap_stat[i].auth_success = CWWTPGetOneVapStatFromFile("auth_success", pathid, index);
			wlanStat->radio_auth_success += wlanStat->vap_stat[i].auth_success;
			wlanStat->vap_stat[i].assoc_req = CWWTPGetOneVapStatFromFile("association_req", pathid, index);
			wlanStat->radio_assoc_req += wlanStat->vap_stat[i].assoc_req;
			wlanStat->vap_stat[i].assoc_resp = CWWTPGetOneVapStatFromFile("association_resp", pathid, index);
			wlanStat->radio_assoc_resp += wlanStat->vap_stat[i].assoc_resp;
			wlanStat->vap_stat[i].assoc_success = CWWTPGetOneVapStatFromFile("association_success", pathid, index);
			wlanStat->radio_assoc_success += wlanStat->vap_stat[i].assoc_success;
			wlanStat->vap_stat[i].reassoc_req = CWWTPGetOneVapStatFromFile("reassociation_req", pathid, index);
			wlanStat->radio_reassoc_req += wlanStat->vap_stat[i].reassoc_req;
			wlanStat->vap_stat[i].reassoc_resp = CWWTPGetOneVapStatFromFile("reassociation_resp", pathid, index);
			wlanStat->radio_reassoc_resp += wlanStat->vap_stat[i].reassoc_resp;
			wlanStat->vap_stat[i].reassoc_success = CWWTPGetOneVapStatFromFile("reassociation_success", pathid, index);
			wlanStat->radio_reassoc_success += wlanStat->vap_stat[i].reassoc_success;
			wlanStat->vap_stat[i].active_disassoc = CWWTPGetOneVapStatFromFile("active_disconnect", pathid, index);
			wlanStat->radio_active_disassoc += wlanStat->vap_stat[i].active_disassoc;
			wlanStat->vap_stat[i].deauth = CWWTPGetOneVapStatFromFile("deauth", pathid, index);
			wlanStat->radio_deauth += wlanStat->vap_stat[i].deauth;
			
			pathid ++;
		}
	}
}

/*
 * CWWTPGetVapOneStatTimes 从事先获取的信息结构wlanStat中获取每一个vap的某一类统计结果，并以此写入strValue
 *
 * member: 要获取的是哪一个结果
 */
static void CWWTPGetVapOneStatTimes(char *strValue, int len, struct hostapd_stat_sta_cfg *wlanStat, char *member)
{
	int i = 0;
	int value = 0;
	
	memset(strValue, 0, len);

	for(i = 0; i < MAX_VAP;i ++){
		if(!strcmp(member, "association_req"))
			value = htonl(wlanStat->vap_stat[i].assoc_req);
		else if(!strcmp(member, "association_resp"))
			value = htonl(wlanStat->vap_stat[i].assoc_resp);
		else if(!strcmp(member, "association_success"))
			value = htonl(wlanStat->vap_stat[i].assoc_success);
		memcpy(strValue+i*sizeof(int), &value, sizeof(int));
	}
}

/*
 * CWWTPGetAllVapOneStatTimes 从事先获取的信息结构wlanStat中获取但张卡的某一类统计结果
 *
 * member: 要获取的是哪一个结果
 */
static void CWWTPGetAllVapOneStatTimes(char *strValue, int len, struct hostapd_stat_sta_cfg *wlanStat, char *member)
{
	int i = 0;
	int value = 0;
	long long reassoc = 0;
	
	memset(strValue, 0, len);

	for(i = 0; i < MAX_VAP;i ++){
		if(!strcmp(member, "association_req")){
			value += wlanStat->vap_stat[i].assoc_req;
			
			value = htonl(value);
			memcpy(strValue, &value, sizeof(int));
		}
		else if(!strcmp(member, "reassociation_req")){
			reassoc += wlanStat->vap_stat[i].reassoc_req;
//			printf("radio-%d-wlan%d: cfg_reassoc_req=%d, reassoc=%lld\n", gAPIndex-1, i, wlanStat->vap_stat[i].reassoc_req, reassoc);
			reassoc = __ntohll(reassoc);
			memcpy(strValue, &reassoc, sizeof(long long));
		}
	}
}

/*
 * CWWTPGetVapEnable 获取vap的启用状态
 *
 * 
 */
static void CWWTPGetVapEnable(char *strValue, int len, char index){
	int i = 0;
	int value = 1;
	char *p = strValue;
	
	memset(strValue, 0, len);

	for(i = 0; i < MAX_VAP;i ++){
		/*< 该字符串已做memset处理，所以只讲启用的写为1即可*/
		if(getVapSwitch(i+(index-1)*8)){
			value = htonl(value);
			memcpy(p, &value, sizeof(int));
		}
		p += sizeof(int);
	}
	return;
}

/*
 * CWWTPGetVapSSID 获取vap的的SSID，即使未启用也获取，所以是从配置文件中读取
 *
 * 
 */
static void CWWTPGetVapSSID(char *strValue, int len, char *cmd, char index){
	int i = 0;
	char cmdbuf[128] = {0};

	for(i = (0+MAX_VAP*(index-1)); i < MAX_VAP*index;i ++){
		memset(cmdbuf, 0, sizeof(cmdbuf));
		sprintf(cmdbuf, cmd, i);
		/*< capwap协议中，每个SSID长度为40*/
		CWWTPGetStringFromShellCmd(strValue+40*(i-MAX_VAP*(index-1)), len -40*(i-MAX_VAP*(index-1)), cmdbuf);
	}
	return;
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
	FILE* iwinfoFp = NULL;
	FILE* staOntimeFp = NULL;
	char buffer[1024] = {0};
	char macbuffer[64] = {0};
	unsigned int tmpaddr[6] = {0};
	char *p = NULL;
	staInfo *sta = NULL;
	char ssid[32] = {0};
	char tmpbuffer[64] = {0};
    int i = 1;

	CW_ZERO_MEMORY(cmd, sizeof(cmd));
	//sprintf(cmd, "iw dev %s info | grep ssid", card);
	//strcat(cmd,  " | awk '{printf \"%s\",$2}'");
	sprintf(cmd, "iwconfig %s | grep ESSID:", card);
	strcat(cmd,  " | awk -F'\"' '{printf $2}'");
    //CWDTTLog("info cmd is:%s", cmd);
    
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

#if 0
    /****************************************************************************************************/
	CW_ZERO_MEMORY(cmd, sizeof(cmd));
	sprintf(cmd, "iwinfo %s assoclist", card);
	iwinfoFp = popen(cmd,"r");

	CW_ZERO_MEMORY(cmd, sizeof(cmd));
	sprintf(cmd, "iw dev %s station dump", card);
	tmp = popen(cmd,"r");

	CW_ZERO_MEMORY(cmd, sizeof(cmd));
	/*< 该文件由hostapd进行记录，sta关联成功，添加记录并记录时间，时间格式为time_t，解除关联后，删除记录*/
	sprintf(cmd, "/tmp/wlan_statistic/statistic_phy%d/sta_record", (index>=8) ? 1 : 0);
	staOntimeFp = fopen(cmd, "r");

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

				CW_ZERO_MEMORY(macbuffer, sizeof(macbuffer));

				snprintf(macbuffer, 18, "%s", buffer+8);
				sscanf(macbuffer, "%2x:%2x:%2x:%2x:%2x:%2x", tmpaddr, tmpaddr+1, tmpaddr+2, tmpaddr+3,tmpaddr+4, tmpaddr+5);
//				CWLog("macbuffer:%s", macbuffer);
				sta->mac[0] = tmpaddr[0];sta->mac[1] = tmpaddr[1];sta->mac[2] = tmpaddr[2];
				sta->mac[3] = tmpaddr[3];sta->mac[4] = tmpaddr[4];sta->mac[5] = tmpaddr[5];
				getStaIP(macbuffer, sta);
				sta->vlanID = htonl(getVapVlanID(index));
				CW_ZERO_MEMORY(buffer, sizeof(buffer));
				if(iwinfoFp){
					fseek(iwinfoFp, 0, SEEK_SET);
					while(fgets(buffer, sizeof(buffer), iwinfoFp)){
						if(!strncasecmp(macbuffer, buffer, strlen(macbuffer))){
//							p = strstr(buffer, "/")+1;
//							sta->noise = htonl(strtod(p, NULL));
							p = strstr(buffer, "SNR")+3;
							sta->SNR = htonl(strtod(p, NULL));
							CW_ZERO_MEMORY(buffer, sizeof(buffer));
							break;
						}
						CW_ZERO_MEMORY(buffer, sizeof(buffer));
					}
				}
				CW_ZERO_MEMORY(buffer, sizeof(buffer));
				if(staOntimeFp){
					fseek(staOntimeFp, 0, SEEK_SET);
					while(fgets(buffer, sizeof(buffer), staOntimeFp)){
						if(!strncasecmp(macbuffer, buffer, strlen(macbuffer))){
							p = strstr(buffer, "-")+1;
							sta->connttime = strtod(p, NULL);
							sta->ontime = 1000 * (time(NULL) - sta->connttime);
							sta->ontime = __ntohll(sta->ontime);
							CW_ZERO_MEMORY(buffer, sizeof(buffer));
							break;
						}
						CW_ZERO_MEMORY(buffer, sizeof(buffer));
					}
				}
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
				/*< 因iwinfo和iw无法读取到重发送的字节数，暂时先做假数据*/
				if(sta->packageTx)
					sta->resendbytes = sta->resendPackage * sta->bytesTx / sta->packageTx;
				else
					sta->resendbytes = 0;
			}
			if(strstr(buffer, "tx failed"))
			{
				p = strstr(buffer, ":")+1;
				sta->sendFail = strtoul(p, NULL, 10);
				sta->sendFail = __ntohll(sta->sendFail);
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
		pclose(iwinfoFp);
		iwinfoFp = NULL;
		pclose(tmp);
		tmp = NULL;
	}
    /***************************************************************************************/
	if(staOntimeFp){
		fclose(staOntimeFp);
		staOntimeFp = NULL;
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
                    /* idel > 0\A3\AC\D4\F2?\BD?\E7??*/
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

static stalist *getAllWlanStaInfo(const char index)
{
    char card[16] = {0};
    int i = 0;
	int flag = 0;
	
	stalist *list = NULL;
	CW_CREATE_OBJECT_ERR(list, stalist, return NULL;);
	list->info = NULL;
	list->count = 0;

	for(i = 0;i < MAX_VAP;i ++){
		if(getVapSwitch(i+(index-1)*8) == 1){
			if(index == 1){
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
			getOneWlanStaInfo(card, list, i+(index-1)*8);
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

static void CWWTPCopyOption43IP(char *strValue, int len)
{
	int i = 0;
	option43_ip_cfg *option43ip = NULL;
	option43ip = (option43_ip_cfg *)getOption43Info();

	memset(strValue, 0, len);
	for(i = 0; i < 4;i ++)
		memcpy(strValue+i*4, option43ip[i].ip, 4);
}

CWBool CWWTPCheckForWTPEventPublicInfo(unsigned short msgElemType){
	CWLog("#__ WTP Event Request Message (Public WTP && AP Info) ___#");
	
	/* Send WTP Event Request */
	CWList msgElemList = NULL;
	CWProtocolMessage *messages = NULL;
	int fragmentsNum = 0;
	int seqNum;
//	int *pendingReqIndex;
	char strValue[1024] = {0};
	unsigned char countrycode = 0;
	seqNum = CWGetSeqNum();

    CWNetworkGetWTPIP(gWtpPublicInfo.ethIP);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_IP, gWtpPublicInfo.ethIP, 4);
    
	CW_ZERO_MEMORY(strValue, 1024);
	getWTPName(NULL, (char *)strValue, 32);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_NAME, strValue, strlen(strValue)+1);
	CW_ZERO_MEMORY(strValue, 1024);
	countrycode = (unsigned char)getCountryCodeCfg();
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_COUNTRYCODE, &countrycode, sizeof(unsigned char));
	CWWTPGetIntValueFromFile(strValue, 1024, WTP_ETH_MTU_FILE_PATH);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_MTU, strValue, 4);

	CWWTPCopyStrToStr(gWtpPublicInfo.fwModel, strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_FIRMWARE_VERSION, strValue, strlen(strValue)+1);//16
	CW_ZERO_MEMORY(strValue, 1024);
	CWWTPGetCPUUsage(strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_CPU_USAGE, strValue, 10);
	CW_ZERO_MEMORY(strValue, 1024);
	sprintf(strValue, MACSTR, MAC2STR((unsigned char *)gWtpPublicInfo.ethMac));
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_NETWORK_CODE, strValue, 32);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_SERIAL_NUMBER, gWtpPublicInfo.sn, 32);
	CWWTPGetWTPLanProto(strValue, 1024, WTP_GET_UCI_LAN_PROTO);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_IP_TYPE, strValue, 4);//22

	CWWTPGetRAMUsage(strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_MEM_USAGE, strValue, strlen(strValue)+1);
	CW_ZERO_MEMORY(strValue, 1024);
	CWWTPGetFlashUsage(strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_FLASH_USAGE, strValue, strlen(strValue)+1);
	
	CWWTPGetWTPNetMask(strValue, 1024, WTP_GET_NETWORK_MASK);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_NETWORK_MASK, strValue, 4);
	
	CWWTPCopyStrToStr(gWtpPublicInfo.apModel, strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_PRODUCT_NAME, strValue, strlen(strValue)+1);

	GET_WTP_ETH_RT_INFO(strValue, 1024, "rx_packets", 8);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_ETH_RX_TOTAL_PACKAGE, strValue, 8);
	GET_WTP_ETH_RT_INFO(strValue, 1024, "tx_packets", 8);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_ETH_TX_TOTAL_PACKAGE, strValue, 8);
	GET_WTP_ETH_RT_INFO(strValue, 1024, "rx_bytes", 8);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_ETH_RX_TOTAL_BYTES, strValue, 8);
	GET_WTP_ETH_RT_INFO(strValue, 1024, "tx_bytes", 8);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_ETH_TX_TOTAL_BYTES, strValue, 8);
	GET_WTP_ETH_RT_xCAST_INFO(strValue, 1024, "RX_STATISTIC", "Unicast", "pcnt");
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_ETH_RX_UNICAST_PACKAGE, strValue, 8);
	GET_WTP_ETH_RT_xCAST_INFO(strValue, 1024, "TX_STATISTIC", "Unicast", "pcnt");
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_ETH_TX_UNICAST_PACKAGE, strValue, 8);
	GET_WTP_ETH_RT_xCAST_INFO(strValue, 1024, "RX_STATISTIC", "Multicast", "pcnt");
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_ETH_RX_MULTI_PACKAGE, strValue, 8);
	GET_WTP_ETH_RT_xCAST_INFO(strValue, 1024, "TX_STATISTIC", "Multicast", "pcnt");
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_ETH_TX_MULTI_PACKAGE, strValue, 8);
	unsigned long long *paraVal_rx = (unsigned long long *)&strValue[0]; *paraVal_rx = 0x1ff;
	*paraVal_rx = __ntohll(*paraVal_rx);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_ETH_RX_THROUGHPUT, strValue, 8);
	unsigned long long *paraVal_tx = (unsigned long long *)&strValue[0]; *paraVal_tx = 0x200;
	*paraVal_tx = __ntohll(*paraVal_tx);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_ETH_TX_THROUGHPUT, strValue, 8);
	GET_WTP_ETH_RT_INFO(strValue, 1024, "rx_errors", 4);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_ETH_RX_ERR_PACKAGE, strValue, 4);
	GET_WTP_ETH_RT_INFO(strValue, 1024, "tx_errors", 4);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_ETH_TX_ERR_PACKAGE, strValue, 4);
	GET_WTP_ETH_RT_INFO(strValue, 1024, "rx_dropped", 4);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_ETH_RX_DROP_PACKAGE, strValue, 4);
	GET_WTP_ETH_RT_INFO(strValue, 1024, "tx_dropped", 4);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_ETH_TX_DROP_PACKAGE, strValue, 4);
	unsigned long *paraVal_ut = (unsigned long *)&strValue[0]; *paraVal_ut = 0x2;
	*paraVal_ut = ntohl(*paraVal_ut);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_ETH_UP_OR_DOWN_TIME, strValue, 4);


	CWWTPGetStringFromShellCmd(strValue, sizeof(strValue), WTP_GET_AP_CPU_INFO);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_CPU_INFO, strValue, 64);
	
	CWWTPCopyStrToStr(gWtpPublicInfo.hwModel, strValue, 1024);
	CWWTPCopyStrToStr(",", strValue+strlen(strValue), 1024-strlen(strValue));
	CWWTPCopyStrToStr(gWtpPublicInfo.fwModel, strValue+strlen(strValue), 1024-strlen(strValue));
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_SYSTEM_DES, strValue, strlen(strValue)+1);
	
	CWWTPGetIntValueFromFile(strValue, 1024, WTP_ETH_WIDTH_FILE_PATH);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_ETH_WIDTH, strValue, 4);
	CWWTPCopyIntToStr(1, strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_VAP_IP_CHANGED, strValue, 4);
	CWWTPCopyIntToStr(getDataTunnelIP(), strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_DATA_TUNNEL_IP, strValue, 4);
	CWWTPCopyStrToStr("eth0", strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_NAME_ETH, strValue, 5);
	CWWTPCopyStrToStr("Up", strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_STATUS_ETH, strValue, 3);
	CWWTPCopyStrToStr("V1.2.0", strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_AP_HARDWARE_VERSION, strValue, strlen(strValue)+1);

	CWWTPCopyOption43IP(strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_AP_OPTION_43_IP, strValue, 16);
	CWWTPCopyIntToStr(1500, strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_AP_MTU, strValue, 4);


	/*< public信息，radio id为0*/
	if(!CWAssembleWTPEventRequest(&messages, &fragmentsNum, gWTPPathMTU, seqNum, msgElemList, msgElemType, 0, 0)){
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

	int i;
	for(i = 0; i < fragmentsNum; i++) {
		if(!CWNetworkSendUnsafeConnected(gWTPSocket, messages[i].msg, messages[i].offset)) {
			return -1;
		}
		CW_FREE_PROTOCOL_MESSAGE(messages[i]);
	}
	CW_FREE_OBJECT(messages);
	
//	CWDeleteList(&msgElemList, CWProtocolDestroyMsgElemData);

	return CW_TRUE;
}

static void packetProtocolStaInfo(char **p, unsigned short type, char *strValue, unsigned short size)
{
	if(!*p)
		return;

	memcpy(*p, &type, sizeof(unsigned short));
	*p += sizeof(unsigned short);
	memcpy(*p, &size, sizeof(unsigned short));
	*p += sizeof(unsigned short);
	memcpy(*p, strValue, size);
	*p += size;

	return;
}

static protocolStaInfo *CWWTPGetStaInfo(const char index)
{
//	int *pendingReqIndex;
	int count = 0;
	unsigned long long throughput = 0;
	protocolStaInfo *staProto;

	staProto = malloc(sizeof(protocolStaInfo));
	CW_ZERO_MEMORY(staProto, sizeof(protocolStaInfo));

//	CW_CREATE_OBJECT_ERR(pendingReqIndex, int, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

	staInfo *sta = NULL;
	/*< 通过iwinfo获取到所有虚拟节点的sta信息*/
	stalist *list = getAllWlanStaInfo(index);

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
//	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.noise, 4*list->count, return CW_FALSE;);
//	CW_ZERO_MEMORY(AllStaList.noise, 4*list->count);
	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.SNR, 4*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.SNR, 4*list->count);
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
	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.sendFail, 4*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.sendFail, 4*list->count);
	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.throughput, 8*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.throughput, 8*list->count);
	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.resendbytes, 8*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.resendbytes, 8*list->count);
	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.ontime, 8*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.ontime, 8*list->count);
	CW_CREATE_OBJECT_SIZE_ERR(AllStaList.connttime, 4*list->count, return CW_FALSE;);
	CW_ZERO_MEMORY(AllStaList.connttime, 4*list->count);

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
//		memcpy((char *)AllStaList.noise+4*count, &sta->noise, 4);
		memcpy((char *)AllStaList.SNR+4*count, &sta->SNR, 4);
		memcpy((char *)AllStaList.txBitrate+4*count, &sta->txBitrate, 4);
		memcpy((char *)AllStaList.savePowerMode+4*count, &sta->savePowerMode, 4);
		memcpy((char *)AllStaList.vlanID+4*count, &sta->vlanID, 4);
		memcpy((char *)AllStaList.packageTx+8*count, &sta->packageTx, 8);
		memcpy((char *)AllStaList.packageRx+8*count, &sta->packageRx, 8);
		memcpy((char *)AllStaList.bytesTx+8*count, &sta->bytesTx, 8);
		memcpy((char *)AllStaList.bytesRx+8*count, &sta->bytesRx, 8);
		memcpy((char *)AllStaList.WMM+4*count, &sta->WMM, 4);
		memcpy((char *)AllStaList.resendPackage+8*count, &sta->resendPackage, 8);
		memcpy((char *)AllStaList.sendFail+4*count, &sta->sendFail, 4);
		throughput = __ntohll(sta->bytesTx+sta->bytesRx);
		memcpy((char *)AllStaList.throughput+8*count, &throughput, 8);
		memcpy((char *)AllStaList.resendbytes+8*count, &sta->resendbytes, 8);
		memcpy((char *)AllStaList.ontime+8*count, &sta->ontime, 8);
		memcpy((char *)AllStaList.connttime+4*count, &sta->connttime, 4);
//		CWLog("list->count is %d, list->ssid is %s, AllStaList->mac:%02x:%02x:%02x:%02x:%02x:%02x, wmm[0]:%d", list->count, sta->ssid, AllStaList.mac[0], AllStaList.mac[1],AllStaList.mac[2],
//			AllStaList.mac[3],AllStaList.mac[4],AllStaList.mac[5], AllStaList.WMM[0]);
		count ++;
		sta = sta->next;
	}
//	CWLog("list->count is %d, list->ssid is %s, AllStaList->mac:%02x:%02x:%02x:%02x:%02x:%02x, wmm[0]:%d, wmm[1]:%d, packageRx[0]:%d, packageRx[1]:%d", list->count, sta->ssid, AllStaList.mac[0], AllStaList.mac[1],AllStaList.mac[2],
//		AllStaList.mac[3],AllStaList.mac[4],AllStaList.mac[5], AllStaList.WMM[0], AllStaList.WMM[1], AllStaList.packageRx[0], AllStaList.packageRx[1]);

//	CWLog("p size = %d, info size = %d", sizeof(staInfoList), sizeof(staInfo));
	/*< sta个数占4字节，协议ID加上length占4字节，staInfoList结构均为在用指针，可用于统计协议数，后面部分为sta信息占用字节数*/
	staProto->size = 4 + 4*sizeof(staInfoList)/4 + (sizeof(staInfo)-4)*count;
	staProto->pData = malloc(staProto->size);
	if(staProto->pData)
		CW_ZERO_MEMORY(staProto->pData, staProto->size);
	else{
		CW_FREE_OBJECT(staProto);
		goto ERR;
	}
//	int vlanid = 1001;
	char *p = staProto->pData;
	memcpy(p, &count, sizeof(int));
	p += sizeof(int);
	/*< 封装sta信息，sta的宏直接使用了WTP的宏，所以命名会不一致*/
	packetProtocolStaInfo(&p, CW_MSG_ELEMENT_WTP_EVENT_WTP_MAC, (char *)AllStaList.mac, 6*list->count);

	packetProtocolStaInfo(&p, CW_MSG_ELEMENT_WTP_EVENT_WTP_IP, (char *)AllStaList.ip, 4*list->count);
	packetProtocolStaInfo(&p, CW_MSG_ELEMENT_WTP_EVENT_WTP_NAME, (char *)AllStaList.txBitrate, 4*list->count);
	packetProtocolStaInfo(&p, CW_MSG_ELEMENT_WTP_EVENT_WTP_COUNTRYCODE, (char *)AllStaList.savePowerMode, 4*list->count);
	packetProtocolStaInfo(&p, CW_MSG_ELEMENT_WTP_EVENT_WTP_CARDMODE, (char *)AllStaList.ssid, 33*list->count);
	packetProtocolStaInfo(&p, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLANFLOW, (char *)AllStaList.ontime, 8*list->count);//6
	packetProtocolStaInfo(&p, CW_MSG_ELEMENT_WTP_EVENT_WTP_SIGNAL, (char *)AllStaList.signal, 4*list->count);
	packetProtocolStaInfo(&p, CW_MSG_ELEMENT_WTP_EVENT_WTP_MTU, (char *)AllStaList.SNR, 4*list->count);//8
	packetProtocolStaInfo(&p, CW_MSG_ELEMENT_WTP_EVENT_WTP_CHANNEL, (char *)AllStaList.packageTx, 8*list->count);
	packetProtocolStaInfo(&p, CW_MSG_ELEMENT_WTP_EVENT_WTP_BSSID_COUNT, (char *)AllStaList.packageRx, 8*list->count);
	packetProtocolStaInfo(&p, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_BSSID_COUNT, (char *)AllStaList.bytesTx, 8*list->count);
	packetProtocolStaInfo(&p, CW_MSG_ELEMENT_WTP_EVENT_WTP_CONNECT_AC_DURATION, (char *)AllStaList.bytesRx, 8*list->count);
	packetProtocolStaInfo(&p, CW_MSG_ELEMENT_WTP_EVENT_WTP_BSSID_NAME, (char *)AllStaList.WMM, 4*list->count);//14
	packetProtocolStaInfo(&p, CW_MSG_ELEMENT_WTP_EVENT_WTP_CUBSSID_NAME, (char *)AllStaList.throughput, 8*list->count);//15
	packetProtocolStaInfo(&p, CW_MSG_ELEMENT_WTP_EVENT_WTP_FIRMWARE_VERSION, (char *)AllStaList.vlanID, 4*list->count);
	
	packetProtocolStaInfo(&p, CW_MSG_ELEMENT_WTP_EVENT_WTP_LOCATION, (char *)AllStaList.sendFail, 4*list->count);//19 0x13
	packetProtocolStaInfo(&p, CW_MSG_ELEMENT_WTP_EVENT_WTP_GATEWAY, (char *)AllStaList.resendPackage, 8*list->count);
//	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_SYSLOG_SERVER, NULL, 4*list->count);//24 0x18
//	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_MEM_USAGE, NULL, 4*list->count);//25
//	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_FLASH_USAGE, NULL, 4*list->count);//26
//	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_NETWORK_MASK, NULL, 4*list->count);//27
	packetProtocolStaInfo(&p, CW_MSG_ELEMENT_WTP_EVENT_WTP_WIDS_FLOODING, (char *)AllStaList.connttime, 4*list->count);//30
	packetProtocolStaInfo(&p, CW_MSG_ELEMENT_WTP_EVENT_WTP_LAST_BOOT_TIME, (char *)AllStaList.resendbytes, 8*list->count);//34
	
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
//	CW_FREE_OBJECT(AllStaList.noise);
	CW_FREE_OBJECT(AllStaList.SNR);
	CW_FREE_OBJECT(AllStaList.packageTx);
	CW_FREE_OBJECT(AllStaList.packageRx);
	CW_FREE_OBJECT(AllStaList.bytesTx);
	CW_FREE_OBJECT(AllStaList.bytesRx);
	CW_FREE_OBJECT(AllStaList.WMM);
	CW_FREE_OBJECT(AllStaList.resendPackage);
	CW_FREE_OBJECT(AllStaList.sendFail);
	CW_FREE_OBJECT(AllStaList.throughput);
	CW_FREE_OBJECT(AllStaList.resendbytes);
	CW_FREE_OBJECT(AllStaList.ontime);
	CW_FREE_OBJECT(AllStaList.connttime);

	/*< 若计算的大小不一致，则直接返回NULL*/
	if(p - staProto->pData != staProto->size){
		CWLog("data is err#########");
		CW_FREE_OBJECT(staProto->pData);
		CW_FREE_OBJECT(staProto);
		goto ERR;
	}
	
	return staProto;
ERR:
	return NULL;
}

CWBool CWWTPCheckForWTPEventPrivateInfo(unsigned short msgElemType, char index){
	CWLog("#__ WTP Event Request Message (Private card %d sta Info) ___#", index);
	    
    /* Send WTP Event Request */
	CWList msgElemList = NULL;
	CWProtocolMessage *messages = NULL;
	int fragmentsNum = 0;
	int seqNum;
//	int *pendingReqIndex;
	char strValue[1024] = {0};
	struct hostapd_stat_sta_cfg hostapd_stat;

	//CWWTPGetStaStatisticTimes(&hostapd_stat, index);
	seqNum = CWGetSeqNum();

	if(1 == index)
		CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_MAC, gWtpPublicInfo.wlan0Mac, 6);
	else
		CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_MAC, gWtpPublicInfo.wlan1Mac, 6);

	CW_ZERO_MEMORY(strValue, 1024);
	CWWTPGetCardType(strValue, index);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_CARDMODE, strValue, 1);
	CWWTPGetIntValueFromFile(strValue, 1024, (index==1) ? WTP_WLAN0_MTU_FILE_PATH : WTP_WLAN1_MTU_FILE_PATH);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_MTU, strValue, 4);
	CWWTPGetWirelessChan(strValue, index);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_CHANNEL, strValue, 4);
	
	CWWTPCopyIntToStr(MAX_VAP, strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_BSSID_COUNT, strValue, sizeof(int));
	
	CWWTPGetIntValueFromShellCmd(strValue, 1024, (index == 1) ? WTP_GET_CARD1_VAP_NUM_CMD : WTP_GET_CARD2_VAP_NUM_CMD);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_BSSID_COUNT, strValue, sizeof(int));
	CW_ZERO_MEMORY(strValue, 1024);
	CWWTPGetConnecttime(strValue);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_CONNECT_AC_DURATION, strValue, sizeof(time_t));
	CW_ZERO_MEMORY(strValue, 1024);
	CWWTPGetUptime(strValue);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_UPTIME, strValue, 4);
	
	//CWWTPGetBssidName(strValue, 1024, WTP_WLAN_BSSID_NAME, index); (index==1) ? gWtpPublicInfo.wlan0Mac : gWtpPublicInfo.wlan1Mac
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_BSSID_NAME, (index==1) ? gWtpPublicInfo.wlan0Mac : gWtpPublicInfo.wlan1Mac, 160);//15
	
	CWWTPGetWTPTxpower(strValue, 1024, (index == 1) ? WTP_GET_WLAN_0_TXPOWER : WTP_GET_WLAN_1_TXPOWER);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_TX_POWER, strValue, 5);//21
	
	strValue[0] = getWirelessMode(index);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WIRELESS_MODE, strValue, 1);//40

	GET_WTP_WLAN_RT_INFO(strValue, 1024, "rx_packets", 8);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_RX_TOTAL_PACKAGE, strValue, 8);
	GET_WTP_WLAN_RT_INFO(strValue, 1024, "tx_packets", 8);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_TX_TOTAL_PACKAGE, strValue, 8);
	GET_WTP_WLAN_RT_INFO(strValue, 1024, "rx_bytes", 8);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_RX_TOTAL_BYTES, strValue, 8);
	GET_WTP_WLAN_RT_INFO(strValue, 1024, "tx_bytes", 8);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_TX_TOTAL_BYTES, strValue, 8);
	GET_WTP_WLAN_RT_xCAST_INFO(strValue, 1024, "RX_STATISTIC", "Unicast", "pcnt");
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_RX_UNICAST_PACKAGE, strValue, 8);
	GET_WTP_WLAN_RT_xCAST_INFO(strValue, 1024, "TX_STATISTIC", "Unicast", "pcnt");
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_TX_UNICAST_PACKAGE, strValue, 8);
	GET_WTP_WLAN_RT_xCAST_INFO(strValue, 1024, "RX_STATISTIC", "Multicast", "pcnt");
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_RX_MULTI_PACKAGE, strValue, 8);
	GET_WTP_WLAN_RT_xCAST_INFO(strValue, 1024, "TX_STATISTIC", "Multicast", "pcnt");
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_TX_MULTI_PACKAGE, strValue, 8);
	GET_WTP_WLAN_RT_xCAST_INFO(strValue, 1024, "RX_STATISTIC", "Broadcast", "pcnt");
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_RX_BROADCAST_PACKAGE, strValue, 8);
	GET_WTP_WLAN_RT_xCAST_INFO(strValue, 1024, "TX_STATISTIC", "Broadcast", "pcnt");
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_TX_BROADCAST_PACKAGE, strValue, 8);
	
	unsigned long *paraVal_ut = (unsigned long *)&strValue[0];
	*paraVal_ut = 0x201; *paraVal_ut = ntohl(*paraVal_ut);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_RX_DATA_FRAME, strValue, 4);
	*paraVal_ut = 0x202; *paraVal_ut = ntohl(*paraVal_ut);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_TX_DATA_FRAME, strValue, 4);
	unsigned long long *paraVal_rx = (unsigned long long *)&strValue[0];
	*paraVal_rx = 0x201; *paraVal_rx = __ntohll(*paraVal_rx);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_RX_THROUGHPUT, strValue, 8);
	unsigned long long *paraVal_tx = (unsigned long long *)&strValue[0];
	*paraVal_tx = 0x202; *paraVal_tx = __ntohll(*paraVal_tx);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_TX_THROUGHPUT, strValue, 8);
	*paraVal_ut = 0x1; *paraVal_ut = ntohl(*paraVal_ut);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_UP_OR_DOWN_TIME, strValue, 4);
	GET_WTP_WLAN_RT_INFO(strValue, 1024, "rx_errors", 4);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_RX_ERR_PACKAGE, strValue, 4);

#if 0
	CWWTPGetAllVapOneStatTimes(strValue, sizeof(strValue), &hostapd_stat, "association_req");
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_ASSOCIATION_COUNT, strValue, 4);
	CWWTPGetAllVapOneStatTimes(strValue, sizeof(strValue), &hostapd_stat, "reassociation_req");
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_REASSOCIATION_COUNT, strValue, 8);

	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "auth", HOSTAPD_STATISTIC_INVALID);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_AUTH_INVALID_COUNT, strValue, 4);
	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "auth", HOSTAPD_STATISTIC_TIMEOUT);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_AUTH_TIMEOUT_COUNT, strValue, 4);
	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "auth", HOSTAPD_STATISTIC_REJECT);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_AUTH_REJECT_COUNT, strValue, 4);
	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "auth", HOSTAPD_STATISTIC_OTHER);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_AUTH_OTHER_COUNT, strValue, 4);
	
	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "assoc", HOSTAPD_STATISTIC_INVALID);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_ASSOCIATION_INVALID_COUNT, strValue, 4);
	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "assoc", HOSTAPD_STATISTIC_TIMEOUT);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_ASSOCIATION_TIMEOUT_COUNT, strValue, 4);
	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "assoc", HOSTAPD_STATISTIC_REJECT);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_ASSOCIATION_REJECT_COUNT, strValue, 4);
	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "assoc", HOSTAPD_STATISTIC_OTHER);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_ASSOCIATION_OTHER_COUNT, strValue, 4);
	
	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "reassoc", HOSTAPD_STATISTIC_INVALID);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_REASSOCIATION_INVALID_COUNT, strValue, 4);
	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "reassoc", HOSTAPD_STATISTIC_TIMEOUT);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_REASSOCIATION_TIMEOUT_COUNT, strValue, 4);
	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "reassoc", HOSTAPD_STATISTIC_REJECT);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_REASSOCIATION_REJECT_COUNT, strValue, 4);
	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "reassoc", HOSTAPD_STATISTIC_OTHER);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_REASSOCIATION_OTHER_COUNT, strValue, 4);

	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "deauth", -1);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_DEAUTH_COUNT, strValue, 4);
	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "deauth", HOSTAPD_STATISTIC_DE_USER_LEAVE);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_DEAUTH_USER_LEAVE_COUNT, strValue, 4);
	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "deauth", HOSTAPD_STATISTIC_DE_WTP_CAPABILITY);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_DEAUTH_WTP_CAP_COUNT, strValue, 4);
	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "deauth", HOSTAPD_STATISTIC_DE_EXCEPTION);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_DEAUTH_EXCEP_COUNT, strValue, 4);
	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "deauth", HOSTAPD_STATISTIC_DE_OTHER);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_DEAUTH_OTHER_COUNT, strValue, 4);

	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "disassoc", HOSTAPD_STATISTIC_DE_USER_LEAVE);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_DISASSOC_USER_LEAVE_COUNT, strValue, 4);
	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "disassoc", HOSTAPD_STATISTIC_DE_WTP_CAPABILITY);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_DISASSOC_WTP_CAP_COUNT, strValue, 4);
	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "disassoc", HOSTAPD_STATISTIC_DE_EXCEPTION);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_DISASSOC_EXCEP_COUNT, strValue, 4);
	CWWTPGetAllVapOneStatDetail(strValue, sizeof(strValue), &hostapd_stat, "disassoc", HOSTAPD_STATISTIC_DE_OTHER);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_WLAN_DISASSOC_OTHER_COUNT, strValue, 4);

	CWWTPGetVapConntStaNum(strValue, sizeof(strValue), WTP_GET_VAP_CONNECT_STA_NUM, index);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_VAP_CONNECT_STA_COUNT, strValue, sizeof(int)*MAX_VAP);
	CWWTPGetVapOneStatTimes(strValue, sizeof(strValue), &hostapd_stat, "association_req");
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_VAP_RCV_ASSOC_TIMES, strValue, sizeof(int)*MAX_VAP);
	CWWTPGetVapOneStatTimes(strValue, sizeof(strValue), &hostapd_stat, "association_resp");
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_VAP_RSP_ASSOC_TIMES, strValue, sizeof(int)*MAX_VAP);
	CWWTPGetVapOneStatTimes(strValue, sizeof(strValue), &hostapd_stat, "association_success");
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_VAP_ASSOC_SUCCESS_TIMES, strValue, sizeof(int)*MAX_VAP);
#endif

	CWWTPGetVapEnable(strValue, sizeof(strValue), index);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_VAP_ENABLE, strValue, sizeof(int)*MAX_VAP);
	
	CWWTPGetVapSSID(strValue, sizeof(strValue), WTP_GET_UCI_VAP_SSID, index);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_VAP_SSID_NAME, strValue, 40*MAX_VAP);
	
	CWWTPGetWTPMaxTxpower(strValue, sizeof(strValue), gWtpPublicInfo.maxtxpower[index-1]);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_MAX_TXPOWER, strValue, 16);
#if 0	
	CWWTPGetStaAcceptStatistic("association_req", strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_AP_STA_ACCEPT_COUNT, strValue, 4);
	CWWTPGetStaAcceptStatistic("association_resp", strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_AP_RESPONS_STA_ACCEPT_COUNT, strValue, 4);
	CWWTPGetStaAcceptStatistic("auth_success", strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_AP_STA_AUTH_SUCCESS_COUNT, strValue, 4);
	CWWTPGetStaAcceptStatistic("association_success", strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_AP_STA_ACCEPT_SUCCESS_COUNT, strValue, 4);
	CWWTPGetStaAcceptStatistic("active_disconnect", strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_AP_STA_DISASSOCIATION_COUNT, strValue, 4);
	CWWTPGetStaAcceptStatistic("reassociation_success", strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_AP_STA_REASSOCIATION_COUNT, strValue, 4);
#endif

	if(gWtpPublicInfo.cardnum == CW_TWO_CARD){
		CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_CARD_INDEX, &index, 1);
		CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_WTP_OTHER_CARD_MAC, (index==1) ? gWtpPublicInfo.wlan1Mac : gWtpPublicInfo.wlan0Mac, 6);
	}

	CWWTPCopyStrToStr("V1.2.0", strValue, 1024);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_AP_HARDWARE_VERSION, strValue, strlen(strValue)+1);

    /* get sta info */
    protocolStaInfo *conntStaInfo = NULL;

	conntStaInfo = CWWTPGetStaInfo(index);
	CWDTTAddElementToList(&msgElemList, CW_MSG_ELEMENT_WTP_EVENT_AP_PRIVATE_STA, conntStaInfo ? conntStaInfo->pData : NULL, conntStaInfo ? conntStaInfo->size : 0);
	if(conntStaInfo){
		if(conntStaInfo->pData)
			CW_FREE_OBJECT(conntStaInfo->pData);
		CW_FREE_OBJECT(conntStaInfo);
	}

	if(!CWAssembleWTPEventRequest(&messages, &fragmentsNum, gWTPPathMTU, seqNum, msgElemList, msgElemType, 0, index-1)){
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

	int i;
	for(i = 0; i < fragmentsNum; i++) {
		if(!CWNetworkSendUnsafeConnected(gWTPSocket, messages[i].msg, messages[i].offset)) {
			return -1;
		}
		CW_FREE_PROTOCOL_MESSAGE(messages[i]);
	}
	CW_FREE_OBJECT(messages);
	
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

