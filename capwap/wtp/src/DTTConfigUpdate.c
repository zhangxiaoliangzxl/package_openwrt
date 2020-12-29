/************************************************************************************************
 * Copyright (c) DTT																			*
 *																								*
 * -------------------------------------------------------------------------------------------- *
 * Project:  DTT Capwap																			*
 *																								*
 * Authors : Suhongbo (suhongbo@datang.com)
 *
 ************************************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h> 
#include <signal.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/shm.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "CWWTP.h"
#include "CWVendorPayloads.h"

#include "DTTConfigUpdate.h"
#include "DTTAclConfig.h"
#include "DTTKmodCommunicate.h"

pthread_mutex_t vlanMutex = PTHREAD_MUTEX_INITIALIZER;

static unsigned int CountryCode = 0;
static unsigned int shortGI = 0;
/*< ntp����*/
static ntpCfg ntpInfo;
/*< WEP���ܽṹ*/
static WEPCfg wep_cfg = {0};
/*< �������IP*/
unsigned int dataTunnelIP;
/*< Ϊ1ʱ����ǰ������radius��֤��Ϊ0����radius��֤*/
static char radiusFlag[8] = {0};
/*< Ϊ��ֹAP����־���ֹ���"uci: Entry not found"���ж�ԭ״̬Ϊradius����ɾ����ز���*/
static char radiusOldFlag[8] = {0};
/*< radius��֤�ͼƷѵ�IP��ǰ����Ϊ��֤�����ӷ�����IP��������Ϊ�Ʒѵ����ӷ�����IP*/
static struct in_addr radiusIP[4] = {0};
/*< radius��֤�ͼƷѵĶ˿ڣ�ǰ����Ϊ��֤�����Ӷ˿ڣ�������Ϊ�Ʒѵ����Ӷ˿�*/
static unsigned int radiusPort[4] = {0};
/*< radius��֤�ͼƷѵ���Կ��ǰ����Ϊ��֤��������Կ��������Ϊ�Ʒѵ�������Կ*/
static unsigned char radiusSecret[4][32] = {0};

int g_autoChannelSwitch = 0;
static int gIs11nMode = 0;
static int gOldChan = 0;
static int gOldChanMode = 0;
/*< ��ǰ���õ�����ģʽ*/
static unsigned int gWirelessMode[2] = {0};
/*< 1Ϊ���ã�0Ϊ����*/
static unsigned int vapSwitch[MAX_VAP] = {0};
/*< �������ñ��λ������������ʱ���漰��VAP�����Լ�vlan�����ã����ô˱�ǣ���VAP�Լ�vlan�����ýӿ���ʹ��*/
char trafficLimitSet = 0;
/*< ���ٿ��أ����������ٹ���һ������*/
static unsigned int trafficLimitSwitch[MAX_VAP] = {0};
/*< ��������*/
static unsigned int upLoadLimit[MAX_VAP] = {0};
/*< ��������*/
static unsigned int downLoadLimit[MAX_VAP] = {0};
/*< VAP��֤��ʽ����������*/
static char gWirelessAuthType[MAX_VAP][UCI_CMD_LENGTH] = {{0}};
/*< �����ļ���*/
static updateCfg updateInfo;
/*< ����sta��������*/
static staLimitCfg *upLoadStaLimit[1024] = {0};
unsigned int staTrafficLimitSwitch = 0;
/*< �����Ƶ�mac������������������ʱ������ϴ�����*/
static unsigned int oldupLoadStaLimitCount = 0;
static unsigned int upLoadStaLimitCount = 0;
/*< ����sta��������*/
static unsigned int downLoadStaLimit[1024] = {0};
/*< ����sta�������ñ�ǣ���Ϊ����ʱ����2.4��5.8�Ƿֱ����ø��������ϵ����٣����������һ�����������ߣ��ᵼ�����ſ������ٹ��򶼶�ʧ����ʱ��Ҫ�����ſ������ٶ�����*/
//char staTrafficLimitSet = 0;
/*< ģ��ID������ת����ʱ���������wltpͷ����,���ֵ�����ı�ʱ���ᷢ�͸��ں�*/
unsigned int gTemplateID[2] = {0};
struct shared_use_st{
	pthread_mutex_t mutex;
	pthread_mutex_t cfgNetMutex;
	/*< AP����ʱ����ʼ��ѡ�����߷�ʽ*/
	pthread_mutex_t onlineTypeMutex;
	/*< ��λ��option43ʹ�ã���Ϊoption43������4��IP����Ҫ����4��IP��������discover���ӵ�һ����ʼ���ĸ���Ӧ���ĸ�*/
	int onlineACCount;
	/*< ��δ���þ�̬��AC��IP�������ڴ��У���ACIP���ɵ�һ��������̼�����AC��IP����Ϊ�㲥��ֱ��Ϊ255.255.255.255*/
	char onlineACIP[4][32];
	char isSeted_5;
	/*< ǰ8��2.4�� ��8��5.8*/
	unsigned int vapVlan[MAX_VAP*2];
	unsigned int downLoadLimit[MAX_VAP*2];
	unsigned int trafficLimitSwitch[MAX_VAP*2];
	unsigned int shmVapSwitch[MAX_VAP*2];
};
/*< �����ڴ�*/
static struct shared_use_st *shared;
/*< ����ת�����ýṹ*/
localCfg localInfo;

void setUciWirelessChanMode(unsigned int ChanMode, char *cmd);
static void setCentreForwardMark(unsigned char *pLocalSwitch, char *cmd, CWProtocolVendorSpecificValues* valPtr);
//static void setUploadLimit(char *cmd, char index);
static CWBool setStaUpdownloadLimit(char *cmd, int index, int flag);

static vapPublicCfg gAllVapinfo;

static CWFreqTable  gCfgUpdateTable[] =
{
	{CW_DTT_MSG_ELEMENT_GENETIC_GET_WTP_INFO, DTTParseWTPVersion},
	{CW_DTT_MSG_ELEMENT_GENETIC_WTP_GET_FILE_FILENAME, DTTParseFirmwareFilename},
	{CW_DTT_MSG_ELEMENT_GENETIC_WTP_GET_FILE_AC_IPADDR, DTTParseFTPServerIP},
	{CW_DTT_MSG_ELEMENT_GENETIC_WTP_GET_FILE_FTP_USER, DTTParseFTPServerUser},
	{CW_DTT_MSG_ELEMENT_GENETIC_WTP_GET_FILE_FTP_PASSWD, DTTParseFTPServerPwd},
	{CW_DTT_MSG_ELEMENT_CONFIG_WTP_UPGRADE_FIRMWARE, DTTParseDoUpdate},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_MODE, DTTParseUCIWirelessHwmode},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_IS_DISABLED, DTTParseUCIWirelessIsDisable},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_COUNTRY_CODE, DTTParseUCIWirelessCountryCode},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_CHANNEL, DTTParseUCIWirelessChannel},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_BEACON_INTERVAL, DTTParseUCIWirelessBeaconInterval},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_RTS_LIMITE, DTTParseUCIWirelessRTS},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_DTIM_INTERVAL, DTTParseUCIWirelessDtimInterval},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_TX_POWER, DTTParseUCIWirelessTxPower},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_WEP_KEY_TYPE, DTTParseUCIWirelessWEPParameter},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_WEP_KEY_ONE, DTTParseUCIWirelessWEPParameter},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_WEP_KEY_TWO, DTTParseUCIWirelessWEPParameter},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_WEP_KEY_THREAD, DTTParseUCIWirelessWEPParameter},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_WEP_KEY_FOUR, DTTParseUCIWirelessWEPParameter},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_WEP_KEY_PASSPHRASE, DTTParseUCIWirelessWEPParameter},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_WEP_DEFAULT_KEY, DTTParseUCIWirelessWEPParameter},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_VAP_VLAN, DTTParseUCIWirelessVAPVlan},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_VAP_SWITCH, DTTParseUCIWirelessVAPSwitch},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_SSID_NAME, DTTParseUCIWirelessSSID},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_SSID_HIDE, DTTParseUCIWirelessHideSSID},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_VAP_WPA_PSK, DTTParseUCIWirelessWPAPSK},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_VAP_AUTH_TYPE, DTTParseUCIWirelessAuthType},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_VAP_PASSWD_TYPE, DTTParseUCIWirelessEncryptType},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_ISOLATE_IS_DISABLED, DTTParseIsolate},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_AUTO_CHANNEL, DTTParseUCIWirelessAutoChannel},
	{CW_DTT_MSG_ELEMENT_CONFIG_LEAD_FRAME_LENGTH, DTTParseUCIWirelessPreamble},
	{CW_DTT_MSG_ELEMENT_CONFIG_RADIUS_SERVER_IPADDR, DTTParseUCIRadiusServer},
	{CW_DTT_MSG_ELEMENT_CONFIG_RADIUS_SERVER_PORT, DTTParseUCIRadiusPort},
	{CW_DTT_MSG_ELEMENT_CONFIG_RADIUS_SERVER_KEY, DTTParseUCIRadiusSecret},
	{CW_DTT_MSG_ELEMENT_CONFIG_WTP_PASSWD, DTTParseUCIAPPassword},
	{CW_DTT_MSG_ELEMENT_CONFIG_NTP_SWITCH, DTTParseNTPSwitch},
	{CW_DTT_MSG_ELEMENT_CONFIG_NTP_IPADDR, DTTParseNTPServerIP},
	{CW_DTT_MSG_ELEMENT_CONFIG_WMM, DTTParseUCIWirelessWmm},
	{CW_DTT_MSG_ELEMENT_CONFIG_VAP_MAX_STA_COUNT, DTTParseUCIVapMaxSta},
	{CW_DTT_MSG_ELEMENT_CONFIG_LOCATION_TRANSMIT, DTTParseLocalForwardSwitch},
	{CW_DTT_MSG_ELEMENT_CONFIG_WTP_HOSTNAME, DTTParseUCIAPName},
	{CW_DTT_MSG_ELEMENT_CONFIG_BASE_SSID_BANDWIDTH_CONTROL, DTTParseVAPTrafficLimitSwitch},
	{CW_DTT_MSG_ELEMENT_CONFIG_BASE_SSID_UP_BANDWIDTH_CONTROL, DTTParseVAPUploadLimit},
	{CW_DTT_MSG_ELEMENT_CONFIG_BASE_SSID_DOWN_BANDWIDTH_CONTROL, DTTParseVAPDownloadLimit},
	{CW_DTT_MSG_ELEMENT_CONFIG_11N_ONLY_CHANNEL_MODE, DTTParseUCI11nChanMode},
	{CW_DTT_MSG_ELEMENT_CONFIG_11N_ONLY_SHORT_GI_PROTECT, DTTParseUCIShortGI},
	{CW_DTT_MSG_ELEMENT_CONFIG_AP_ASK_AC_AUTH_MACADDR_AC_RESPOSE, DTTParseACLControl},
	{CW_DTT_MSG_ELEMENT_CONFIG_NEED_ACL_AUTH_SSID, DTTParseACLSSIDList},
	{CW_DTT_MSG_ELEMENT_CONFIG_NEED_ACL_AUTH_VALN, DTTParseACLVlanList},
	{CW_DTT_MSG_ELEMENT_CONFIG_REBOOT_WTP, DTTParseRebootAP},
	{CW_DTT_MSG_ELEMENT_CONFIG_RESET_FACTORY_SETTING, DTTParseResetFactoryAP},
	{CW_DTT_MSG_ELEMENT_CONFIG_SET_FORMWORK_NUM, DTTParseTemplateID},
	{CW_DTT_MSG_ELEMENT_CONFIG_SET_DATA_CHANNEL_IPADDR, DTTParseDataTunnelIP},
	{CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_BANDWIDTH_CONTROL_MODE, DTTParseStaTrafficLimitSwitch},
	{CW_DTT_MSG_ELEMENT_CONFIG_TAP_FLUX_CONTROL_STA_LIST, DTTParseStaLimit},
};

unsigned int getDataTunnelIP(){
	return dataTunnelIP;
}

unsigned int getWirelessMode(char index){
	return gWirelessMode[index-1];
}

/*< �豸��������ʱ�����ô�λΪ0*/
void setTrafficLimitFlag(){
	trafficLimitSet = 0;
}
/*< 
 * ��ȡ����vap�Ŀ���״̬
 *
 * 1Ϊ������0Ϊ�ر�
*/
unsigned int getVapSwitch(int index){
	unsigned int vapRet = -1;

	if(index >= MAX_VAP*2)
		return 0;
	
	vapRet = gAllVapinfo.vapSwitch[index];

	return vapRet;
}

/*< ��ȡ����vap��vlan ID*/
unsigned int getVapVlanID(int index){
	unsigned int vlanID = 0;
	
	pthread_mutex_lock(&vlanMutex);
	vlanID = gAllVapinfo.vapVlan[index];
	pthread_mutex_unlock(&vlanMutex);

	return vlanID;
}
/*< �������е�vlan��Ϣ*/
void getAllVapVlanID(unsigned int *pvlan){
	pthread_mutex_lock(&vlanMutex);
	memcpy((char *)pvlan, (char *)gAllVapinfo.vapVlan, sizeof(unsigned int)*MAX_VAP*2);
	pthread_mutex_unlock(&vlanMutex);
}

/*< ����wlan��id�����������wlan���ڵ�vlan��*/
int getVlanIDFromWlanId(char index, char cardId){
	int vlanid = 0;
	int i = 0, count = -1, id = 0;

	for(i = 0;i < MAX_VAP;i ++){
		if(gAllVapinfo.vapSwitch[i+(cardId-1)*8]){
			count ++;
		}
		if(count == index){
			break;
		}
	}

	if(i < MAX_VAP){
		id = i + (cardId-1)*8;
		vlanid = gAllVapinfo.vapVlan[id];
	}
	return vlanid;
}

void APOnlineTypeLock(void){
	CWThreadMutexLock(&shared->onlineTypeMutex);
}
void APOnlineTypeUnLock(void){
	CWThreadMutexUnlock(&shared->onlineTypeMutex);
}

void setAPOnlineACIPandCount(int count, char *ip){	
	shared->onlineACCount = count+1;
	memset(shared->onlineACIP[count], 0, 32);
	memcpy(shared->onlineACIP[count], ip, 32);
}
int getAPOnlineACCountOption43(){
	return shared->onlineACCount;
}
void getAPOnlineACIPOption43(CWACDescriptor *CWACList){
	int i = 0;
	
	for(i = 0; i < shared->onlineACCount; i++) {
		CWLog("Init get from option43 , AC at %s", shared->onlineACIP[i]);
		memset(gCWACCfg->gCWACList[i].address, 0, 32);
		CW_COPY_MEMORY(gCWACCfg->gCWACList[i].address, shared->onlineACIP[i], strlen(shared->onlineACIP[i]));
	}
}

static void CWGetWlanName(int index, char *wlan, int len, int id)
{
	memset(wlan, 0, len);
	if(index == 1)
	{
		if(id)
			sprintf(wlan, "ath0%d", id);
		else
			sprintf(wlan, "ath0");
	}else{
		if(id)
			sprintf(wlan, "ath1%d", id);
		else
			sprintf(wlan, "ath1");
	}
}

CWBool DTTDispatchCfgUpdateCmd(CWProtocolVendorSpecificValues *valPtr, CWProtocolMessage *msgPtr, unsigned short len, char *buf){
	CWFreqTable *pTable = gCfgUpdateTable;
	int i = 0;
	int ret = CW_FALSE;

	for(i = 0;i < (sizeof(gCfgUpdateTable)/sizeof(CWFreqTable));i ++){
		if(pTable[i].funcID == valPtr->vendorPayloadType){
			if(pTable[i].handler){
				pTable[i].handler(msgPtr, len, buf, valPtr);
				CWLog("parse vendor type ..., type is 0x%04x, len is %d\n", valPtr->vendorPayloadType, len);
				ret = CW_TRUE;
			}
			break;
		}
	}
	
	return ret;
}

/*< �����ļ���*/
CWBool DTTParseWTPVersion(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {	
	valPtr->getWtpVersion = 1;
	msgPtr->offset += len;
	
	return CW_TRUE;
}

/*< �����ļ���*/
CWBool DTTParseFirmwareFilename(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {	
	updateInfo.name = CWProtocolRetrieveStr(msgPtr, len);

//	printf("name:%s\n", updateInfo.name);
	
	return CW_TRUE;
}
/*< ��ȡ�����ļ���FTP����IP*/
CWBool DTTParseFTPServerIP(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {	
	updateInfo.ip = (struct in_addr *)CWProtocolRetrieveStr(msgPtr, len);
	
//	printf("ip:%s\n", inet_ntoa(*(updateInfo.ip)));
	
	return CW_TRUE;
}
/*< ʵ����������*/
CWBool DTTParseDoUpdate(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {	
	CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);
	sprintf(buf, "wget ftp://%s/%s -P /tmp/ --ftp-user=%s --ftp-password=%s --quiet", 
		inet_ntoa(*(updateInfo.ip)), updateInfo.name, updateInfo.user, updateInfo.password);
	CWLog("update system:%s", buf);
	system(buf);
	
	CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);
	sprintf(buf, "mv /tmp/%s /tmp/ap.bin", updateInfo.name);
	system(buf);
	
	CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);
	sprintf(buf, "sysupgrade /tmp/ap.bin");
//	sprintf(cmd, "mtd -r write /tmp/%s firmware", updateInfo.name);
	system(buf);

	CW_FREE_OBJECT(updateInfo.name);
	CW_FREE_OBJECT(updateInfo.ip);
	CW_FREE_OBJECT(updateInfo.user);
	CW_FREE_OBJECT(updateInfo.password);
	
	return CW_TRUE;
}
CWBool DTTParseFTPServerUser(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr){
	updateInfo.user = CWProtocolRetrieveStr(msgPtr, len);
	
	return CW_TRUE;
}
CWBool DTTParseFTPServerPwd(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr){
	updateInfo.password = CWProtocolRetrieveStr(msgPtr, len);
	
	return CW_TRUE;
}


CWBool DTTParseUCIWirelessHwmode(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {
	unsigned int value = -1;
	char mode[16] = {0};
	int i = 0;

	value = (unsigned int) CWProtocolRetrieve32(msgPtr);

	CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);

	switch(value)
	{
		case 0:
			strcpy(mode, "0");
			break;
		case 1:
			strcpy(mode, "11a");
			break;
		case 2:
			strcpy(mode, "11b");
			break;
		case 3:
			strcpy(mode, "11g");
			break;
		case 7:
			strcpy(mode, "11na");
			break;
		case 8:
			strcpy(mode, "11bng");
			break;
		case 9:
			strcpy(mode, "11ng");/*< 2.4G 11n Only*/
			break;
		case 10:
			strcpy(mode, "11na");/*< 5.8G 11n Only*/
			break;
		case 11:
			strcpy(mode, "11ac");
			break;
		default:
			CWLog("Unregistered mode ..., mode value is %d\n", value);
			return CW_FALSE;
	}
	/*< ��11nģʽ��ʱ����ɾ��htmode������������Ч*/
    /* 5g */
	if((value == 1 || value == 7 || value == 10 || value == 11) && gRadio == 2)
	{
		CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);
        
		if(value == 1){
			sprintf(buf, UCI_SET_WIRELESS_DEVICE_1 "hwmode=%s && "UCI_DELETE_WIRELESS_DEVICE_1 "htmode", mode);
            system(buf);

			gIs11nMode = 0;
		}
		else
        {
			sprintf(buf, UCI_SET_WIRELESS_DEVICE_1 "hwmode=%s", mode);
			system(buf);
            
			gIs11nMode = 1;
		}
	}
	else
	{
		//sprintf(buf, UCI_DELETE_WIRELESS_DEVICE_0 "require_mode");
		//system(buf);
		CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);
        
		if(value == 2 || value == 3){
			sprintf(buf, UCI_SET_WIRELESS_DEVICE_0 "hwmode=%s && "UCI_DELETE_WIRELESS_DEVICE_0 "htmode", mode);
            system(buf);
            
			gIs11nMode = 0;
		}
		else{
			sprintf(buf, UCI_SET_WIRELESS_DEVICE_0 "hwmode=%s", mode);
			system(buf);
            
			gIs11nMode = 1;
		}
	}
    
	gWirelessMode[gRadio-1] = value;
	

	CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);
	setUciWirelessChanMode(gOldChanMode, buf);
	system(buf);

	/*< ���Է��֣�����11n onlyʱ�����뿪��wmm�ſɣ���˴˴����⴦��*/
	if(value == 9 || value == 10){
		/*< �����ԣ�openwrt�£�������wifi-device����Ч����������ÿһ��wifi-iface�Ͻ�������*/
		for(i = 0;i < MAX_VAP;i ++)
		{
			UCI_IFACE_SET_PARAM_INT(buf, i+(gRadio-1)*8, "wmm", 1);
		}
	}
	/*< δ��ʹ��htmode�ܽ���11nģʽ�²����ã��˲���ֱ���ύ*/
	valPtr->restartwifi = 1;
	
	return CW_TRUE;
}

CWBool DTTParseUCIWirelessIsDisable(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {
	unsigned int IsDisable = 0;

	IsDisable = (unsigned int)CWProtocolRetrieve32(msgPtr);

	if(IsDisable < 0)
	{
		return CW_FALSE;
	}
	CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);

	if(gRadio == 1){
		if(1 == IsDisable){
			sprintf(buf, UCI_SET_WIRELESS_DEVICE_0 "disabled=0");
		}
		else{
			sprintf(buf, UCI_SET_WIRELESS_DEVICE_0 "disabled=1");
		}
	}else{
		if(1 == IsDisable){
			sprintf(buf, UCI_SET_WIRELESS_DEVICE_1 "disabled=0");
		}
		else{
			sprintf(buf, UCI_SET_WIRELESS_DEVICE_1 "disabled=1");
		}
	}

	system(buf);
	valPtr->restartwifi = 1;
//	CWLog("## config ssid ####, cmd = %s", cmd);
	
	return CW_TRUE;
}

unsigned int getCountryCodeCfg(){
	return CountryCode;
}

CWBool DTTParseUCIWirelessCountryCode(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {
	char country[16] = {0};

	CountryCode = (unsigned int)CWProtocolRetrieve32(msgPtr);

	CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);

	switch(CountryCode)
	{
		case 156:
			strcpy(country, "CN");
			break;
		case 840:
			strcpy(country, "US");
			break;
		default:
			strcpy(country, "CN");
			break;
	}
	/*< �Ѿ��޸Ĺ��Ҵ���Ĺ������ƣ�ֱ�Ӱ�ʵ��ֵ���ü���*/
	if(gRadio == 1){
		sprintf(buf, UCI_SET_WIRELESS_DEVICE_0 "country=%s", country);
	}
	else{
		sprintf(buf, UCI_SET_WIRELESS_DEVICE_1 "country=%s", country);
	}
	system(buf);
	valPtr->restartwifi = 1;
//	CWLog("## config ssid ####, cmd = %s", cmd);
	
	return CW_TRUE;
}

CWBool DTTParseUCIWirelessChannel(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {
	unsigned int channel = 0;

	/*< Ӧ�Ƚ��˲������ߣ������Ӱ��������������*/
	channel = (unsigned int)CWProtocolRetrieve32(msgPtr);

	if(g_autoChannelSwitch)
	{
//		CWLog("***********g_autoChannelSwitch=%d", g_autoChannelSwitch);
		gOldChan = channel;
		if(gRadio == 2 && 11 == gOldChan)
			gOldChan = 149;
		return CW_TRUE;
	}

	CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);

	if(channel < 15 && gRadio == 1)
	{
		sprintf(buf, UCI_SET_WIRELESS_DEVICE_0 "channel=%d", channel);
	}
	else if(gRadio == 2){
//		if(channel > 161)
//			channel = 161;
		sprintf(buf, UCI_SET_WIRELESS_DEVICE_1 "channel=%d", channel);
	}
	
	system(buf);
	valPtr->restartwifi = 1;
	/*< �˴������ŵ����Ա�֤����Ӧ�ر�ʱ����ʹ��ԭ�ŵ����ã���Ϊ�ر�����Ӧ��ʱ��AC�����·���ǰ���ŵ�*/
	gOldChan = channel;
//	CWLog("## config ssid ####, cmd = %s", cmd);
	
	return CW_TRUE;
}

CWBool DTTParseUCIWirelessBeaconInterval(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {
	unsigned int beaconInt = 0;

	beaconInt = (unsigned int)CWProtocolRetrieve32(msgPtr);

	CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);

	if(gRadio == 1)
		sprintf(buf, UCI_SET_WIRELESS_DEVICE_0 "beacon_int=%d", beaconInt);
	else
		sprintf(buf, UCI_SET_WIRELESS_DEVICE_1 "beacon_int=%d", beaconInt);

	system(buf);
	valPtr->restartwifi = 1;
	
	return CW_TRUE;
}

CWBool DTTParseUCIWirelessRTS(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {
	unsigned int rts = 0;

	rts = (unsigned int)CWProtocolRetrieve32(msgPtr);

	if(rts < 0 || rts > 2346)
	{
		return CW_FALSE;
	}
	CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);
	
	if(gRadio == 1)
		sprintf(buf, UCI_SET_WIRELESS_DEVICE_0 "rts=%d", rts);
	else
		sprintf(buf, UCI_SET_WIRELESS_DEVICE_1 "rts=%d", rts);

	system(buf);
	valPtr->restartwifi = 1;
//	CWLog("## config ssid ####, cmd = %s", cmd);
	
	return CW_TRUE;
}
/*< DTIM ʱ���� (1-255) */
CWBool DTTParseUCIWirelessDtimInterval(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {
	unsigned int dtim = 0;
	int i = 0;

	dtim = (unsigned int)CWProtocolRetrieve32(msgPtr);

	if(dtim < 1 || dtim > 255)
	{
		/*< ���������÷�Χ��ֱ��ָ��ΪĬ��ֵ2*/
		dtim = 2;
	}
	/*< �����ԣ�openwrt�£�������wifi-device����Ч����������ÿһ��wifi-iface�Ͻ�������*/
	for(i = 0;i < MAX_VAP;i ++)
	{
		CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);
		sprintf(buf, UCI_SET_WIRELESS_IFACE "[%d]." "dtim_period=%d", i+(gRadio-1)*8, dtim);
		system(buf);
	}
	valPtr->restartwifi = 1;
	
	return CW_TRUE;
}

CWBool DTTParseUCIWirelessTxPower(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {
	unsigned int txpower = 0;

	txpower = (unsigned int)CWProtocolRetrieve32(msgPtr);

	if(txpower < 0 || txpower > 40)
	{
		return CW_FALSE;
	}
	CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);

	if(0 == txpower)
	{
		if(gRadio == 1)
			sprintf(buf, UCI_SET_WIRELESS_DEVICE_0 "txpower=%d", gWtpPublicInfo.maxtxpower[gRadio-1]);
		else
			sprintf(buf, UCI_SET_WIRELESS_DEVICE_1 "txpower=%d", gWtpPublicInfo.maxtxpower[gRadio-1]);
	}
	else
	{
		if(gRadio == 1)
		/*< ZDC��AC�·��Ĺ���Ϊ��ţ���-0.5ʱ�·�1��-1ʱ�·�2�����Դ˴�Ҫת����openwrt�Ĺ��ʲ���Ϊ1������0.5��1����op����С��Ч����Ϊ3����������Ϊ1����2����ЧΪ3*/
			sprintf(buf, UCI_SET_WIRELESS_DEVICE_0 "txpower=%d", gWtpPublicInfo.maxtxpower[gRadio-1]-(txpower+1)/2);
		else
			sprintf(buf, UCI_SET_WIRELESS_DEVICE_1 "txpower=%d", gWtpPublicInfo.maxtxpower[gRadio-1]-(txpower+1)/2);
			
	}
	system(buf);
	valPtr->restartwifi = 1;
//	CWLog("## config ssid ####, cmd = %s", cmd);
	
	return CW_TRUE;
}

static int getNetworkConf(char cardIndex, unsigned int vlanid){
	FILE *fp = NULL;
	char buf[32] = {0};
	char cmd[UCI_CMD_LENGTH] = {0};
	int count = 0, k = 0;
	
	if(gWtpPublicInfo.cardnum == CW_ONE_CARD)
		return -1;

	if(cardIndex == 2){
		k = 0;
		count = MAX_VAP;
	}
	else{
		k = 8;
		count = MAX_VAP * 2;
	}
	for(k;k < count;k ++){
		CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
		sprintf(cmd, "if [ `uci get network.vlan%d.disabled` == 0 ] ;then uci get network.vlan%d.ifname | cut -d . -f 2; fi", k+1, k+1);
//		printf("cmd:%s\n", cmd);
		fp = popen(cmd, "r");
		if(NULL != fgets(buf, sizeof(buf), fp)){		
			buf[strlen(buf)-1] = '\0';
			if(atoi(buf) == (vlanid==1?3:vlanid)){
				pclose(fp);
				fp = NULL;
				break;
			}
		}
		pclose(fp);
		fp = NULL;
	}

	return k;
}

static void DTTSetVlan(char *cmd, unsigned int *vapVlan, char APIndex){
	int i = 0, j = 0;
	int k = 0;
	int flag = 0;
	unsigned int switchCount = 8;
	
	/*< ÿ�ν���vlan����ǰ����ɾ�����е�switch_vlan��Ȼ��������vlan��ʱ���ٽ��д���*/
	if(APIndex == 1){
		for(i = MAX_VAP*2-1;i >= 0;i --)
		{
			CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
			sprintf(cmd, "uci delete network.@switch_vlan[%d]", 2+i);
//			printf("cmd=%s\n", cmd);
			system(cmd);
		}
		
		gAllVapinfo.switchId = 1;
	}else{
		for(i = 0;i < MAX_VAP;i ++)
		{
			for(j = 0; j < i; j ++)
			{
				if(gAllVapinfo.vapVlan[i] == gAllVapinfo.vapVlan[j])
				{
					switchCount --;
					break;
				}
			}
		}
//		printf("switchId = %d, switchCount=%d\n", shared->switchId, switchCount);
		/*< switch�л���lan��wan,����switch����Ǵ�2��ʼ*/
		for(i = gAllVapinfo.switchId;i > switchCount+1; i --)
		{
			CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
			sprintf(cmd, "uci delete network.@switch_vlan[%d]", i);
//			printf("cmd=%s\n", cmd);
			system(cmd);
			gAllVapinfo.switchId --;
		}
	}

	/*< network�ļ���ǰ8��wifi-iface�ֶι�2.4G����8����5.8G*/
	for(i = 0;i < MAX_VAP;i ++)
	{
//		printf("vapVlan[%d] = %d\n", i, vapVlan[i]);
		flag = 0;
//		printf("## config ssid ####, vapVlan[%d]=%d\n", i, vapVlan[i]);
		if(vapVlan[i] < 1 || vapVlan[i] > 4094)
		{
			continue;
		}

		/*< ʵ������network��6����ͬvlan�Ҷ�����ʱ��������6��������ͬeth0.xʱ���ᵼ���ں˹ҵ���AP�������˴��������������ͬ��vlan����ʱ����д�������ʵ�ʲ���*/
		/*< ����ֱ��ʹ��ǰ8��wifi-iface����2.4����8��wifi-iface����5.8����ʹvlan��ͬ��Ҳ�ֿ�д����ʵ�ʲ��������⣬��ʹ�������취*/
		if(APIndex == 1){
			k = -1;
		}else{
			k = getNetworkConf(APIndex, vapVlan[i]);
//			printf("k = %d, i = %d\n", k, i);
		}
		if(k == -1 || ((APIndex == 1) ? (k >= MAX_VAP*2) : (k >= MAX_VAP))){
			for(j = 0; j < i; j ++)
			{
				if(vapVlan[i] == vapVlan[j])
				{
					flag = 1;
					break;
				}
			}

			if(!flag)
			{
				CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
				sprintf(cmd, "uci set network.vlan%d.ifname=eth0.%d", i+1+(APIndex-1)*8, vapVlan[i]==1?3:vapVlan[i]);
				system(cmd);
//				printf("1cmd:%s\n", cmd);

				CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
				sprintf(cmd, "uci set network.vlan%d.disabled=0", i+1+(APIndex-1)*8);
				system(cmd);
//				printf("1cmd:%s\n", cmd);
				
				CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
				sprintf(cmd,  "uci set wireless.@wifi-iface[%d].network=vlan%d", i+(APIndex-1)*8, i+1+(APIndex-1)*8);
				system(cmd);
//				printf("1cmd:%s\n", cmd);
#if 1
				gAllVapinfo.switchId ++;

				CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
				sprintf(cmd,  "uci add network switch_vlan");
				system(cmd);

				CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
				sprintf(cmd,  "uci set network.@switch_vlan[%d].device=switch0", gAllVapinfo.switchId);
				system(cmd);

				CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
				sprintf(cmd,  "uci set network.@switch_vlan[%d].vlan=%d", gAllVapinfo.switchId, gAllVapinfo.switchId+1);
				system(cmd);
				
				CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
				sprintf(cmd,  "uci set network.@switch_vlan[%d].vid=%d", gAllVapinfo.switchId, vapVlan[i]==1?3:vapVlan[i]);
				system(cmd);
				
				CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
				sprintf(cmd,  "uci set network.@switch_vlan[%d].ports='0t %dt'", gAllVapinfo.switchId, wanSwitchPort);
				system(cmd);
#endif
			}
			else
			{
				CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
				sprintf(cmd,  "uci set wireless.@wifi-iface[%d].network=vlan%d", i+(APIndex-1)*8, j+1+(APIndex-1)*8);
				system(cmd);
				
//				printf("222cmd:%s\n", cmd);
				CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
				sprintf(cmd, "uci set network.vlan%d.disabled=1", i+1+(APIndex-1)*8);
				system(cmd);
//				printf("222cmd:%s\n", cmd);

                CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
				sprintf(cmd, "uci set network.vlan%d.ifname=", i+1+(APIndex-1)*8);
				system(cmd);
			}
		}
		else{
			CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
			sprintf(cmd,  "uci set wireless.@wifi-iface[%d].network=vlan%d", i+(APIndex-1)*8, k+1);
			system(cmd);
//			printf("333cmd:%s\n", cmd);
			
			CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
			sprintf(cmd, "uci set network.vlan%d.disabled=1", i+1+(APIndex-1)*8);
			system(cmd);

            CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
            sprintf(cmd, "uci set network.vlan%d.ifname=", i+1+(APIndex-1)*8);
            system(cmd);
		}
	}
}

CWBool DTTParseUCIWirelessWEPParameter(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {
	int i = 0;
	char *sys_str = NULL;
	char tmp_str[WEP_KEY_LENGTH];

	switch(valPtr->vendorPayloadType)
	{
	case CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_WEP_KEY_ONE:
	case CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_WEP_KEY_TWO:
	case CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_WEP_KEY_THREAD:
	case CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_WEP_KEY_FOUR:
	case CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_WEP_KEY_PASSPHRASE:
		sys_str = CWProtocolRetrieveStr(msgPtr, len);
		if(len < WEP_KEY_LENGTH)
		{
			memset(tmp_str, 0, WEP_KEY_LENGTH);
			memcpy(tmp_str, sys_str, len);
		}
		CW_FREE_OBJECT(sys_str);
		break;	
	}

	switch(valPtr->vendorPayloadType)
	{
	case CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_WEP_KEY_TYPE:
		wep_cfg.wep_key_type = (unsigned int)CWProtocolRetrieve32(msgPtr);
		switch(wep_cfg.wep_key_type)
		{
		case WEP_KEY_64BIT:
		case WEP_KEY_128BIT:
		case WEP_KEY_152BIT:
			/*do nothing*/
			break;
		default:
			wep_cfg.wep_key_type = 0;
			break;
		}
		break;
	case CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_WEP_KEY_ONE:
		memset(wep_cfg.key1, 0, WEP_KEY_LENGTH);
		if(len < WEP_KEY_LENGTH) 
		{
			memcpy(wep_cfg.key1, tmp_str, len);
		}
		break;
	case CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_WEP_KEY_TWO:
		memset(wep_cfg.key2, 0, WEP_KEY_LENGTH);
		if(len < WEP_KEY_LENGTH) 
		{
			memcpy(wep_cfg.key2, tmp_str, len);
		}
		break;
	case CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_WEP_KEY_THREAD:
		memset(wep_cfg.key3, 0, WEP_KEY_LENGTH);
		if(len < WEP_KEY_LENGTH) 
		{
			memcpy(wep_cfg.key3, tmp_str, len);
		}
		break;
	case CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_WEP_KEY_FOUR:
		memset(wep_cfg.key4, 0, WEP_KEY_LENGTH);
		if(len < WEP_KEY_LENGTH) 
		{
			memcpy(wep_cfg.key4, tmp_str, len);
		}
		break;
	case CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_WEP_KEY_PASSPHRASE:
		memset(wep_cfg.passphrase, 0, WEP_KEY_LENGTH);
		if(len < WEP_KEY_LENGTH) 
		{
			memcpy(wep_cfg.passphrase, tmp_str, len);
		}
		break;
	case CW_DTT_MSG_ELEMENT_CONFIG_WIRELESS_WEP_DEFAULT_KEY:
		for(i = 0;i < MAX_VAP;i ++)
		{
			wep_cfg.def_wep_key[i] = (unsigned int)CWProtocolRetrieve32(msgPtr);
			if(0 == wep_cfg.wep_swh[i]) continue;
			
			switch(wep_cfg.def_wep_key[i])
			{
			case 1:
				UCI_IFACE_SET_PARAM_STRING(buf, i+(gRadio-1)*8, "key", "1");
				UCI_IFACE_SET_PARAM_STRING(buf, i+(gRadio-1)*8, "key1", wep_cfg.key1);
				break;
			case 2:
				UCI_IFACE_SET_PARAM_STRING(buf, i+(gRadio-1)*8, "key", "2");
				UCI_IFACE_SET_PARAM_STRING(buf, i+(gRadio-1)*8, "key2", wep_cfg.key2);
				break;
			case 3:
				UCI_IFACE_SET_PARAM_STRING(buf, i+(gRadio-1)*8, "key", "3");
				UCI_IFACE_SET_PARAM_STRING(buf, i+(gRadio-1)*8, "key3", wep_cfg.key3);
				break;
			case 4:
				UCI_IFACE_SET_PARAM_STRING(buf, i+(gRadio-1)*8, "key", "4");
				UCI_IFACE_SET_PARAM_STRING(buf, i+(gRadio-1)*8, "key4", wep_cfg.key4);
				break;
			default:
				break;
			}
		}
		break;
	}
	
	return CW_TRUE;
}

CWBool DTTParseUCIWirelessVAPVlan(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {
	int i = 0;
	unsigned int vapVlan[MAX_VAP] = {0};

	/*< network�ļ���ǰ8��wifi-iface�ֶι�2.4G����8����5.8G*/
	pthread_mutex_lock(&vlanMutex);
	for(i = 0;i < MAX_VAP;i ++)
	{
		vapVlan[i] = (unsigned int)CWProtocolRetrieve32(msgPtr);
		gAllVapinfo.vapVlan[i+(gRadio-1)*8] = vapVlan[i];
	}
	pthread_mutex_unlock(&vlanMutex);
	/*< ��2.4G��5.8G�ǹ���һ��vlan�������߹�����һ��vlan��ʱ�򣬴�ʱһ�������仯����һ��Ҳ������������vlan*/
	DTTSetVlan(buf, vapVlan, gRadio);
	if(2 == gRadio){
		gAllVapinfo.isSeted_5 = 1;
	}
	if(1 == gRadio && gAllVapinfo.isSeted_5){
		DTTSetVlan(buf, gAllVapinfo.vapVlan+8, 2);
	}
#if 0
	/*< 2.4G��vlan������������*/
	else if(2 == gAPIndex && shared->isSeted_2){
		printf("again set 2.4\n");
		DTTSetVlan(cmd, shared->vapVlan, 1);
	}
#endif
	/*< vlan�������ֱ�ӽ����ύ����ֹuci���ò�����������ֱ��治�˵����*/
	system(UCI_COMMIT);

	if(localInfo.flag){
		setCentreForwardMark(localInfo.localSwitch, buf, valPtr);
	}
	/*< ��λΪ1ʱ����������������*/
	if(trafficLimitSet){
		//setUploadLimit(buf);
		valPtr->trafficDownloadLimit = 1;
	}
	valPtr->restartNetwork = 1;
	return CW_TRUE;
}


CWBool DTTParseUCIWirelessVAPSwitch(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {
	int i = 0;

	for(i = 0;i < MAX_VAP;i ++)
	{
		gAllVapinfo.vapSwitch[i+(gRadio-1)*8] = (unsigned int)CWProtocolRetrieve32(msgPtr);
		CWLog("## config ssid ####, vapSwitch[%d]=%d", i+(gRadio-1)*8, gAllVapinfo.vapSwitch[i+(gRadio-1)*8]);
		if(gAllVapinfo.vapSwitch[i+(gRadio-1)*8] != 0 && gAllVapinfo.vapSwitch[i+(gRadio-1)*8] != 1)
		{
			gAllVapinfo.vapSwitch[i+(gRadio-1)*8] = 0;
		}
	}

	for(i = 0;i < MAX_VAP;i ++)
	{
		CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);
		if(gAllVapinfo.vapSwitch[i+(gRadio-1)*8] == 0){
			sprintf(buf, UCI_SET_WIRELESS_IFACE "[%d]." "disabled=1", i+(gRadio-1)*8);
		}
		else{
			sprintf(buf, UCI_SET_WIRELESS_IFACE "[%d]." "disabled=0", i+(gRadio-1)*8);
		}
		system(buf);
		//CWLog("## config ssid ####, cmd = %s", cmd);
	}
	/*< ��ΪΪ1ʱ�����������ü���ת��*/
	if(localInfo.flag){
		setCentreForwardMark(localInfo.localSwitch, buf, valPtr);
	}
	/*< ��λΪ1ʱ����������������*/
	if(trafficLimitSet){
		//setUploadLimit(buf);
		valPtr->trafficDownloadLimit = 1;
	}
	
	valPtr->restartwifi = 1;
	
	return CW_TRUE;
}

CWBool DTTParseUCIWirelessSSID(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {
	unsigned short count = 0;
	unsigned char ssid[MAX_VAP][64] = {{0}};
	int i = 0,j = 0;
	
	for(i = 0;i < MAX_VAP;i ++)
	{
		while(count <= len)
		{
			ssid[i][j] = (unsigned char)CWProtocolRetrieve8(msgPtr);
			count ++;
			/*< SSID���39���ֽ�*/
			if(!ssid[i][j] || j > 39)
			{
				CWLog("ssid[%d] = %s, j = %d", i, ssid[i], j);
				j = 0;
				break;
			}
			j++;
		}
	}
	for(i = 0;i < MAX_VAP;i ++)
	{
		CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);
		sprintf(buf, UCI_SET_WIRELESS_IFACE "[%d]." "ssid=%s", i+(gRadio-1)*8, ssid[i]);
		system(buf);
		//CWLog("## config ssid ####, cmd = %s", cmd);
	}
	valPtr->restartwifi = 1;
	
	return CW_TRUE;
}

CWBool DTTParseUCIWirelessHideSSID(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {
	unsigned int hide[MAX_VAP] = {0};
	int i = 0;
	
	for(i = 0;i < MAX_VAP;i ++)
	{
		hide[i] = (unsigned int)CWProtocolRetrieve32(msgPtr);
		if(hide[i] != 0 && hide[i] != 1)
		{
			return CW_FALSE;
		}
	}

	for(i = 0;i < MAX_VAP;i ++)
	{
		CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);
		sprintf(buf, UCI_SET_WIRELESS_IFACE "[%d]." "hidden=%d", i+(gRadio-1)*8, hide[i]);
		system(buf);
		//CWLog("## config ssid ####, cmd = %s", cmd);
	}
	valPtr->restartwifi = 1;
	
	return CW_TRUE;
}

/*< VAP��WPA_PSK������������*/
CWBool DTTParseUCIWirelessWPAPSK(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr)
{
	unsigned short count = 0;
	char psk[MAX_VAP][64] = {{0}};
	int i = 0, j = 0;

	for(i = 0;i < MAX_VAP;i ++)
	{
		while(count <= len){
			psk[i][j] = (char)CWProtocolRetrieve8(msgPtr);
			count ++;
			
			if(!psk[i][j] || j > 64)
			{
//				CWLog("psk[%d] = %s, j = %d", i, psk[i], j);
				j = 0;
				break;
			}
			j++;
		}
	}
	for(i = 0;i < MAX_VAP;i ++)
	{
		if(!strlen(psk[i]))
			continue;
		CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);
		sprintf(buf, UCI_SET_WIRELESS_IFACE "[%d]." "key=%s", i+(gRadio-1)*8, psk[i]);
//		CWLog("cmd = %s", cmd);
		system(buf);
	}

	valPtr->restartwifi = 1;

	return CW_TRUE;
}

/*< VAP��֤��ʽ*/
CWBool DTTParseUCIWirelessAuthType(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr)
{
	unsigned int type[MAX_VAP] = {0};
	int i = 0;

	for(i = 0;i < MAX_VAP;i ++)
	{
		type[i] = (unsigned int)CWProtocolRetrieve32(msgPtr);
		radiusFlag[i] = 0;
//		CWLog("type[%d] = %d, i = %d", i, type[i], i);
		switch(type[i]){
			case WIRELESS_AUTH_OPEN_SYSTEM:
			case WIRELESS_AUTH_SHARED_KEY:
				break;
			case WIRELESS_AUTH_LEGACY_8021X:
                                CW_ZERO_MEMORY(gWirelessAuthType[i], UCI_CMD_LENGTH);
				strcpy(gWirelessAuthType[i], "8021x+");
                                radiusFlag[i] = 1;
				break;
			case WIRELESS_AUTH_WPA_WITH_RADIUS:
				CW_ZERO_MEMORY(gWirelessAuthType[i], UCI_CMD_LENGTH);
				strcpy(gWirelessAuthType[i], "wpa+");
				radiusFlag[i] = 1;
				break;
			case WIRELESS_AUTH_WPA2_WITH_RADIUS:
				CW_ZERO_MEMORY(gWirelessAuthType[i], UCI_CMD_LENGTH);
				strcpy(gWirelessAuthType[i], "wpa2+");
				radiusFlag[i] = 1;
				break;
			/*< WAP & WPA2*/
			case WIRELESS_AUTH_WPA_WPA2_WITH_RADIUS:
				CW_ZERO_MEMORY(gWirelessAuthType[i], UCI_CMD_LENGTH);
				strcpy(gWirelessAuthType[i], "wpa-mixed+");
				radiusFlag[i] = 1;
				break;
			case WIRELESS_AUTH_WPA_PSK:
				CW_ZERO_MEMORY(gWirelessAuthType[i], UCI_CMD_LENGTH);
				strcpy(gWirelessAuthType[i], "psk+");
				break;
			case WIRELESS_AUTH_WPA2_PSK:
				CW_ZERO_MEMORY(gWirelessAuthType[i], UCI_CMD_LENGTH);
				strcpy(gWirelessAuthType[i], "psk2+");
				break;
			case WIRELESS_AUTH_WPA_WPA2_PSK:
				CW_ZERO_MEMORY(gWirelessAuthType[i], UCI_CMD_LENGTH);
				strcpy(gWirelessAuthType[i], "psk-mixed+");
				break;
			case WIRELESS_AUTH_WAPI_PSK:
			case WIRELESS_AUTH_WAPI_CERT:
				break;
			default:
				return CW_FALSE;
		}
	}

	return CW_TRUE;
}

/*< VAP���ܷ�ʽ*/
CWBool DTTParseUCIWirelessEncryptType(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr)
{
	unsigned int type[MAX_VAP] = {0};
	int i = 0;

	for(i = 0;i < MAX_VAP;i ++)
	{
		wep_cfg.wep_swh[i] = 0;
		type[i] = (unsigned int)CWProtocolRetrieve32(msgPtr);
		//CWLog("---------------------type[%d] = %d, i = %d", i, type[i], i);

		if(1 == radiusFlag[i] && 0 == strcmp(gWirelessAuthType[i], "8021x+"))
		{
                        CW_ZERO_MEMORY(gWirelessAuthType[i], UCI_CMD_LENGTH);
			strcpy(gWirelessAuthType[i], "wpa-mixed+tkip+ccmp");
		}
		else
		{
			switch(type[i]){
			case WIRELESS_AUTH_ENCRYPT_NONE:
				CW_ZERO_MEMORY(gWirelessAuthType[i], UCI_CMD_LENGTH);
				strcpy(gWirelessAuthType[i], "none");
				break;
			case WIRELESS_AUTH_ENCRYPT_WEP:
				wep_cfg.wep_swh[i] = 1;
				if(0x0 == strlen(gWirelessAuthType[i]))
				{
					strcpy(gWirelessAuthType[i], "wep-open");
				}
				break;
			case WIRELESS_AUTH_ENCRYPT_TKIP:
				strcat(gWirelessAuthType[i], "tkip");
				break;
			case WIRELESS_AUTH_ENCRYPT_AES:
				strcat(gWirelessAuthType[i], "ccmp");
				break;
			case WIRELESS_AUTH_ENCRYPT_AES_TKIP:
				strcat(gWirelessAuthType[i], "tkip+ccmp");
				break;
			default:
                                CW_ZERO_MEMORY(gWirelessAuthType[i], UCI_CMD_LENGTH);
				strcpy(gWirelessAuthType[i], "none");
				break;
			}
		}
		
	}
	for(i = 0;i < MAX_VAP;i ++)
	{                
		UCI_IFACE_SET_PARAM_STRING(buf, i+(gRadio-1)*8, "encryption", gWirelessAuthType[i]);
		
		/*< ��SSIDΪradius��֤ʱ*/
		
		
		if(1 == radiusFlag[i]){
			UCI_IFACE_SET_PARAM_STRING(buf, i+(gRadio-1)*8, "auth_server", inet_ntoa(radiusIP[0]));
			UCI_IFACE_SET_PARAM_INT(buf, i+(gRadio-1)*8, "auth_port", radiusPort[0]);
			UCI_IFACE_SET_PARAM_STRING(buf, i+(gRadio-1)*8, "auth_secret", radiusSecret[0]);
			
			UCI_IFACE_SET_PARAM_STRING(buf, i+(gRadio-1)*8, "acct_server", inet_ntoa(radiusIP[2]));
			UCI_IFACE_SET_PARAM_INT(buf, i+(gRadio-1)*8, "acct_port", radiusPort[2]);
			UCI_IFACE_SET_PARAM_STRING(buf, i+(gRadio-1)*8, "acct_secret", radiusSecret[2]);

			radiusOldFlag[i] = 1;
		}
		else
		{
			if(1 == radiusOldFlag[i]){
				UCI_IFACE_DEL_PARAM(buf, i+(gRadio-1)*8, "auth_server");
				UCI_IFACE_DEL_PARAM(buf, i+(gRadio-1)*8, "auth_port");
				UCI_IFACE_DEL_PARAM(buf, i+(gRadio-1)*8, "auth_secret");
				UCI_IFACE_DEL_PARAM(buf, i+(gRadio-1)*8, "acct_server");
				UCI_IFACE_DEL_PARAM(buf, i+(gRadio-1)*8, "acct_port");
				UCI_IFACE_DEL_PARAM(buf, i+(gRadio-1)*8, "acct_secret");
				
				radiusOldFlag[i] = 0;
			}
			
		}
	}

	valPtr->restartwifi = 1;

	return CW_TRUE;
}

static void setEbtables(int count, int type)
{
	char cmd[256] = {0};
	char wlan[16] = {0};

	if(gRadio == 1){
		if(count)
			sprintf(wlan, "ath0%d", count);
		else
			sprintf(wlan, "ath0");
	}else{
		if(count)
			sprintf(wlan, "ath1%d", count);
		else
			sprintf(wlan, "ath1");
	}
	/*< ��ֹebtables�����ֶ�����ͬ����һ����ɾ�����*/
	switch(type){
		case 0:
			/*< ����·��رգ�ֱ��ȥɾ��ebtables��*/
			EBTABLES_DEL_BROADCAST(wlan, cmd);
			EBTABLES_DEL_UNICAST(wlan, cmd);
			break;
		case 1:
			EBTABLES_DEL_BROADCAST(wlan, cmd);
			EBTABLES_DEL_UNICAST(wlan, cmd);
			EBTABLES_ADD_UNICAST(wlan, cmd);
			break;
		case 2:
			EBTABLES_DEL_BROADCAST(wlan, cmd);
			EBTABLES_DEL_UNICAST(wlan, cmd);
			EBTABLES_ADD_BROADCAST(wlan, cmd);
			break;
		case 3:
			EBTABLES_DEL_BROADCAST(wlan, cmd);
			EBTABLES_DEL_UNICAST(wlan, cmd);
			EBTABLES_ADD_BROADCAST(wlan, cmd);
			EBTABLES_ADD_UNICAST(wlan, cmd);
			break;
	}
}

CWBool DTTParseIsolate(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr)
{
	unsigned int isolate[MAX_VAP] = {0};
	int i = 0;
	int vapIndex = 0;
	
	for(i = 0;i < MAX_VAP;i ++)
	{
//		printf("isolate[%d]:%d, g_isolate[%d]:%d\n", i, isolate[i], i, g_isolate[i]);
		isolate[i] = (unsigned int)CWProtocolRetrieve32(msgPtr);
		if(isolate[i] != 0 && isolate[i] != 1 && isolate[i] != 2 && isolate[i] != 3)
		{
			return CW_FALSE;
		}
		if(gAllVapinfo.vapSwitch[i+(gRadio-1)*8]){
			setEbtables(vapIndex, isolate[i]);
			vapIndex ++;
		}
	}
	
	return CW_TRUE;
}

CWBool DTTParseUCIWirelessAutoChannel(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {
	unsigned int autoChanSwitch = 0;

	autoChanSwitch = (unsigned int)CWProtocolRetrieve32(msgPtr);

	if(NULL == buf)
	{
		return CW_FALSE;
	}
	CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);

	if(autoChanSwitch == 1)
	{
		g_autoChannelSwitch = 1;
		if(gRadio == 1)
			sprintf(buf, UCI_SET_WIRELESS_DEVICE_0 "channel=auto");
		else if(gRadio == 2){
			/*< 5.8G����Ӧ�����⣬��ʱ��149����*/
			sprintf(buf, UCI_SET_WIRELESS_DEVICE_1 "channel=auto");
		}
	}else if(autoChanSwitch == 0){
		g_autoChannelSwitch = 0;
		if(gRadio == 1)
			sprintf(buf, UCI_SET_WIRELESS_DEVICE_0 "channel=%d", gOldChan);
		else if(gRadio == 2)
			sprintf(buf, UCI_SET_WIRELESS_DEVICE_1 "channel=%d", gOldChan);
	}
	
	system(buf);
	valPtr->restartwifi = 1;
	
	return CW_TRUE;
}
/*< ǰ��֡����:   0:��  1:����Ӧ*/
CWBool DTTParseUCIWirelessPreamble(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {
	unsigned int preamble = 0;
	int i = 0;

	preamble = (unsigned int)CWProtocolRetrieve32(msgPtr);

	if(preamble != 1 && preamble != 0)
	{
		/*< ���������÷�Χ��ֱ��ָ��ΪĬ��ֵ1*/
		preamble = 1;
	}
	/*< �����ԣ�openwrt�£�������wifi-device����Ч����������ÿһ��wifi-iface�Ͻ�������*/
	for(i = 0;i < MAX_VAP;i ++)
	{
		UCI_IFACE_SET_PARAM_INT(buf, i+(gRadio-1)*8, "short_preamble", preamble);
	}
	valPtr->restartwifi = 1;
	
	return CW_TRUE;
}

CWBool DTTParseUCIRadiusServer(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr){
	int i = 0;
	unsigned int ip;

	for(i = 0;i < 4; i ++){
		ip = (unsigned int)CWProtocolRetrieve32(msgPtr);
		memcpy(radiusIP+i, &ip, 4);
		//CWLog("---------------------radiusIP[%d] = %s\n", i, inet_ntoa(radiusIP[i]));
	}
	
	return CW_TRUE;
}

CWBool DTTParseUCIRadiusPort(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr){
	int i = 0;

	for(i = 0;i < 4; i ++){
		radiusPort[i] = (unsigned int)CWProtocolRetrieve32(msgPtr);
//		CWLog("radiusPort[%d] = %d\n", i, radiusPort[i]);
	}
	
	return CW_TRUE;
}

CWBool DTTParseUCIRadiusSecret(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr){
	char *secret = NULL;
	int i = 0, j = 0, count = 0;

	secret = CWProtocolRetrieveStr(msgPtr, len);
	for(i = 0;i < 4; i ++){
		while(count <= len)
		{
			radiusSecret[i][j] = secret[count];
			count ++;
			/*< Secret���32���ֽ�,����'\0'*/
			if(!radiusSecret[i][j] || j >= 32)
			{
				j = 0;
				break;
			}
			j ++;
		}
//		CWLog("radiusSecret[%d] = %s\n", i, radiusSecret[i]);
	}

	CW_FREE_OBJECT(secret);
	return CW_TRUE;
}

CWBool DTTParseUCIAPPassword(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr){
	char *passwd = NULL;

	/*< password�ֽ��20*/
	if(len > 20)
		len = 20;
	
	passwd = CWProtocolRetrieveStr(msgPtr, len);

	/*< 5.8G��WTPʱ��ֱ�ӷ���,�ҷ���ʱ������Ѹ�λ����*/
	if(gRadio == 2)
		return CW_TRUE;

	if(!passwd)
		return CW_FALSE;
	
	CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);
	sprintf(buf, "(echo \"%s\"; sleep 1; echo \"%s\") | passwd > /dev/null  &", passwd, passwd);
	system(buf);

	CW_FREE_OBJECT(passwd);
	
	return CW_TRUE;
}

CWBool DTTParseNTPSwitch(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr){
	ntpInfo.ntpswitch = (unsigned int)CWProtocolRetrieve32(msgPtr);
    
    CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);

    /*
    if(ntpInfo.ntpswitch)
    {
        sprintf(buf, "uci set system.ntp.enable_client=1");
    }else
    {
        sprintf(buf, "uci set system.ntp.enable_client=0");
    }

	system(buf);
	*/

	return CW_TRUE;
}

CWBool DTTParseNTPServerIP(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr){
	char addr_p[16]; /*IP��ַ�ĵ��ʮ�����ַ�����ʾ��ʽ*/
	
	ntpInfo.ip = (unsigned int)CWProtocolRetrieve32(msgPtr);
	
	inet_ntop(AF_INET,(struct in_addr *)&ntpInfo.ip,addr_p,(socklen_t )sizeof(addr_p));

	CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);
	sprintf(buf, UCI_SET_NTPCLIENT "%s", addr_p);
	system(buf);

    system("uci commit ntpclient");

    /*
    CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);
	sprintf(buf, UCI_SET_NTPD "%s", addr_p);
	system(buf);
    */

	return CW_TRUE;
}

/*< wmm:   0:����  1:����*/
CWBool DTTParseUCIWirelessWmm(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {
	unsigned int wmm = 0;
	int i = 0;

	wmm = (unsigned int)CWProtocolRetrieve32(msgPtr);

	if(wmm != 1 && wmm != 0)
	{
		/*< ���������÷�Χ��ֱ��ָ��ΪĬ��ֵ1*/
		wmm = 1;
	}
	/*< ���Է��֣�����11n onlyʱ�����뿪��wmm�ſɣ���˴˴����⴦��*/
	if(gWirelessMode[gRadio-1] == 9 || gWirelessMode[gRadio-1] == 10)
		wmm = 1;
	/*< �����ԣ�openwrt�£�������wifi-device����Ч����������ÿһ��wifi-iface�Ͻ�������*/

    if (1 == wmm)
    {
        for(i = 0;i < MAX_VAP;i ++)
    	{
    		UCI_IFACE_SET_PARAM_INT(buf, i+(gRadio-1)*8, "wmm", wmm);
    	}
    }
    else
    {
        for(i = 0;i < MAX_VAP;i ++)
    	{
    		UCI_IFACE_DEL_PARAM(buf, i+(gRadio-1)*8, "wmm");
    	}
    }
	
	valPtr->restartwifi = 1;
	
	return CW_TRUE;
}

CWBool DTTParseUCIVapMaxSta(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr){
	unsigned int count[8] = {0};
	int i = 0;

	for(i = 0;i < MAX_VAP; i ++){
		count[i] = (unsigned int)CWProtocolRetrieve32(msgPtr);
		UCI_IFACE_SET_PARAM_INT(buf, i+(gRadio-1)*8, "maxsta", count[i]);
	}
	
//	system(UCI_COMMIT_WIRELESS);
	valPtr->restartwifi = 1;
	
	return CW_TRUE;
}

static void setCentreForwardMark(unsigned char *pLocalSwitch, char *cmd, CWProtocolVendorSpecificValues* valPtr)
{
	int i = 0;
	char wlan[16] = {0};
	/*< ����ebtables��markʱ���ǰ���wlan0,wlan0-1��ʽ���õģ�������ʹ�ô˱�־λ���ж�*/
	int flag = 0;
	/*< ����ǰ���Ƚ��ñ���յ�*/
	CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
	if(gRadio == 1){
		EBTABLES_CLEAR_CHAIN("24FORWARD", cmd);
	}else{
		EBTABLES_CLEAR_CHAIN("58FORWARD", cmd);
	}
	for(i = 0;i < MAX_VAP;i ++){
		if(gAllVapinfo.vapSwitch[i+(gRadio-1)*8] == 1){
			/*< ����ת��ʱ���˱�־λΪ0��δ����vap��ҲΪ0*/
			if(pLocalSwitch[i] == 0){
				if(gRadio == 1){
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
				/*< ���Է��֣���������ʱ�������markΪ356�İ������ԣ��˴���markʱ����1000����*/
				if(gRadio == 1){
					EBTABLES_SET_MARK("24FORWARD", wlan, ((gAllVapinfo.vapVlan[i+(gRadio-1)*8]+1000) << 6) | (gRadio-1), cmd);
				}
				else{
					EBTABLES_SET_MARK("58FORWARD", wlan, ((gAllVapinfo.vapVlan[i+(gRadio-1)*8]+1000) << 6) | (gRadio-1), cmd);
				}
//				CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
//				sprintf(cmd,  "uci set wireless.@wifi-iface[%d].network=lan", i+(gAPIndex-1)*8);
//				system(cmd);
//				valPtr->restartwifi = 1;
			}

			flag ++;
		}
	}
	return;
}

CWBool DTTParseLocalForwardSwitch(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr)
{
	int i = 0;

	memset(&localInfo, 0, sizeof(localInfo));
	for(i = 0;i < MAX_VAP;i ++)
	{
//		printf("isolate[%d]:%d, g_isolate[%d]:%d\n", i, isolate[i], i, g_isolate[i]);
		localInfo.localSwitch[i] = (unsigned int)CWProtocolRetrieve8(msgPtr);
		if(localInfo.localSwitch[i] != 0 && localInfo.localSwitch[i] != 1)
		{
			return CW_FALSE;
		}
	}
	localInfo.flag = 1;
	
	setCentreForwardMark(localInfo.localSwitch, buf, valPtr);
	/*��Ϊ��ϵ�����кͱ��ص�mark�����ٵĻ����㣬���������꼯��ת������Ҫ������������*/
	if(trafficLimitSet){
		//setUploadLimit(buf);
		valPtr->trafficDownloadLimit = 1;
	}
	
	return CW_TRUE;
}

CWBool DTTParseUCIAPName(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr){
	char *name = NULL;
    char cmd_buf[128] = {0};
	
	/*< password�ֽ��20*/
	if(len > 128)
		len = 128;
	
	name = CWProtocolRetrieveStr(msgPtr, len);

	/*< 5.8G��WTPʱ��ֱ�ӷ���*/
	if(gRadio == 2)
		return CW_TRUE;

	if(!name)
		return CW_FALSE;
	
	CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);
	sprintf(buf, "uci set system.@system[-1].hostname='%s' && uci commit system", name);
	system(buf);

    /* ������Ч */
	sprintf(cmd_buf, "echo %s > /proc/sys/kernel/hostname", name);
	system(cmd_buf);
    
	CW_FREE_OBJECT(name);

	//valPtr->restartSystem = 1;
	
	return CW_TRUE;
}

void setUciWirelessChanMode(unsigned int ChanMode, char *buf)
{
	/*< ��11nģʽ��ֱ������ qcawifi disablecoext insdead of noscan */
	if(!gIs11nMode)
		return;

	/*< 11ACģʽ*/
	if(11 == gWirelessMode[gRadio-1])
	{
		switch(ChanMode)
		{
			case 0:
				sprintf(buf, "uci set wireless.@wifi-device[%d].htmode=HT20 && uci delete wireless.@wifi-device[%d].disablecoext", gRadio-1, gRadio-1);
				break;
			case 1:
				sprintf(buf, "uci set wireless.@wifi-device[%d].htmode=HT40 && uci delete wireless.@wifi-device[%d].disablecoext", gRadio-1, gRadio-1);
				break;
			case 2:
				sprintf(buf, "uci set wireless.@wifi-device[%d].htmode=HT40 && uci set wireless.@wifi-device[%d].disablecoext=1", gRadio-1, gRadio-1);
				break;
			case 5:
				sprintf(buf, "uci set wireless.@wifi-device[%d].htmode=HT80 && uci set wireless.@wifi-device[%d].disablecoext=1", gRadio-1, gRadio-1);
				break;
			default:
				sprintf(buf, "uci set wireless.@wifi-device[%d].htmode=HT20 && uci delete wireless.@wifi-device[%d].disablecoext", gRadio-1, gRadio-1);
				break;
		}
	}else{
		switch(ChanMode)
		{
			case 0:
				sprintf(buf, "uci set wireless.@wifi-device[%d].htmode=HT20 && uci delete wireless.@wifi-device[%d].disablecoext", gRadio-1, gRadio-1);
				break;
			case 1:
				sprintf(buf, "uci set wireless.@wifi-device[%d].htmode=HT40 && uci delete wireless.@wifi-device[%d].disablecoext", gRadio-1, gRadio-1);
				break;
			case 2:
				sprintf(buf, "uci set wireless.@wifi-device[%d].htmode=HT40 && uci set wireless.@wifi-device[%d].disablecoext=1", gRadio-1, gRadio-1);
				break;
			default:
				sprintf(buf, "uci set wireless.@wifi-device[%d].htmode=HT40 && uci delete wireless.@wifi-device[%d].disablecoext", gRadio-1, gRadio-1);
				break;
		}
	}
}

CWBool DTTParseUCI11nChanMode(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {
	unsigned int ChanMode = 0;

	ChanMode = (unsigned int)CWProtocolRetrieve32(msgPtr);

	/*< ��11nģʽ��ֱ������*/
	if(!gIs11nMode)
		return CW_TRUE;
	
	CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);
	setUciWirelessChanMode(ChanMode, buf);
	system(buf);

	valPtr->restartwifi = 1;

	gOldChanMode = ChanMode;
	/*< �߼�˳��shortGI�ӿ��л�ʹ��gOldChanMode����*/
	DTTParseUCIShortGI(NULL, 0, buf, NULL);
	return CW_TRUE;
}

CWBool DTTParseUCIShortGI(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr) {
	if(msgPtr)
		shortGI = (unsigned int)CWProtocolRetrieve32(msgPtr);

	/*< ��11nģʽ��ֱ������*/
	if(!gIs11nMode)
		return CW_TRUE;
	
	CW_ZERO_MEMORY(buf, UCI_CMD_LENGTH);
	/*< �رն̱������ʱ��ֱ�ӽ�20��40��shortgi������Ϊ0*/
#if 0
	if(0 == shortGI){
		sprintf(buf, "uci set wireless.@wifi-device[%d].short_gi_20=0 && uci set wireless.@wifi-device[%d].short_gi_40=0", gRadio-1, gRadio-1);
	}else{
		switch(gOldChanMode)
		{
			case 0:
				sprintf(buf, "uci set wireless.@wifi-device[%d].short_gi_20=1 && uci set wireless.@wifi-device[%d].short_gi_40=0", gRadio-1, gRadio-1);
				break;
			case 1:
				sprintf(buf, "uci set wireless.@wifi-device[%d].short_gi_20=1 && uci set wireless.@wifi-device[%d].short_gi_40=1", gRadio-1, gRadio-1);
				break;
			case 2:
				sprintf(buf, "uci set wireless.@wifi-device[%d].short_gi_20=0 && uci set wireless.@wifi-device[%d].short_gi_40=1", gRadio-1, gRadio-1);
				break;
			default:
				sprintf(buf, "uci set wireless.@wifi-device[%d].short_gi_20=1 && uci set wireless.@wifi-device[%d].short_gi_40=1", gRadio-1, gRadio-1);
				break;
		}
	}
#else
    if(0 == shortGI){
        sprintf(buf, "uci set wireless.@wifi-device[%d].shortgi=0", gRadio-1);
    }else{
        switch(gOldChanMode)
        {
            case 0:
                sprintf(buf, "uci set wireless.@wifi-device[%d].shortgi=0", gRadio-1);
                break;
            case 1:
                sprintf(buf, "uci set wireless.@wifi-device[%d].shortgi=1", gRadio-1);
                break;
            case 2:
                sprintf(buf, "uci set wireless.@wifi-device[%d].shortgi=1", gRadio-1);
                break;
            default:
                sprintf(buf, "uci set wireless.@wifi-device[%d].shortgi=1", gRadio-1);
                break;
        }
    }
#endif

	system(buf);
	if(valPtr){
		valPtr->restartwifi = 1;
	}

	return CW_TRUE;
}

/*< ���ٿ���*/
CWBool DTTParseVAPTrafficLimitSwitch(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr)
{
	int i = 0;
	for(i = 0;i < MAX_VAP;i ++)
	{
		gAllVapinfo.trafficLimitSwitch[i+(gRadio-1)*8] = (unsigned int)CWProtocolRetrieve32(msgPtr);
	}
	if(trafficLimitSet){
		//setUploadLimit(buf);
		valPtr->trafficDownloadLimit = 1;
	}
	return CW_TRUE;
}

void setUploadLimit(char *cmd, char index)
{
	int i = 0;
	int wlanFlag = 0;
	unsigned int vlanid = 0, id = 0, vapid = 0, mark = 0;
	unsigned char cardIndex = 0;
	char wlan[16] = {0};

//	TC_QISC_CLEAR_ROOT(cmd, "eth0");
	TC_QISC_ROOT_CREAT(cmd, "eth0");

	if(1 == index)
		system("ebtables -t nat -F QOS_24UPLOAD_CHAIN");
	else
		system("ebtables -t nat -F QOS_58UPLOAD_CHAIN");

	for(i = 0;i < MAX_VAP;i ++){
		/*< openwrt�У����߽ӿ���ʼ��Ϊwlan0,wlan0-1����*/
		if(gAllVapinfo.vapSwitch[i+(index-1)*8]){
			if(index == 1){
				if(wlanFlag)
					sprintf(wlan, "ath0%d", wlanFlag);
				else
					sprintf(wlan, "ath0");
			}else{
				if(wlanFlag)
					sprintf(wlan, "ath1%d", wlanFlag);
				else
					sprintf(wlan, "ath1");
			}
			wlanFlag ++;
		}else{
			continue;
		}

		id = (i+SSID_LIMIT_BANDWIDTH_CLASSID_OFFSET+(index-1)*8) << SSID_LIMTI_MARK_CLASSID_OFFSET;

		if(0 == localInfo.localSwitch[i]){
			vlanid = (gAllVapinfo.vapVlan[i+(index-1)*8]+1000) << SSID_LIMTI_MARK_VLAN_OFFSET;
		}else{
			vlanid = 0;
		}
		vapid = (i) << SSID_LIMTI_MARK_VAP_OFFSET;

		cardIndex = (index-1) << SSID_LIMTI_MARK_WLANCARD_OFFSET;

		mark = vlanid | id | vapid | cardIndex;
		
		if(gAllVapinfo.trafficLimitSwitch[i+(index-1)*8]){
			/*< �������ٹ���ʱ��ʹ��replace�������ڣ��򴴽������ڣ����޸�*/
			/*< ���ٵ��������Ŵ�10��ʼ*/
			TC_TRAFFIC_LIMIT(cmd, "eth0", id, upLoadLimit[i]);
			TC_ADD_FILTER(cmd, "eth0", mark, id);
			TC_QDISC_SQF(cmd, "eth0", id, mark);
		}else{
			TC_DEL_FILTER(cmd, "eth0", mark, id);
			TC_CLEAR_CLASS_TRAFFIC_LIMIT(cmd, "eth0", id);
		}
		/*< �����Ƿ������٣���Ӧ�ô������mark�����mark���������٣�Ҳ���ڼ���ת��ʱwltpͷ�е�vap index*/
		/*< ��������markʱ���뱾��ת������ת����markȡ������*/
		if(1 == index){
			TC_UPLOAD_EBTABLES_MARK(cmd, wlan, mark, "QOS_24UPLOAD_CHAIN");
		}
		else{
			TC_UPLOAD_EBTABLES_MARK(cmd, wlan, mark, "QOS_58UPLOAD_CHAIN");
		}
	}
}
/*< ��������*/
CWBool DTTParseVAPUploadLimit(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr)
{
	int i = 0;

	for(i = 0;i < MAX_VAP;i ++)
	{
		upLoadLimit[i] = (unsigned int)CWProtocolRetrieve32(msgPtr);
	}
	//setUploadLimit(buf);
	trafficLimitSet = 1;
	valPtr->trafficDownloadLimit = 1;
	
	return CW_TRUE;
}
/*< ��������ʵ�����ýӿ�*/
void setDownloadLimit(char *cmd, char index)
{
	int i = 0;
	int id = 0;
	int wlanFlag = 0; 
	char wlan[16] = {0};
	
	if(1 == index)
		system("ebtables -t nat -F QOS_24DOWNLOAD_CHAIN");
	else
		system("ebtables -t nat -F QOS_58DOWNLOAD_CHAIN");
	
	for(i = 0;i < MAX_VAP;i ++){
		/*< openwrt�У����߽ӿ���ʼ��Ϊwlan0,wlan0-1����*/
		if(gAllVapinfo.vapSwitch[i+(index-1)*8]){
			if(index == 1){
				if(wlanFlag)
					sprintf(wlan, "ath0%d", wlanFlag);
				else
					sprintf(wlan, "ath0");
			}else{
				if(wlanFlag)
					sprintf(wlan, "ath1%d", wlanFlag);
				else
					sprintf(wlan, "ath1");
			}
			wlanFlag ++;
		}else{
			continue;
		}

		/*< �����Ƿ������٣�������չ������������ڹر�����ʱ����֤û����Ӧ��tc���򣬱�֤����ת��Ч��*/
		TC_QISC_CLEAR_ROOT(cmd, wlan);
		if(!gAllVapinfo.trafficLimitSwitch[i+(index-1)*8]){
			continue;
		}
		id = i+SSID_LIMIT_BANDWIDTH_CLASSID_OFFSET+(index-1)*8;

		/*< ��ʱ�ȴ�*/
		TC_SLEEP_WAIT_WLAN(cmd, wlan);
		TC_QISC_ROOT_CREAT(cmd, wlan);
		/*< ���ٹ�����ÿ����ͬ�������ϣ����Ծ�������һ����Ҳ�ֱ��������*/
		/*< �������ٹ���ʱ��ʹ��replace�������ڣ��򴴽������ڣ����޸�*/
		/*< ���ٵ��������Ŵ�10��ʼ*/
		TC_TRAFFIC_LIMIT(cmd, wlan, id, gAllVapinfo.downLoadLimit[i+(index-1)*8]);
//		printf("set downLoadLimit[%d]=%d\n", i+(index-1)*8, shared->downLoadLimit[i+(index-1)*8]);
		TC_ADD_FILTER(cmd, wlan, id, id);
		TC_QDISC_SQF(cmd, wlan, id, id);

		if(1 == index){
			TC_DOWNLOAD_EBTABLES_MARK(cmd, wlan, id, "QOS_24DOWNLOAD_CHAIN");
		}
		else{
			TC_DOWNLOAD_EBTABLES_MARK(cmd, wlan, id, "QOS_58DOWNLOAD_CHAIN");
		}
			
	}
	/*< ���������ߺ󣬻���sta������Ҳ��Ҫ�������ã��ӿ��ڻ��жϣ�ֱ�ӵ���*/
	/*< ���������ߣ��������ϵ�tc���򶼻ᶪ��������ÿ�����涼��Ҫ��������������*/
	setStaUpdownloadLimit(cmd, 1, 0);
	setStaUpdownloadLimit(cmd, 2, 0);
}

/*< ��������*/
CWBool DTTParseVAPDownloadLimit(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr)
{
	int i = 0;

	for(i = 0;i < MAX_VAP;i ++)
	{
		gAllVapinfo.downLoadLimit[i+(gRadio-1)*8] = (unsigned int)CWProtocolRetrieve32(msgPtr);
//		printf("downLoadLimit[%d]=%d\n", i, downLoadLimit[i]);
	}
	valPtr->trafficDownloadLimit = 1;
	//setDownloadLimit(cmd);
	trafficLimitSet = 1;
	
	return CW_TRUE;
}

CWBool DTTParseACLControl(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr)
{
	aclControlCfg *aclCont = NULL;
	
	aclCont = (aclControlCfg *)CWProtocolRetrieveStr(msgPtr, len);

	if(!aclCont)
		return CW_FALSE;
	
	switch(aclCont->aclType){
		case ACL_TYPE_RESPONSR:
			CWLog("################ACL_TYPE_RESPONSR");
			setAclAuthResultInfo(aclCont);
			valPtr->dttAclConfigUpdate = 1;
			break;
		case ACL_TYPE_SWITCH_ON:
			setACLSwitch(MACL_ACL_ON);
			CWLog("################ACL Control : on");
			break;
		case ACL_TYPE_SWITCH_OFF:
			setACLSwitch(ACL_OFF);
			CWLog("################ACL Control : off");
			break;
		case ACL_TYPE_SSID_SWITCH_ON:
			setACLSwitch(SSID_ACL_ON);
			CWLog("################ACL Control : SSID ACL On");
			break;
		case ACL_TYPE_VLAN_SWITCH_ON:
			setACLSwitch(VLAN_ACL_ON);
			CWLog("################ACL Control : Vlan ACL On");
			break;
		default:
			break;
	}
	
	return CW_TRUE;
}

CWBool DTTParseACLSSIDList(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr)
{
	char *str = NULL;

	if(0 == len)
		return CW_TRUE;
	ACLSSIDEditLock();
	unsigned char *ssid = getAclssidList();
	
	memset(ssid, 0, 256);
	str = CWProtocolRetrieveStr(msgPtr, len);

	memcpy(ssid, str, len > 256 ? 255 : len);
	ssid[strlen(ssid)] = ',';
	free(str);
	str = NULL;
	
	ACLSSIDEditUnLock();

	return CW_TRUE;

}

CWBool DTTParseACLVlanList(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr)
{
	char *str = NULL;
	unsigned short i = 0;
	unsigned short count = 0;
	unsigned short *vlancfg = (unsigned short *)getAclVlanList();

	if(0 == len){
		memset(vlancfg+(gRadio-1)*8, 0, sizeof(unsigned short)*MAX_VAP);
		return CW_TRUE;
	}
	
	ACLSSIDEditLock();
	
	memset(vlancfg+(gRadio-1)*8, 0, sizeof(unsigned short)*MAX_VAP);

	count = len / 2;

	if(count > 8)
		count = 8;
	
	for(i = 0; i < count;i ++){
		vlancfg[i+(gRadio-1)*8] = (unsigned short)CWProtocolRetrieve16(msgPtr);
//		CWLog("********len=%d, vlan %d=%d, gRadio=%d", len, i+(gRadio-1)*8, vlancfg[i+(gRadio-1)*8], gRadio);
	}
	
	ACLSSIDEditUnLock();

	return CW_TRUE;

}


CWBool DTTParseRebootAP(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr){
	
	valPtr->reboot = (unsigned int)CWProtocolRetrieve32(msgPtr);
	
	return CW_TRUE;
}

CWBool DTTParseResetFactoryAP(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr){
	
	unsigned int flag = (unsigned int)CWProtocolRetrieve32(msgPtr);
	if(flag == 1){
		/*< ��Ҫ�ظ���reponse֮���ٽ��лָ�����*/
		system("sleep 2 && rm /overlay/* -rf &");
		system("sleep 5 && reboot -f &");
	}
	
	return CW_TRUE;
}
CWBool DTTParseTemplateID(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr){
	
	unsigned int templateID = (unsigned int)CWProtocolRetrieve32(msgPtr);

	if(gTemplateID[gRadio-1] != templateID){
		gTemplateID[gRadio-1] = templateID;
		if(1 == gRadio){
			sendto_kmod(CW_NLMSG_SET_TEMPLATEID_1, (s8 *)&templateID, sizeof(u32));
		}else{
			sendto_kmod(CW_NLMSG_SET_TEMPLATEID_2, (s8 *)&templateID, sizeof(u32));
		}
	}
	
	return CW_TRUE;
}
CWBool DTTParseDataTunnelIP(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr){
//	char addr_p[16]; /*IP��ַ�ĵ��ʮ�����ַ�����ʾ��ʽ*/
	
	dataTunnelIP = (unsigned int)CWProtocolRetrieve32(msgPtr);
	
//	inet_ntop(AF_INET,(struct in_addr *)&tunnelIP,addr_p,(socklen_t )sizeof(addr_p));
	
	return CW_TRUE;
}

#if 1
CWBool DTTParseStaTrafficLimitSwitch(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr){
	
	unsigned int flag = (unsigned int)CWProtocolRetrieve32(msgPtr);

	staTrafficLimitSwitch = flag;
	
	return CW_TRUE;
}

/*< ����sta����������*/
static CWBool setStaUpdownloadLimit(char *cmd, int index, int flag)
{
	int i= 0,j = 0;
	int id = 0;
	char wlan[16] = {0};
	char wlanid = 0;
	FILE *fp = NULL;
	char buf[8] = {0};

//	printf("staTrafficLimitSwitch=%d, upLoadStaLimitCount=%d\n", staTrafficLimitSwitch, upLoadStaLimitCount);
	if(staTrafficLimitSwitch == 0 || upLoadStaLimitCount <= 0)
		return CW_TRUE;

	memset(cmd, 0, UCI_CMD_LENGTH);
	sprintf(cmd, "tc filter ls dev ath%d | grep u32 | wc -l", index-1);
	fp = popen(cmd, "r");
	if(fp){
		fgets(buf, sizeof(buf), fp);
//		printf("########buf=%s, atoi(buf) = %d\n", buf, atoi(buf));
		/*< Ŀǰֻ��sta����ʹ����tc��u32ƥ�䣬ֱ��grep u32�����У����Ϊ��ǰ�Ѿ�������sta����*/
		if(atoi(buf) > 0){
			if(!flag)
				return CW_TRUE;
			else{
				/*< ÿ�������ԭ�ȵ�tc����*/
				id = STA_LIMIT_BANDWIDTH_CLASSID_OFFSET;
				for(i = 0;i < oldupLoadStaLimitCount; i++){
					wlanid = 0;
					for(j = 0;j < MAX_VAP;j ++){
						if(gAllVapinfo.vapSwitch[i+(gRadio-1)*8]){
							CWGetWlanName(index, wlan, sizeof(wlan), wlanid);
							wlanid ++;
//							printf("i-%d:j-%d will clear %s tc\n", i, j, wlan);
							/*< ����������в���handle��filter����*/
							TC_STA_CLEAR_FILTER(cmd, wlan);
//				printf("cmd=%s\n", cmd);
							/*< ÿһ��sta������������id���ֱ�������к�����*/
							TC_CLEAR_CLASS_TRAFFIC_LIMIT(cmd, wlan, id);
//				printf("cmd=%s\n", cmd);
							TC_CLEAR_CLASS_TRAFFIC_LIMIT(cmd, wlan, id+1);
//				printf("cmd=%s\n", cmd);
						}
					}
					id+=2;
				}
			}
		}
		pclose(fp);
		fp = NULL;
	}else{
		return CW_TRUE;
	}
//	printf("\n#################################\n");
	id = STA_LIMIT_BANDWIDTH_CLASSID_OFFSET;

	for(i = 0;i < upLoadStaLimitCount; i++){
		/*< ����SSID���ٵ�classid��10��ʼ������sta���ٵ�classid��32��ʼ*/
		wlanid = 0;
		for(j = 0;j < MAX_VAP;j ++){
			if(gAllVapinfo.vapSwitch[i+(gRadio-1)*8]){
				CWGetWlanName(index, wlan, sizeof(wlan), wlanid);
//							printf("%d: will add %s tc\n", i, wlan);
				wlanid ++;
				/*< ֱ�Ӵ��������Ѵ��ڣ���ᴴ��ʧ�ܣ���Ӱ��*/
				TC_QISC_ROOT_CREAT(cmd, wlan);
				/*< ���к����зֱ𴴽�һ��class*/
				TC_TRAFFIC_LIMIT(cmd, wlan, id, upLoadStaLimit[i]->up);
//				printf("cmd=%s\n", cmd);
				TC_STA_UPLOAD_FILTER(cmd, wlan, upLoadStaLimit[i]->mac, id);
//				printf("cmd=%s\n", cmd);
				TC_TRAFFIC_LIMIT(cmd, wlan, id+1, upLoadStaLimit[i]->down);
//				printf("cmd=%s\n", cmd);
				TC_STA_DOWNLOAD_FILTER(cmd, wlan, upLoadStaLimit[i]->mac, id+1);
//				printf("cmd=%s\n", cmd);
			}
		}
		
		id += 2;
	}

	oldupLoadStaLimitCount = upLoadStaLimitCount;
	return CW_TRUE;
}

#endif

CWBool DTTParseStaLimit(CWProtocolMessage *msgPtr, unsigned short len, char *buf, CWProtocolVendorSpecificValues *valPtr)
{
	unsigned int StaCount = 0;
	int i = 0;
//	staLimitCfg *limitInfo = NULL;
	
	StaCount = (unsigned int)CWProtocolRetrieve32(msgPtr);

	for(i = 0;i < StaCount;i ++){
		upLoadStaLimit[i] = (staLimitCfg *)CWProtocolRetrieveStr(msgPtr, sizeof(staLimitCfg));
//		setStaUploadLimit(cmd, i);
	}
	upLoadStaLimitCount = StaCount;

//	staTrafficLimitSet = 1;
	setStaUpdownloadLimit(buf, gRadio, 1);
	
	return CW_TRUE;
}

