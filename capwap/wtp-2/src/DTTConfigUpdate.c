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

static unsigned int CountryCode = 0;
static unsigned int shortGI = 0;
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
static unsigned int gWirelessMode;
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
/*< �����Ƶ�mac������������������ʱ������ϴ�����*/
static unsigned int upLoadStaLimitCount = 0;
/*< ����sta��������*/
static unsigned int downLoadStaLimit[1024] = {0};
/*< ģ��ID������ת����ʱ���������wltpͷ����,���ֵ�����ı�ʱ���ᷢ�͸��ں�*/
unsigned int gTemplateID = 0;
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
	/*< network�ļ���switch���ã�lan��wan����Ϊ0��1��vlan�����ô��±�2��ʼ*/
	unsigned int switchId;
};
/*< �����ڴ�*/
static struct shared_use_st *shared;
/*< ����ת�����ýṹ*/
localCfg localInfo;

void setUciWirelessChanMode(unsigned int ChanMode, char *cmd);
static void setCentreForwardMark(unsigned char *pLocalSwitch, char *cmd, CWProtocolVendorSpecificValues* valPtr);
static void setUploadLimit(char *cmd);

unsigned int getWirelessMode(){
	return gWirelessMode;
}

/*< �豸��������ʱ�����ô�λΪ0*/
void setTrafficLimitFlag(){
	trafficLimitSet = 0;
}
/*< ��ȡ����vap�Ŀ���״̬*/
unsigned int getVapSwitch(int index){
	unsigned int vapRet = -1;

	if(index >= MAX_VAP)
		return 0;
	
	vapRet = vapSwitch[index];

	return vapRet;
}

/*< ��ȡ����vap��vlan ID*/
unsigned int getVapVlanID(int index){
	unsigned int vlanID = 0;
	
	pthread_mutex_lock(&shared->mutex);
	vlanID = shared->vapVlan[index];
	pthread_mutex_unlock(&shared->mutex);

	return vlanID;
}
/*< �������е�vlan��Ϣ*/
void getAllVapVlanID(unsigned int *pvlan){
	pthread_mutex_lock(&shared->mutex);
	memcpy((char *)pvlan, (char *)shared->vapVlan, sizeof(unsigned int)*MAX_VAP*2);
	pthread_mutex_unlock(&shared->mutex);
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

CWBool shareMemInit(){
	void *shm = NULL;//����Ĺ����ڴ��ԭʼ�׵�ַ
	int shmid;
	pthread_mutexattr_t mutex_shared_attr;
	
	shmid = shmget((key_t)1234, sizeof(struct shared_use_st), 0666);
	//�������ڣ��򴴽������ڴ� 
	if(shmid == -1){
	    shmid = shmget((key_t)1234, sizeof(struct shared_use_st), 0666|IPC_CREAT);
	    if(shmid == -1)
	    {
	        CWLog("shmget failed");
	        return CW_FALSE;
	    }
	}
    //�������ڴ����ӵ���ǰ���̵ĵ�ַ�ռ�  
    shm = shmat(shmid, 0, 0);
    if(shm == (void*)-1)
    {
        CWLog("shmat failed");
        return CW_FALSE;
    }
	shared = (struct shared_use_st*)shm;
	/*< ��ʼ�������ڴ�*/
	if(gAPIndex == 1){
		memset(shared, 0, sizeof(struct shared_use_st));

		/*< ���������ڶ����֮��ʱ�����Զ������䶨*/
		/*< ����vlan�Ľ��̼以����*/
		pthread_mutexattr_init(&mutex_shared_attr);  
  		pthread_mutexattr_setpshared(&mutex_shared_attr, PTHREAD_PROCESS_SHARED);
		pthread_mutex_init (&shared->mutex,&mutex_shared_attr);
//		pthread_mutexattr_destroy(&mutex_shared_attr);
		/*< ����network��wifi�Ľ��̼以����,��ֹ��������ͬʱ���ó�����*/
//		pthread_mutexattr_init(&mutex_shared_attr);  
//		pthread_mutexattr_setpshared(&mutex_shared_attr, PTHREAD_PROCESS_SHARED);
		pthread_mutex_init (&shared->cfgNetMutex,&mutex_shared_attr);
//		pthread_mutexattr_destroy(&mutex_shared_attr);
		/*< ��ʼ����AP���߷�ʽ��*/
//		pthread_mutexattr_init(&mutex_shared_attr);  
//		pthread_mutexattr_setpshared(&mutex_shared_attr, PTHREAD_PROCESS_SHARED);
		pthread_mutex_init (&shared->onlineTypeMutex,&mutex_shared_attr);
		pthread_mutexattr_destroy(&mutex_shared_attr);

		shared->switchId = 1;
	}
	
	return CW_TRUE;
}

/*< �����ļ���*/
CWBool DTTParseFirmwareFilename(CWProtocolMessage *msgPtr, unsigned short len) {	
	updateInfo.name = CWProtocolRetrieveStr(msgPtr, len);

//	printf("name:%s\n", updateInfo.name);
	
	return CW_TRUE;
}
/*< ��ȡ�����ļ���FTP����IP*/
CWBool DTTParseFTPServerIP(CWProtocolMessage *msgPtr, unsigned short len) {	
	updateInfo.ip = (struct in_addr *)CWProtocolRetrieveStr(msgPtr, len);
	
//	printf("ip:%s\n", inet_ntoa(*(updateInfo.ip)));
	
	return CW_TRUE;
}
/*< ʵ����������*/
CWBool DTTParseDoUpdate(char *cmd) {	
	CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
	sprintf(cmd, "wget ftp://%s/%s -P /tmp/ --ftp-user=%s --ftp-password=%s --quiet", 
		inet_ntoa(*(updateInfo.ip)), updateInfo.name, updateInfo.user, updateInfo.password);
	system(cmd);
	
	CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
	sprintf(cmd, "mv /tmp/%s /tmp/ap.bin", updateInfo.name);
	system(cmd);
	
	CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
	sprintf(cmd, "sysupgrade -F /tmp/ap.bin");
//	sprintf(cmd, "mtd -r write /tmp/%s firmware", updateInfo.name);
	system(cmd);


	CW_FREE_OBJECT(updateInfo.name);
	CW_FREE_OBJECT(updateInfo.ip);
	CW_FREE_OBJECT(updateInfo.user);
	CW_FREE_OBJECT(updateInfo.password);
	
	return CW_TRUE;
}
CWBool DTTParseFTPServerUser(CWProtocolMessage *msgPtr, unsigned short len){
	updateInfo.user = CWProtocolRetrieveStr(msgPtr, len);
	
	return CW_TRUE;
}
CWBool DTTParseFTPServerPwd(CWProtocolMessage *msgPtr, unsigned short len){
	updateInfo.password = CWProtocolRetrieveStr(msgPtr, len);
	
	return CW_TRUE;
}


CWBool DTTParseUCIWirelessHwmode(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr) {
	unsigned int value = -1;
	char mode[16] = {0};

	value = (unsigned int) CWProtocolRetrieve32(msgPtr);

	CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
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
	if((value == 10 || value == 1 || value == 7 || value == 11) && gAPIndex == 2)
	{
		sprintf(cmd, UCI_DELETE_WIRELESS_DEVICE_1 "require_mode");
		system(cmd);
		CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
		if(value == 1){
			sprintf(cmd, UCI_SET_WIRELESS_DEVICE_1 "hwmode=%s && "UCI_DELETE_WIRELESS_DEVICE_1 "htmode", mode);
			gIs11nMode = 0;
		}
		else{
			sprintf(cmd, UCI_SET_WIRELESS_DEVICE_1 "hwmode=%s", mode);
			system(cmd);
			CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
			if(10 == value){
				sprintf(cmd, UCI_SET_WIRELESS_DEVICE_1 "require_mode=n");
			}
			gIs11nMode = 1;
		}
	}
	else
	{
		sprintf(cmd, UCI_DELETE_WIRELESS_DEVICE_0 "require_mode");
		system(cmd);
		CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
		if(value == 2 || value == 3){
			sprintf(cmd, UCI_SET_WIRELESS_DEVICE_0 "hwmode=%s && "UCI_DELETE_WIRELESS_DEVICE_0 "htmode", mode);
			gIs11nMode = 0;
		}
		else{
			sprintf(cmd, UCI_SET_WIRELESS_DEVICE_0 "hwmode=%s", mode);
			system(cmd);
			CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
			if(9 == value){
				sprintf(cmd, UCI_SET_WIRELESS_DEVICE_0 "require_mode=n");
			}
			gIs11nMode = 1;
		}
	}
	gWirelessMode = value;
	
	system(cmd);

	CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
	setUciWirelessChanMode(gOldChanMode, cmd);
	system(cmd);
	/*< δ��ʹ��htmode�ܽ���11nģʽ�²����ã��˲���ֱ���ύ*/
//	system("uci commit wireless");
	valPtr->restartwifi = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);
//	CWLog("## config ssid ####, cmd = %s", cmd);
	
	return CW_TRUE;
}

CWBool DTTParseUCIWirelessIsDisable(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr) {
	unsigned int IsDisable = 0;

	IsDisable = (unsigned int)CWProtocolRetrieve32(msgPtr);

	if(IsDisable < 0)
	{
		return CW_FALSE;
	}
	CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);

    
	if(gAPIndex == 1){
		if(1 == IsDisable){
			sprintf(cmd, UCI_SET_WIRELESS_DEVICE_0 "disabled=0");
		}
		else{
			sprintf(cmd, UCI_SET_WIRELESS_DEVICE_0 "disabled=1");
		}
	}else{
		if(1 == IsDisable){
			sprintf(cmd, UCI_SET_WIRELESS_DEVICE_1 "disabled=0");
		}
		else{
			sprintf(cmd, UCI_SET_WIRELESS_DEVICE_1 "disabled=1");
		}
	}

	system(cmd);
    CWLog("%s", cmd);
	valPtr->restartwifi = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);
//	CWLog("## config ssid ####, cmd = %s", cmd);
	
	return CW_TRUE;
}

unsigned int getCountryCodeCfg(){
	return CountryCode;
}

CWBool DTTParseUCIWirelessCountryCode(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr) {
	char country[16] = {0};

	CountryCode = (unsigned int)CWProtocolRetrieve32(msgPtr);

	CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);

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
	if(gAPIndex == 1){
		sprintf(cmd, UCI_SET_WIRELESS_DEVICE_0 "country=%s", country);
		//sprintf(cmd, UCI_SET_WIRELESS_DEVICE_0 "country=US");
	}
	else{
		sprintf(cmd, UCI_SET_WIRELESS_DEVICE_1 "country=%s", country);
		//sprintf(cmd, UCI_SET_WIRELESS_DEVICE_1 "country=US");
	}

	system(cmd);
	valPtr->restartwifi = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);
//	CWLog("## config ssid ####, cmd = %s", cmd);
	
	return CW_TRUE;
}

CWBool DTTParseUCIWirelessChannel(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr) {
	unsigned int channel = 0;

	/*< Ӧ�Ƚ��˲������ߣ������Ӱ��������������*/
	channel = (unsigned int)CWProtocolRetrieve32(msgPtr);

	if(g_autoChannelSwitch)
	{
//		CWLog("***********g_autoChannelSwitch=%d", g_autoChannelSwitch);
		gOldChan = channel;
		if(gAPIndex == 2 && 11 == gOldChan)
			gOldChan = 149;
		return CW_TRUE;
	}

	CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);

	if(channel < 15 && gAPIndex == 1)
	{
		sprintf(cmd, UCI_SET_WIRELESS_DEVICE_0 "channel=%d", channel);
	}
	else if(gAPIndex == 2){
		if(channel > 161)
			channel = 161;
		sprintf(cmd, UCI_SET_WIRELESS_DEVICE_1 "channel=%d", channel);
	}
	
	system(cmd);
	valPtr->restartwifi = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);
	/*< �˴������ŵ����Ա�֤����Ӧ�ر�ʱ����ʹ��ԭ�ŵ����ã���Ϊ�ر�����Ӧ��ʱ��AC�����·���ǰ���ŵ�*/
	gOldChan = channel;
//	CWLog("## config ssid ####, cmd = %s", cmd);
	
	return CW_TRUE;
}

CWBool DTTParseUCIWirelessBeaconInterval(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr) {
	unsigned int beaconInt = 0;

	beaconInt = (unsigned int)CWProtocolRetrieve32(msgPtr);

	CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);

	if(gAPIndex == 1)
		sprintf(cmd, UCI_SET_WIRELESS_DEVICE_0 "beacon_int=%d", beaconInt);
	else
		sprintf(cmd, UCI_SET_WIRELESS_DEVICE_1 "beacon_int=%d", beaconInt);

	system(cmd);
	valPtr->restartwifi = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);
	
	return CW_TRUE;
}

CWBool DTTParseUCIWirelessRTS(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr) {
	unsigned int rts = 0;

	rts = (unsigned int)CWProtocolRetrieve32(msgPtr);

	if(rts < 0 || rts > 2346)
	{
		return CW_FALSE;
	}
	CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
	
	if(gAPIndex == 1)
		sprintf(cmd, UCI_SET_WIRELESS_DEVICE_0 "rts=%d", rts);
	else
		sprintf(cmd, UCI_SET_WIRELESS_DEVICE_1 "rts=%d", rts);

	system(cmd);
	valPtr->restartwifi = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);
//	CWLog("## config ssid ####, cmd = %s", cmd);
	
	return CW_TRUE;
}
/*< DTIM ʱ���� (1-255) */
CWBool DTTParseUCIWirelessDtimInterval(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr) {
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
		CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
		sprintf(cmd, UCI_SET_WIRELESS_IFACE "[%d]." "dtim_period=%d", i+(gAPIndex-1)*8, dtim);
		system(cmd);
	}
	valPtr->restartwifi = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);
	
	return CW_TRUE;
}

CWBool DTTParseUCIWirelessTxPower(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr) {
	unsigned int txpower = 0;

	txpower = (unsigned int)CWProtocolRetrieve32(msgPtr);

	if(txpower < 0 || txpower > 40)
	{
		return CW_FALSE;
	}
	CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);

	if(0 == txpower)
	{
		if(gAPIndex == 1)
			sprintf(cmd, UCI_SET_WIRELESS_DEVICE_0 "txpower=%d", g_WtpMaxTxpower);
		else
			sprintf(cmd, UCI_SET_WIRELESS_DEVICE_1 "txpower=%d", g_WtpMaxTxpower);
	}
	else
	{
		if(gAPIndex == 1)
		/*< ZDC��AC�·��Ĺ���Ϊ��ţ���-0.5ʱ�·�1��-1ʱ�·�2�����Դ˴�Ҫת����openwrt�Ĺ��ʲ���Ϊ1������0.5��1����op����С��Ч����Ϊ3����������Ϊ1����2����ЧΪ3*/
			sprintf(cmd, UCI_SET_WIRELESS_DEVICE_0 "txpower=%d", g_WtpMaxTxpower-(txpower+1)/2);
		else
			sprintf(cmd, UCI_SET_WIRELESS_DEVICE_1 "txpower=%d", g_WtpMaxTxpower-(txpower+1)/2);
			
	}
	system(cmd);
	valPtr->restartwifi = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);
//	CWLog("## config ssid ####, cmd = %s", cmd);
	
	return CW_TRUE;
}

static int getNetworkConf(char cardIndex, unsigned int vlanid){
	FILE *fp = NULL;
	char buf[32] = {0};
	char cmd[UCI_CMD_LENGTH] = {0};
	int count = 0, k = 0;
	
	if(gCWAPCardCount == CW_ONE_CARD)
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
	if(APIndex == 1)
    {
		for(i = MAX_VAP*2-1;i >= 0;i --)
		{
			CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
			sprintf(cmd, "uci delete network.@switch_vlan[%d]", 2+i);
//			printf("cmd=%s\n", cmd);
			system(cmd);
		}
		
		shared->switchId = 1;
	}
    else
    {
		for(i = 0;i < MAX_VAP;i ++)
		{
			for(j = 0; j < i; j ++)
			{
				if(shared->vapVlan[i] == shared->vapVlan[j])
				{
					switchCount --;
					break;
				}
			}
		}
//		printf("switchId = %d, switchCount=%d\n", shared->switchId, switchCount);
		/*< switch�л���lan��wan,����switch����Ǵ�2��ʼ*/
		for(i = shared->switchId;i > switchCount+1; i --)
		{
			CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
			sprintf(cmd, "uci delete network.@switch_vlan[%d]", i);
//			printf("cmd=%s\n", cmd);
			system(cmd);
			shared->switchId --;
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
				shared->switchId ++;

				CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
				sprintf(cmd,  "uci add network switch_vlan");
				system(cmd);

				CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
				sprintf(cmd,  "uci set network.@switch_vlan[%d].device=switch0", shared->switchId);
				system(cmd);

				CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
				sprintf(cmd,  "uci set network.@switch_vlan[%d].vlan=%d", shared->switchId, shared->switchId+1);
				system(cmd);
				
				CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
				sprintf(cmd,  "uci set network.@switch_vlan[%d].vid=%d", shared->switchId, vapVlan[i]==1?3:vapVlan[i]);
				system(cmd);
				
				CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
				sprintf(cmd,  "uci set network.@switch_vlan[%d].ports='0t %dt'", shared->switchId, wanSwitchPort);
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
			}
		}
		else
        {
			CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
			sprintf(cmd,  "uci set wireless.@wifi-iface[%d].network=vlan%d", i+(APIndex-1)*8, k+1);
			system(cmd);
//			printf("333cmd:%s\n", cmd);
			
			CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
			sprintf(cmd, "uci set network.vlan%d.disabled=1", i+1+(APIndex-1)*8);
			system(cmd);
		}
	}
}

CWBool DTTParseUCIWirelessVAPVlan(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr) {
	int i = 0;
	unsigned int vapVlan[MAX_VAP] = {0};

	/*< ���߶�����networkȥ����vlan���������������*/
	pthread_mutex_lock(&shared->mutex);

	/*< network�ļ���ǰ8��wifi-iface�ֶι�2.4G����8����5.8G*/
	for(i = 0;i < MAX_VAP;i ++)
	{
		vapVlan[i] = (unsigned int)CWProtocolRetrieve32(msgPtr);
		shared->vapVlan[i+(gAPIndex-1)*8] = vapVlan[i];
	}
	/*< ��2.4G��5.8G�ǹ���һ��vlan�������߹�����һ��vlan��ʱ�򣬴�ʱһ�������仯����һ��Ҳ������������vlan*/
	DTTSetVlan(cmd, vapVlan, gAPIndex);
	if(2 == gAPIndex){
	}
    shared->isSeted_5 = 1;
	if(1 == gAPIndex && shared->isSeted_5){
		DTTSetVlan(cmd, shared->vapVlan+8, 2);
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
	pthread_mutex_unlock(&shared->mutex);

	if(localInfo.flag){
		setCentreForwardMark(localInfo.localSwitch, cmd, valPtr);
	}
	/*< ��λΪ1ʱ����������������*/
	if(trafficLimitSet){
		setUploadLimit(cmd);
		valPtr->trafficDownloadLimit = 1;
	}
	valPtr->restartNetwork = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);
	return CW_TRUE;
}


CWBool DTTParseUCIWirelessVAPSwitch(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr) {
	int i = 0;

	for(i = 0;i < MAX_VAP;i ++)
	{
		vapSwitch[i] = (unsigned int)CWProtocolRetrieve32(msgPtr);
		shared->shmVapSwitch[i+(gAPIndex-1)*8] = vapSwitch[i];
		CWLog("## config ssid ####, vapSwitch[%d]=%d", i, vapSwitch[i]);
		if(vapSwitch[i] != 0 && vapSwitch[i] != 1)
		{
			return CW_FALSE;
		}
	}

	for(i = 0;i < MAX_VAP;i ++)
	{
		CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
		if(vapSwitch[i] == 0){
			sprintf(cmd, UCI_SET_WIRELESS_IFACE "[%d]." "disabled=1", i+(gAPIndex-1)*8);
		}
		else{
			sprintf(cmd, UCI_SET_WIRELESS_IFACE "[%d]." "disabled=0", i+(gAPIndex-1)*8);
		}
		system(cmd);
		CWLog("##cmd = %s", cmd);
	}
	/*< ��ΪΪ1ʱ�����������ü���ת��*/
	if(localInfo.flag){
		setCentreForwardMark(localInfo.localSwitch, cmd, valPtr);
	}
	/*< ��λΪ1ʱ����������������*/
	if(trafficLimitSet){
		setUploadLimit(cmd);
		valPtr->trafficDownloadLimit = 1;
	}
	
	valPtr->restartwifi = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);
	
	return CW_TRUE;
}

CWBool DTTParseUCIWirelessSSID(CWProtocolMessage *msgPtr, char *cmd, unsigned short len, CWProtocolVendorSpecificValues* valPtr) {
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
		CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
		sprintf(cmd, UCI_SET_WIRELESS_IFACE "[%d]." "ssid=%s", i+(gAPIndex-1)*8, ssid[i]);
		system(cmd);
		CWLog("##cmd = %s", cmd);
	}
	valPtr->restartwifi = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);
	
	return CW_TRUE;
}

CWBool DTTParseUCIWirelessHideSSID(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr) {
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
		CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
		sprintf(cmd, UCI_SET_WIRELESS_IFACE "[%d]." "hidden=%d", i+(gAPIndex-1)*8, hide[i]);
		system(cmd);
		//CWLog("## config ssid ####, cmd = %s", cmd);
	}
	valPtr->restartwifi = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);
	
	return CW_TRUE;
}

/*< VAP��WPA_PSK������������*/
CWBool DTTParseUCIWirelessWPAPSK(CWProtocolMessage *msgPtr, char *cmd, unsigned short len, CWProtocolVendorSpecificValues* valPtr)
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
		CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
		sprintf(cmd, UCI_SET_WIRELESS_IFACE "[%d]." "key=%s", i+(gAPIndex-1)*8, psk[i]);
//		CWLog("cmd = %s", cmd);
		system(cmd);
	}

	valPtr->restartwifi = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);

	return CW_TRUE;
}

/*< VAP��֤��ʽ*/
CWBool DTTParseUCIWirelessAuthType(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr)
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
			case WIRELESS_AUTH_LEGACY_8021X:
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
CWBool DTTParseUCIWirelessEncryptType(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr)
{
	unsigned int type[MAX_VAP] = {0};
	int i = 0;

	for(i = 0;i < MAX_VAP;i ++)
	{
		type[i] = (unsigned int)CWProtocolRetrieve32(msgPtr);
//		CWLog("type[%d] = %d, i = %d", i, type[i], i);
		switch(type[i]){
			case WIRELESS_AUTH_ENCRYPT_NONE:
				CW_ZERO_MEMORY(gWirelessAuthType[i], UCI_CMD_LENGTH);
				strcpy(gWirelessAuthType[i], "none");
				break;
			case WIRELESS_AUTH_ENCRYPT_WEP:
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
				break;
		}
	}
	for(i = 0;i < MAX_VAP;i ++)
	{
		UCI_IFACE_SET_PARAM_STRING(cmd, i+(gAPIndex-1)*8, "encryption", gWirelessAuthType[i]);
		
		/*< ��SSIDΪradius��֤ʱ*/
		if(1 == radiusFlag[i]){
			UCI_IFACE_SET_PARAM_STRING(cmd, i+(gAPIndex-1)*8, "auth_server", inet_ntoa(radiusIP[0]));
			UCI_IFACE_SET_PARAM_INT(cmd, i+(gAPIndex-1)*8, "auth_port", radiusPort[0]);
			UCI_IFACE_SET_PARAM_STRING(cmd, i+(gAPIndex-1)*8, "auth_secret", radiusSecret[0]);
			
			UCI_IFACE_SET_PARAM_STRING(cmd, i+(gAPIndex-1)*8, "acct_server", inet_ntoa(radiusIP[2]));
			UCI_IFACE_SET_PARAM_INT(cmd, i+(gAPIndex-1)*8, "acct_port", radiusPort[2]);
			UCI_IFACE_SET_PARAM_STRING(cmd, i+(gAPIndex-1)*8, "acct_secret", radiusSecret[2]);
		}else{
			if(radiusOldFlag[i]){
				UCI_IFACE_DEL_PARAM(cmd, i+(gAPIndex-1)*8, "auth_server");
				UCI_IFACE_DEL_PARAM(cmd, i+(gAPIndex-1)*8, "auth_port");
				UCI_IFACE_DEL_PARAM(cmd, i+(gAPIndex-1)*8, "auth_secret");
				UCI_IFACE_DEL_PARAM(cmd, i+(gAPIndex-1)*8, "acct_server");
				UCI_IFACE_DEL_PARAM(cmd, i+(gAPIndex-1)*8, "acct_port");
				UCI_IFACE_DEL_PARAM(cmd, i+(gAPIndex-1)*8, "acct_secret");
				radiusOldFlag[i] = radiusFlag[i];
			}
		}
	}

	valPtr->restartwifi = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);

	return CW_TRUE;
}

static void setEbtables(int count, int type)
{
	char cmd[256] = {0};
	char wlan[16] = {0};

	if(gAPIndex == 1){
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

CWBool DTTParseIsolate(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr)
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
		if(vapSwitch[i]){
			setEbtables(vapIndex, isolate[i]);
			vapIndex ++;
		}
	}
	
	return CW_TRUE;
}

CWBool DTTParseUCIWirelessAutoChannel(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr) {
	unsigned int autoChanSwitch = 0;

	autoChanSwitch = (unsigned int)CWProtocolRetrieve32(msgPtr);

	if(NULL == cmd)
	{
		return CW_FALSE;
	}
	CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);

	if(autoChanSwitch == 1)
	{
		g_autoChannelSwitch = 1;
		if(gAPIndex == 1)
			sprintf(cmd, UCI_SET_WIRELESS_DEVICE_0 "channel=auto");
		else if(gAPIndex == 2){
			/*< 5.8G����Ӧ�����⣬��ʱ��149����*/
			sprintf(cmd, UCI_SET_WIRELESS_DEVICE_1 "channel=auto");
		}
	}else if(autoChanSwitch == 0){
		g_autoChannelSwitch = 0;
		if(gAPIndex == 1)
			sprintf(cmd, UCI_SET_WIRELESS_DEVICE_0 "channel=%d", gOldChan);
		else if(gAPIndex == 2)
			sprintf(cmd, UCI_SET_WIRELESS_DEVICE_1 "channel=%d", gOldChan);
	}
	
	system(cmd);
	valPtr->restartwifi = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);
	
	return CW_TRUE;
}
/*< ǰ��֡����:   0:��  1:����Ӧ*/
CWBool DTTParseUCIWirelessPreamble(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr) {
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
		UCI_IFACE_SET_PARAM_INT(cmd, i+(gAPIndex-1)*8, "short_preamble", preamble);
	}
	valPtr->restartwifi = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);
	
	return CW_TRUE;
}

CWBool DTTParseUCIRadiusServer(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr){
	int i = 0;
	unsigned int ip;

	for(i = 0;i < 4; i ++){
		ip = (unsigned int)CWProtocolRetrieve32(msgPtr);
		memcpy(radiusIP+i, &ip, 4);
//		CWLog("radiusIP[%d] = %s\n", i, inet_ntoa(radiusIP[i]));
	}
	
	return CW_TRUE;
}

CWBool DTTParseUCIRadiusPort(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr){
	int i = 0;

	for(i = 0;i < 4; i ++){
		radiusPort[i] = (unsigned int)CWProtocolRetrieve32(msgPtr);
//		CWLog("radiusPort[%d] = %d\n", i, radiusPort[i]);
	}
	
	return CW_TRUE;
}

CWBool DTTParseUCIRadiusSecret(CWProtocolMessage *msgPtr, char *cmd, unsigned short len, CWProtocolVendorSpecificValues* valPtr){
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

CWBool DTTParseUCIAPPassword(CWProtocolMessage *msgPtr, char *cmd, unsigned short len, CWProtocolVendorSpecificValues* valPtr){
	char *passwd = NULL;

	/*< password�ֽ��20*/
	if(len > 20)
		len = 20;
	
	passwd = CWProtocolRetrieveStr(msgPtr, len);

	/*< 5.8G��WTPʱ��ֱ�ӷ���,�ҷ���ʱ������Ѹ�λ����*/
	if(gAPIndex == 2)
		return CW_TRUE;

	if(!passwd)
		return CW_FALSE;
	
	CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
	sprintf(cmd, "(echo \"%s\"; sleep 1; echo \"%s\") | passwd > /dev/null  &", passwd, passwd);
	system(cmd);

	CW_FREE_OBJECT(passwd);
	
	return CW_TRUE;
}

/*< wmm:   0:����  1:����*/
CWBool DTTParseUCIWirelessWmm(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr) {
	unsigned int wmm = 0;
	int i = 0;

	wmm = (unsigned int)CWProtocolRetrieve32(msgPtr);

	if(wmm != 1 && wmm != 0)
	{
		/*< ���������÷�Χ��ֱ��ָ��ΪĬ��ֵ1*/
		wmm = 1;
	}
	/*< �����ԣ�openwrt�£�������wifi-device����Ч����������ÿһ��wifi-iface�Ͻ�������*/
	for(i = 0;i < MAX_VAP;i ++)
	{
		UCI_IFACE_SET_PARAM_INT(cmd, i+(gAPIndex-1)*8, "wmm", wmm);
	}
	valPtr->restartwifi = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);
	
	return CW_TRUE;
}

CWBool DTTParseUCIVapMaxSta(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr){
	unsigned int count[8] = {0};
	int i = 0;

	for(i = 0;i < MAX_VAP; i ++){
		count[i] = (unsigned int)CWProtocolRetrieve32(msgPtr);
		UCI_IFACE_SET_PARAM_INT(cmd, i+(gAPIndex-1)*8, "maxsta", count[i]);
	}
	
//	system(UCI_COMMIT_WIRELESS);
	valPtr->restartwifi = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);
	
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
	if(gAPIndex == 1){
		EBTABLES_CLEAR_CHAIN("24FORWARD", cmd);
	}else{
		EBTABLES_CLEAR_CHAIN("58FORWARD", cmd);
	}
	for(i = 0;i < MAX_VAP;i ++){
		if(vapSwitch[i] == 1){
			/*< ����ת��ʱ���˱�־λΪ0��δ����vap��ҲΪ0*/
			if(pLocalSwitch[i] == 0){
				if(gAPIndex == 1){
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
				if(gAPIndex == 1){
					EBTABLES_SET_MARK("24FORWARD", wlan, ((shared->vapVlan[i+(gAPIndex-1)*8]+1000) << 6) | (gAPIndex-1), cmd);
				}
				else{
					EBTABLES_SET_MARK("58FORWARD", wlan, ((shared->vapVlan[i+(gAPIndex-1)*8]+1000) << 6) | (gAPIndex-1), cmd);
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

CWBool DTTParseLocalForwardSwitch(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr)
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
	
	setCentreForwardMark(localInfo.localSwitch, cmd, valPtr);
	/*��Ϊ��ϵ�����кͱ��ص�mark�����ٵĻ����㣬���������꼯��ת������Ҫ������������*/
	if(trafficLimitSet){
		setUploadLimit(cmd);
	}
	
	return CW_TRUE;
}

CWBool DTTParseUCIAPName(CWProtocolMessage *msgPtr, char *cmd, unsigned short len, CWProtocolVendorSpecificValues* valPtr){
	char *name = NULL;
	char cmd_buf[128] = {0};
    
	/*< password�ֽ��20*/
	if(len > 128)
		len = 128;
	
	name = CWProtocolRetrieveStr(msgPtr, len);

	/*< 5.8G��WTPʱ��ֱ�ӷ���*/
	if(gAPIndex == 2)
		return CW_TRUE;

	if(!name)
		return CW_FALSE;
	
	CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
	sprintf(cmd, "uci set system.@system[-1].hostname='%s'", name);
	system(cmd);

    /* ������Ч */
	sprintf(cmd_buf, "echo %s > /proc/sys/kernel/hostname", name);
	system(cmd_buf);
    
	CW_FREE_OBJECT(name);

	valPtr->restartSystem = 1;
	
	return CW_TRUE;
}

void setUciWirelessChanMode(unsigned int ChanMode, char *cmd)
{
	/*< ��11nģʽ��ֱ������*/ //qcawifi disablecoext insdead of noscan
	if(!gIs11nMode)
		return;

	/*< 11ACģʽ*/
	if(11 == gWirelessMode)
	{
		switch(ChanMode)
		{
			case 0:
				sprintf(cmd, "uci set wireless.@wifi-device[%d].htmode=VHT20 && uci delete wireless.@wifi-device[%d].disablecoext", gAPIndex-1, gAPIndex-1);
				break;
			case 1:
				sprintf(cmd, "uci set wireless.@wifi-device[%d].htmode=VHT40 && uci delete wireless.@wifi-device[%d].disablecoext", gAPIndex-1, gAPIndex-1);
				break;
			case 2:
				sprintf(cmd, "uci set wireless.@wifi-device[%d].htmode=VHT40 && uci set wireless.@wifi-device[%d].disablecoext=1", gAPIndex-1, gAPIndex-1);
				break;
			case 5:
				sprintf(cmd, "uci set wireless.@wifi-device[%d].htmode=VHT80 && uci set wireless.@wifi-device[%d].disablecoext=1", gAPIndex-1, gAPIndex-1);
				break;
			default:
				sprintf(cmd, "uci set wireless.@wifi-device[%d].htmode=VHT20 && uci delete wireless.@wifi-device[%d].disablecoext", gAPIndex-1, gAPIndex-1);
				break;
		}
	}else{
		switch(ChanMode)
		{
			case 0:
				sprintf(cmd, "uci set wireless.@wifi-device[%d].htmode=HT20 && uci delete wireless.@wifi-device[%d].disablecoext", gAPIndex-1, gAPIndex-1);
				break;
			case 1:
				sprintf(cmd, "uci set wireless.@wifi-device[%d].htmode=HT40 && uci delete wireless.@wifi-device[%d].disablecoext", gAPIndex-1, gAPIndex-1);
				break;
			case 2:
				sprintf(cmd, "uci set wireless.@wifi-device[%d].htmode=HT40 && uci set wireless.@wifi-device[%d].disablecoext=1", gAPIndex-1, gAPIndex-1);
				break;
			default:
				sprintf(cmd, "uci set wireless.@wifi-device[%d].htmode=HT40 && uci delete wireless.@wifi-device[%d].disablecoext", gAPIndex-1, gAPIndex-1);
				break;
		}
	}
}

CWBool DTTParseUCI11nChanMode(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr) {
	unsigned int ChanMode = 0;

	ChanMode = (unsigned int)CWProtocolRetrieve32(msgPtr);

	/*< ��11nģʽ��ֱ������*/
	if(!gIs11nMode)
		return CW_TRUE;
	
	CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
	setUciWirelessChanMode(ChanMode, cmd);
	system(cmd);

	valPtr->restartwifi = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);

	gOldChanMode = ChanMode;
	/*< �߼�˳��shortGI�ӿ��л�ʹ��gOldChanMode����*/
	DTTParseUCIShortGI(NULL, cmd, NULL);
	return CW_TRUE;
}

CWBool DTTParseUCIShortGI(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr) {
	if(msgPtr)
		shortGI = (unsigned int)CWProtocolRetrieve32(msgPtr);

	/*< ��11nģʽ��ֱ������*/
	if(!gIs11nMode)
		return CW_TRUE;
	
	CW_ZERO_MEMORY(cmd, UCI_CMD_LENGTH);
#if 0
	/*< �رն̱������ʱ��ֱ�ӽ�20��40��shortgi������Ϊ0*/
	if(0 == shortGI){
		sprintf(cmd, "uci set wireless.@wifi-device[%d].short_gi_20=0 && uci set wireless.@wifi-device[%d].short_gi_40=0", gAPIndex-1, gAPIndex-1);
	}else{
		switch(gOldChanMode)
		{
			case 0:
				sprintf(cmd, "uci set wireless.@wifi-device[%d].short_gi_20=1 && uci set wireless.@wifi-device[%d].short_gi_40=0", gAPIndex-1, gAPIndex-1);
				break;
			case 1:
				sprintf(cmd, "uci set wireless.@wifi-device[%d].short_gi_20=1 && uci set wireless.@wifi-device[%d].short_gi_40=1", gAPIndex-1, gAPIndex-1);
				break;
			case 2:
				sprintf(cmd, "uci set wireless.@wifi-device[%d].short_gi_20=0 && uci set wireless.@wifi-device[%d].short_gi_40=1", gAPIndex-1, gAPIndex-1);
				break;
			default:
				sprintf(cmd, "uci set wireless.@wifi-device[%d].short_gi_20=1 && uci set wireless.@wifi-device[%d].short_gi_40=1", gAPIndex-1, gAPIndex-1);
				break;
		}
	}
#else
    if(0 == shortGI){
		sprintf(cmd, "uci set wireless.@wifi-device[%d].shortgi=0", gAPIndex-1);
	}else{
		switch(gOldChanMode)
		{
			case 0:
				sprintf(cmd, "uci set wireless.@wifi-device[%d].shortgi=0", gAPIndex-1);
				break;
			case 1:
				sprintf(cmd, "uci set wireless.@wifi-device[%d].shortgi=1", gAPIndex-1);
				break;
			case 2:
				sprintf(cmd, "uci set wireless.@wifi-device[%d].shortgi=1", gAPIndex-1);
				break;
			default:
				sprintf(cmd, "uci set wireless.@wifi-device[%d].shortgi=1", gAPIndex-1);
				break;
		}
	}
#endif
	system(cmd);
	if(valPtr){
		valPtr->restartwifi = 1;
		valPtr->cfgNetMutex = &(shared->cfgNetMutex);
	}

	return CW_TRUE;
}

/*< ���ٿ���*/
CWBool DTTParseVAPTrafficLimitSwitch(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr)
{
	int i = 0;
	for(i = 0;i < MAX_VAP;i ++)
	{
		shared->trafficLimitSwitch[i+(gAPIndex-1)*8] = (unsigned int)CWProtocolRetrieve32(msgPtr);
	}
	if(trafficLimitSet){
		setUploadLimit(cmd);
		valPtr->trafficDownloadLimit = 1;
		valPtr->cfgNetMutex = &(shared->cfgNetMutex);
	}
	return CW_TRUE;
}

static void setUploadLimit(char *cmd)
{
	int i = 0, j = 0;
	unsigned int mark = 0;
	int wlanFlag = 0, id = 0;
	char wlan[16] = {0};

//	TC_QISC_CLEAR_ROOT(cmd, "eth0");
	TC_QISC_ROOT_CREAT(cmd, "eth0");

	if(1 == gAPIndex)
		system("ebtables -t nat -F QOS_24UPLOAD_CHAIN");
	else
		system("ebtables -t nat -F QOS_58UPLOAD_CHAIN");

	for(i = 0;i < MAX_VAP;i ++){
		/*< openwrt�У����߽ӿ���ʼ��Ϊwlan0,wlan0-1����*/
		if(vapSwitch[i]){
			if(gAPIndex == 1){
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
		id = (i+SSID_LIMIT_BANDWIDTH_CLASSID_OFFSET+(gAPIndex-1)*8) << 1;

		if(0 == localInfo.localSwitch[i]){
			pthread_mutex_lock(&shared->mutex);
			mark = (shared->vapVlan[i+(gAPIndex-1)*8]+1000) << 6;
			pthread_mutex_unlock(&shared->mutex);
		}else{
			mark = 0;
		}
		if(shared->trafficLimitSwitch[i+(gAPIndex-1)*8]){
			/*< �������ٹ���ʱ��ʹ��replace�������ڣ��򴴽������ڣ����޸�*/
			/*< ���ٵ��������Ŵ�10��ʼ*/
			TC_TRAFFIC_LIMIT(cmd, "eth0", id, upLoadLimit[i]);
			TC_ADD_FILTER(cmd, "eth0", mark | id | (gAPIndex-1), id);
			TC_QDISC_SQF(cmd, "eth0", id, mark | id | (gAPIndex-1));
		}else{
			TC_DEL_FILTER(cmd, "eth0", mark | id | (gAPIndex-1), id);
			TC_CLEAR_CLASS_TRAFFIC_LIMIT(cmd, "eth0", id);
		}
		/*< �����Ƿ������٣���Ӧ�ô������mark�����mark���������٣�Ҳ���ڼ���ת��ʱwltpͷ�е�vap index*/
		/*< ��������markʱ���뱾��ת������ת����markȡ������*/
		if(1 == gAPIndex){
			TC_UPLOAD_EBTABLES_MARK(cmd, wlan, mark | id | (gAPIndex-1), "QOS_24UPLOAD_CHAIN");
		}
		else{
			TC_UPLOAD_EBTABLES_MARK(cmd, wlan, mark | id | (gAPIndex-1), "QOS_58UPLOAD_CHAIN");
		}
	}
}
/*< ��������*/
CWBool DTTParseVAPUploadLimit(CWProtocolMessage *msgPtr, char *cmd)
{
	int i = 0;

	for(i = 0;i < MAX_VAP;i ++)
	{
		upLoadLimit[i] = (unsigned int)CWProtocolRetrieve32(msgPtr);
	}
	setUploadLimit(cmd);
	trafficLimitSet = 1;
	
	return CW_TRUE;
}
/*< ��������ʵ�����ýӿ�*/
void setDownloadLimit(char *cmd, char index)
{
	int i = 0, j = 0;
	int id = 0;
	int wlanFlag = 0; 
	char wlan[16] = {0};
	
	if(1 == index)
		system("ebtables -t nat -F QOS_24DOWNLOAD_CHAIN");
	else
		system("ebtables -t nat -F QOS_58DOWNLOAD_CHAIN");
	
	for(i = 0;i < MAX_VAP;i ++){
		/*< openwrt�У����߽ӿ���ʼ��Ϊwlan0,wlan0-1����*/
		if(shared->shmVapSwitch[i+(index-1)*8]){
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
		if(!shared->trafficLimitSwitch[i+(index-1)*8]){
			continue;
		}
		id = i+SSID_LIMIT_BANDWIDTH_CLASSID_OFFSET+(index-1)*8;

		/*< ��ʱ�ȴ�*/
		TC_SLEEP_WAIT_WLAN(cmd, wlan);
		TC_QISC_ROOT_CREAT(cmd, wlan);
		/*< ���ٹ�����ÿ����ͬ�������ϣ����Ծ�������һ����Ҳ�ֱ��������*/
		/*< �������ٹ���ʱ��ʹ��replace�������ڣ��򴴽������ڣ����޸�*/
		/*< ���ٵ��������Ŵ�10��ʼ*/
		TC_TRAFFIC_LIMIT(cmd, wlan, id, shared->downLoadLimit[i+(index-1)*8]);
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
}

/*< ��������*/
CWBool DTTParseVAPDownloadLimit(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr)
{
	int i = 0;

	for(i = 0;i < MAX_VAP;i ++)
	{
		shared->downLoadLimit[i+(gAPIndex-1)*8] = (unsigned int)CWProtocolRetrieve32(msgPtr);
//		printf("downLoadLimit[%d]=%d\n", i, downLoadLimit[i]);
	}
	valPtr->trafficDownloadLimit = 1;
	valPtr->cfgNetMutex = &(shared->cfgNetMutex);
//	setDownloadLimit(cmd);
	trafficLimitSet = 1;
	
	return CW_TRUE;
}

CWBool DTTParseACLControl(CWProtocolMessage *msgPtr, char *cmd, unsigned short len, CWProtocolVendorSpecificValues* valPtr)
{
	aclControlCfg *aclCont = NULL;
	
	aclCont = (aclControlCfg *)CWProtocolRetrieveStr(msgPtr, len);

	if(!aclCont)
		return CW_FALSE;
	
	switch(aclCont->aclType){
		case ACL_TYPE_RESPONSR:
			setAclAuthResultInfo(aclCont);
			valPtr->dttAclConfigUpdate = 1;
			break;
		case ACL_TYPE_SWITCH_ON:
			setACLSwitch(1);
			break;
		case ACL_TYPE_SWITCH_OFF:
			setACLSwitch(0);
			break;
		default:
			break;
	}
	
	return CW_TRUE;
}

CWBool DTTParseRebootAP(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr){
	
	valPtr->reboot = (unsigned int)CWProtocolRetrieve32(msgPtr);
	
	return CW_TRUE;
}

CWBool DTTParseResetFactoryAP(CWProtocolMessage *msgPtr, char *cmd, CWProtocolVendorSpecificValues* valPtr){
	
	unsigned int flag = (unsigned int)CWProtocolRetrieve32(msgPtr);
	if(flag == 1){
		/*< ��Ҫ�ظ���reponse֮���ٽ��лָ�����*/
		system("sleep 2 && rm /overlay/* -rf &");
		system("sleep 5 && reboot -f &");
	}
	
	return CW_TRUE;
}
CWBool DTTParseTemplateID(CWProtocolMessage *msgPtr){
	
	unsigned int flag = (unsigned int)CWProtocolRetrieve32(msgPtr);

	if(gTemplateID != flag){
		gTemplateID = flag;
		if(1 == gAPIndex){
			sendto_kmod(CW_NLMSG_SET_TEMPLATEID_1, (s8 *)&gTemplateID, sizeof(u32));
		}else{
			sendto_kmod(CW_NLMSG_SET_TEMPLATEID_2, (s8 *)&gTemplateID, sizeof(u32));
		}
	}
	
	return CW_TRUE;
}

#if 0
/*< �˽ӿ����ڲ���ĳһ��mac���ڵ�vlan�������±�*/
static int iwinfoGetMacVlanid(char *mac)
{
    FILE* cardfp = NULL;
    FILE* fp = NULL;

    char cmd[128] = {0};
    char buffer[256] = {0};

    char card[16] = {0};
    int i = 0;
	char flag = 0;

    strcpy(cmd, "iwinfo");
    cardfp = popen(cmd,"r");
    if(cardfp){
        while(fgets(buffer, sizeof(buffer), cardfp)){
            if('\t' == buffer[0] || '\n' == buffer[0]|| ' ' == buffer[0])
                    continue;
            while(buffer[i] != ' ')
            	i ++;
            strncpy(card, buffer, i);
            printf("card:%s#\n", card);
			memset(cmd, 0, sizeof(cmd));
			sprintf(cmd, "iw dev %s station dump | grep %s | wc -l", card, mac);
			fp = popen(cmd, "r");
			if(fp){
				fgets(&flag, sizeof(flag), fp);
				if(flag)
					break;
				pclose(fp);
				fp = NULL;
			}
			
            memset(buffer, 0, sizeof(buffer));
			if(!flag)
            	memset(card, 0, sizeof(card));
            i = 0;
        }
        pclose(cardfp);
		cardfp = NULL;
    }else{
        return CW_FALSE;
    }
    return CW_TRUE;

}
/*< ����sta��������*/
static CWBool setStaUploadLimit(char *cmd, int i)
{
	int i= 0,j = 0;
	unsigned int mark = 0;
	int wlanFlag = 0, id = 0;
	char wlan[16] = {0};
	char flag = 0;
	char macBuf[32] = {0};

//	TC_QISC_CLEAR_ROOT(cmd, "eth0");
//	TC_QISC_ROOT_CREAT(cmd, "eth0");

	system("ebtables -t nat -F QOS_STA_UPLOAD_CHAIN");
	for(i = 0;i < upLoadStaLimitCount; i++){
		memset(macBuf, 0, sizeof(macBuf));
		snprintf(macBuf, sizeof(macBuf), MACSTR, MAC2STR(upLoadStaLimit[i]->mac));
		
		/*< ����SSID���ٵ�classid��10��ʼ������sta���ٵ�classid��32��ʼ*/
		id = i+STA_LIMIT_BANDWIDTH_CLASSID_OFFSET;
		/*< ��Ϊ�漰������ת����mark��ǣ��������Ѿ�������vlan������£��ſ��Խ��л���mac����������*/
		if(vlanSetFlag){
			pthread_mutex_lock(&shared->mutex);
			mark = (shared->vapVlan[i+(gAPIndex-1)*8]+1000)<<10;
			pthread_mutex_unlock(&shared->mutex);
		}else{
			return CW_FALSE;
		}

		for(j = 0;j < i;j ++){
			if(upLoadStaLimit[i]->up == upLoadStaLimit[j]->up){
				flag = 1;
			}
		}
		if(!flag){
			/*< ���ٵ��������Ŵ�10��ʼ*/
			TC_TRAFFIC_LIMIT(cmd, "eth0", id, upLoadStaLimit[i]->up);
			TC_ADD_FILTER(cmd, "eth0", mark | id, id);
			TC_QDISC_SQF(cmd, "eth0", id, mark | id);
		}else{
			/*< ֱ�ӽ����������Ѵ��ڵ����*/
			TC_ADD_FILTER(cmd, "eth0", mark | id, j+STA_LIMIT_BANDWIDTH_CLASSID_OFFSET);
			TC_QDISC_SQF(cmd, "eth0", j+STA_LIMIT_BANDWIDTH_CLASSID_OFFSET, mark | id);
		}
		TC_STA_UPLOAD_EBTABLES_MARK(cmd, upLoadStaLimit[i]->mac, mark | id);
	}
	return CW_TRUE;
}

#endif

CWBool DTTParseStaLimit(CWProtocolMessage *msgPtr, char *cmd, unsigned short len, CWProtocolVendorSpecificValues* valPtr)
{
	unsigned int StaCount = 0;
	int i = 0;
//	staLimitCfg *limitInfo = NULL;
	
	StaCount = (unsigned int)CWProtocolRetrieve32(msgPtr);

	for(i = 0;i < upLoadStaLimitCount;i ++){
//		TC_DEL_TRAFFIC_LIMIT_CLASS(cmd, "eth0", i+STA_LIMIT_BANDWIDTH_CLASSID_OFFSET);
	}

	for(i = 0;i < StaCount;i ++){
		upLoadStaLimit[i] = (staLimitCfg *)CWProtocolRetrieveStr(msgPtr, sizeof(staLimitCfg));
//		setStaUploadLimit(cmd, i);
	}
	upLoadStaLimitCount = StaCount;
	
	return CW_TRUE;
}

