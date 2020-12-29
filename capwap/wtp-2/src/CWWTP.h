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


#ifndef __CAPWAP_CWWTP_HEADER__
#define __CAPWAP_CWWTP_HEADER__

/*_______________________________________________________*/
/*  *******************___INCLUDE___*******************  */

#include "CWCommon.h"
#include "WTPProtocol.h"
#include "WTPBinding.h"

#include "DTTWltp.h"
#include "DTTWTPProtocol.h"

/*______________________________________________________*/
/*  *******************___DEFINE___*******************  */
#define WTP_LOG_FILE_NAME_1	"/var/log/wtp-1.log.txt"
#define WTP_LOG_FILE_NAME_2	"/var/log/wtp-2.log.txt"
#define WTP_LOG_FILE_NAME_3	"/var/log/wtp-3.log.txt"

/*_____________________________________________________*/
/*  *******************___TYPES___*******************  */

typedef struct {
	char address[32];
	CWBool received;
	int seqNum;
} CWACDescriptor;

typedef struct {
	int gCWACCount;
	CWACDescriptor *gCWACList;
	int broadcastFlag;				/*< 添加广播地址之后，该标记置1，防止多次添加*/
	CWThreadMutex mutex;
} CWACFoundCfg;

/*< 
 *	AP上线时发现AC的方式
 *
 *	共4种:1.静态配置 2.option43 3.DNS 4.广播
 *
 */
enum {
	WTP_FOUND_AC_TYPE_INIT,
	WTP_FOUND_AC_TYPE_STATIC,
	WTP_FOUND_AC_TYPE_OPTION43,
	WTP_FOUND_AC_TYPE_DNS,
	WTP_FOUND_AC_TYPE_BROADCAST,
};

/*_____________________________________________________________*/
/*  *******************___WTP VARIABLES___*******************  */
extern char* gInterfaceName;
extern char* gWanIfname;
extern int wanSwitchPort;

extern char **gCWACAddresses;
extern CWACFoundCfg *gCWACCfg;

extern char *gWTPLocation;
extern char *gWTPName;
extern int gIPv4StatusDuplicate;
extern int gIPv6StatusDuplicate;
extern CWAuthSecurity gWTPForceSecurity;

extern CWSocket gWTPSocket;
extern CWSocket gWTPDataSocket;

extern int gWTPPathMTU;
extern char gAPIndex;
extern char g_DevModel[64];
extern char g_DevMAC[64];
extern char g_DevSn[64];
extern char g_DevHwMode[48];
extern char g_DevFwMode[48];
extern char g_DevHideFwMode[48];
extern char g_SlaveDevMAC[64];
extern char gCWAPCardCount;
extern char g_DevIP[32];
extern unsigned int g_WtpMaxTxpower;

//extern CWACDescriptor *gCWACList;
extern CWACInfoValues *gACInfoPtr;

extern int gEchoInterval;
extern int gWTPStatisticsTimer;
extern WTPRebootStatisticsInfo gWTPRebootStatistics;
extern CWWTPRadiosInfo gRadiosInfo;
extern CWSecurityContext gWTPSecurityContext;
extern CWSecuritySession gWTPSession;

extern CWPendingRequestMessage gPendingRequestMsgs[MAX_PENDING_REQUEST_MSGS];

extern CWSafeList gPacketReceiveList;
extern CWSafeList gFrameList;
extern CWThreadCondition gInterfaceWait;
extern CWThreadMutex gInterfaceMutex;

/*__________________________________________________________*/
/*  *******************___PROTOTYPES___*******************  */

/* in WTP.c */
CWBool CWWTPLoadConfiguration();
CWBool CWWTPInitConfiguration();
void CWWTPResetRadioStatistics(WTPRadioStatisticsInfo *radioStatistics);
CWBool CWReceiveMessage(CWProtocolMessage *msgPtr);
CWBool CWWTPSendAcknowledgedPacket(int seqNum,
				   CWList msgElemlist, 
				   CWBool (assembleFunc)(CWProtocolMessage **, int *, int, int, CWList),
				   CWBool (parseFunc)(char*, int, int, void*),
				   CWBool (saveFunc)(void*),
				   void *valuesPtr);
void CWWTPDestroy();

/* in WTPRunState.c */
CWBool CWAssembleWTPDataTansferRequest(CWProtocolMessage **messagesPtr,
				       int *fragmentsNumPtr,
				       int PMTU,
				       int seqNum,
				       CWList msgElemList);

CWBool CWAssembleWTPEventRequest(CWProtocolMessage **messagesPtr,
				 int *fragmentsNumPtr,
				 int PMTU,
				 int seqNum,
				 CWList msgElemList, unsigned short msgElemType, int staCount);

CW_THREAD_RETURN_TYPE CWWTPReceiveControlPacket(void *arg);
CWBool CWWTPCheckForBindingFrame();

/* in WTPProtocol_User.c */
CWBool CWWTPGetACNameWithIndex (CWACNamesWithIndex *ACsInfo);
int CWWTPGetStatisticsTimer ();
void CWWTPGetIPv6Address(struct sockaddr_in6* myAddr);
CWBool CWGetWTPRadiosAdminState(CWRadiosAdminInfo *valPtr);
CWBool CWGetDecryptErrorReport(int radioID, CWDecryptErrorReportInfo *valPtr);

/* in WTPRetransmission.c */
int CWSendPendingRequestMessage(CWPendingRequestMessage *pendingRequestMsgs,
				CWProtocolMessage *messages,
				int fragmentsNum);

int CWFindPendingRequestMsgsBox(CWPendingRequestMessage *pendingRequestMsgs,
				const int length,
				const int msgType,
				const int seqNum);

void CWResetPendingMsgBox(CWPendingRequestMessage *pendingRequestMsgs);
CWBool CWUpdatePendingMsgBox(CWPendingRequestMessage *pendingRequestMsgs,
			     unsigned char msgType,
			     int seqNum,
			     int timer_sec,
			     CWTimerArg timer_arg,
			     void (*timer_hdl)(CWTimerArg),
			     int retransmission,
			     CWProtocolMessage *msgElems,
			     int fragmentsNum);

#ifndef BCM
//in WTPDriverInteraction.c
int set_cwmin(int sock, struct iwreq wrq, int acclass, int sta, int value);
int get_cwmin(int sock, struct iwreq* wrq, int acclass, int sta);
int set_cwmax(int sock, struct iwreq wrq, int acclass, int sta, int value);
int get_cwmax(int sock, struct iwreq* wrq, int acclass, int sta);
int set_aifs(int sock, struct iwreq wrq, int acclass, int sta, int value);
int get_aifs(int sock, struct iwreq* wrq, int acclass, int sta);

#else

//in WTPBcmDriverInteraction.c
int set_wme_cwmin(int acclass,int value);
int set_wme_cwmax(int acclass,int value);
int set_wme_aifsn(int acclass,int value);
#endif

/* in WTPDiscoveryState.c */
CWStateTransition CWWTPEnterDiscovery();
void CWWTPPickACInterface();

CWStateTransition CWWTPEnterSulking();
CWStateTransition CWWTPEnterJoin();
CWStateTransition CWWTPEnterConfigure();
CWStateTransition CWWTPEnterDataCheck();
CWStateTransition CWWTPEnterRun();

CWBool CWStartHeartbeatTimer();
CWBool CWStopHeartbeatTimer();
CWBool CWStartNeighborDeadTimer();
CWBool CWStopNeighborDeadTimer();
CWBool CWResetTimers();
CWBool CWStopTimers();
CWBool CWStopWTPEventTimer();
CWBool CWResetWTPEventTimer();


void CWWTPHeartBeatTimerExpiredHandler(void *arg); 
void CWWTPRetransmitTimerExpiredHandler(CWTimerArg arg);

CWBool shareMemInit();
void setTrafficLimitFlag();


extern CWBool WTPExitOnUpdateCommit;

#endif
