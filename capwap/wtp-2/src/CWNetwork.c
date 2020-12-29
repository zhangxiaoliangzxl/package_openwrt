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

 
#include "CWCommon.h"
#include "WTPProtocol.h"

#include "DTTWltp.h"

#include <net/if_arp.h>


#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

CWNetworkLev3Service gNetworkPreferredFamily = CW_IPv4;
pthread_mutex_t mutex_WTPSock = PTHREAD_MUTEX_INITIALIZER;
static unsigned short gSockPort = 0;
/*< network的restart会导致sock断开，需要重新初始化*/
/*< 控制隧道sock重新初始化标志位*/
//static int gReInitFlag = -1;
//extern CWSocket gWTPSocket;
//extern CWACInfoValues *gACInfoPtr;

/*
 * Assume address is valid
 */
__inline__ int CWNetworkGetAddressSize(CWNetworkLev4Address *addrPtr) {

	return sizeof(CWNetworkLev4Address);
#if 0
	switch ( ((struct sockaddr*)(addrPtr))->sa_family ) {
		
	#ifdef	IPV6
		/* IPv6 is defined in Stevens' library */
		case AF_INET6:
			return sizeof(struct sockaddr_in6);
			break;
	#endif
		case AF_INET:
		default:
			return sizeof(struct sockaddr_in);
	}
#endif
}

/* 
 * Send buf on an unconnected UDP socket. Unsafe means that we don't use DTLS.
 */
CWBool CWNetworkSendUnsafeUnconnected(CWSocket sock, 
				      CWNetworkLev4Address *addrPtr,
				      const char *buf,
				      int len) {

	if(buf == NULL || addrPtr == NULL) 
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	while(sendto(sock, buf, (size_t)len, 0, (struct sockaddr*)addrPtr, (socklen_t)CWNetworkGetAddressSize(addrPtr)) < 0) {

		if(errno == EINTR) continue;
		CWDTTLog("failed to send data in <%s> line:%d :  %s\n", __func__,__LINE__, strerror(errno));
		CWNetworkRaiseSystemError(CW_ERROR_SENDING);
//		CWNetworkReInitSocketClientDataChannel(&sock);
	}
	
	return CW_TRUE;
}

/*
 * Send buf on a "connected" UDP socket. Unsafe means that we don't use DTLS.
 */
CWBool CWNetworkSendUnsafeConnected(CWSocket sock, const char *buf, int len) {

	if(buf == NULL) 
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	pthread_mutex_lock(&mutex_WTPSock);
	while(send(sock, buf, len, 0) < 0) {
	
		if(errno == EINTR) continue;
#if 0
		if(1 == gReInitFlag){
			sock = gWTPSocket;
			gReInitFlag = 0;
			continue;
		}
		close(gWTPSocket);
		gWTPSocket = -1;
 		CWNetworkInitSocketClient(&gWTPSocket, &(gACInfoPtr->preferredAddress));
		sock = gWTPSocket;
		gReInitFlag = 1;
		continue;
#endif
		pthread_mutex_unlock(&mutex_WTPSock);
		CWNetworkRaiseSystemError(CW_ERROR_SENDING);
	}
	pthread_mutex_unlock(&mutex_WTPSock);
	return CW_TRUE;
}

/* 
 * Receive a datagram on an connected UDP socket (blocking).
 * Unsafe means that we don't use DTLS.
 */
CWBool CWNetworkReceiveUnsafeConnected(CWSocket sock, char *buf, int len, int *readBytesPtr) {
	
	if(buf == NULL) 
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	pthread_mutex_lock(&mutex_WTPSock);
	while((*readBytesPtr = recv(sock, buf, len, 0)) < 0) {

		if(errno == EINTR) continue;
		pthread_mutex_unlock(&mutex_WTPSock);
		CWNetworkRaiseSystemError(CW_ERROR_RECEIVING);
	}
	pthread_mutex_unlock(&mutex_WTPSock);
	return CW_TRUE;
}

/*
 * Receive a datagram on an unconnected UDP socket (blocking).
 * Unsafe means that we don't use DTLS.
 */
CWBool CWNetworkReceiveUnsafe(CWSocket sock,
			      char *buf,
			      int len,
			      int flags,
			      CWNetworkLev4Address *addrPtr,
			      int *readBytesPtr) {

	socklen_t addrLen = sizeof(CWNetworkLev4Address);
	
	if(buf == NULL || addrPtr == NULL || readBytesPtr == NULL) 
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	pthread_mutex_lock(&mutex_WTPSock);
	while((*readBytesPtr = recvfrom(sock, buf, len, flags, (struct sockaddr*)addrPtr, &addrLen)) < 0) {
		CWDTTLog("Network recv pkg err: %s", strerror(errno));
		if(errno == EINTR) continue;
		pthread_mutex_unlock(&mutex_WTPSock);
		CWNetworkRaiseSystemError(CW_ERROR_RECEIVING);
	}
	pthread_mutex_unlock(&mutex_WTPSock);
	return CW_TRUE;
}

/*
 * Init network for client.
 */
CWBool CWNetworkInitSocketClient(CWSocket *sockPtr, CWNetworkLev4Address *addrPtr)
{	
	int yes = 1;
	struct ifreq interface;
	char *inf = "br-lan";

	struct sockaddr_in sockaddr;
	socklen_t addrlen = sizeof(sockaddr);
	
	/* NULL addrPtr means that we don't want to connect to a 
	 * specific address
	 */
	if(sockPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if(((*sockPtr)=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		CWNetworkRaiseSystemError(CW_ERROR_CREATING);
	}
	int opt = 1;

	/*< 设置可重用，防止出现Address already in use*/
	setsockopt(*sockPtr,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));

	memset(&sockaddr, 0, addrlen);
	sockaddr.sin_family = AF_INET;
	/*< */
	if(gSockPort){
		sockaddr.sin_port = htons(gSockPort);
	}
	if(bind(*sockPtr, (struct sockaddr *)&sockaddr, addrlen) < 0) {
		close(*sockPtr);
		CWDTTLog("failed to bind Client socket in <%s> line:%d :  %s\n", __func__,__LINE__, strerror(errno));
		return CW_FALSE;
	}
	/*< 初始化由系统分配端口，随后一直使用此端口*/
	if(!gSockPort){
		getsockname(*sockPtr, (struct sockaddr *)&sockaddr, &addrlen);
		gSockPort = ntohs(sockaddr.sin_port);
	}
	if(addrPtr != NULL) {
		if(connect((*sockPtr), ((struct sockaddr*)addrPtr), CWNetworkGetAddressSize(addrPtr)) < 0) {

			CWNetworkRaiseSystemError(CW_ERROR_CREATING);
		}
	}
	/* allow sending broadcast packets */
	setsockopt(*sockPtr, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));
	/*< 设置绑定网卡*/
	strncpy(interface.ifr_name, inf, IFNAMSIZ);
	setsockopt(*sockPtr, SOL_SOCKET, SO_BINDTODEVICE,(char *)&interface, sizeof(interface));

	return CW_TRUE;
}

/*
 * Wrapper for select
 */
CWBool CWNetworkTimedPollRead(CWSocket sock, struct timeval *timeout) {
	int r;
	
	fd_set fset;
	
	if(timeout == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	FD_ZERO(&fset);
	FD_SET(sock, &fset);

	if((r = select(sock+1, &fset, NULL, NULL, timeout)) == 0) {

		CWLog("Select Time Expired");
		return CWErrorRaise(CW_ERROR_TIME_EXPIRED, NULL);
	} else 
		if (r < 0) {
		
			CWLog("Select Error");
			
			if(errno == EINTR){
				
				CWLog("Select Interrupted by signal");
				return CWErrorRaise(CW_ERROR_INTERRUPTED, NULL);
			}

			CWNetworkRaiseSystemError(CW_ERROR_GENERAL);
		}

	return CW_TRUE;
}

/*
 * Init data channel network for client
 */
CWBool CWNetworkInitSocketClientDataChannel(CWSocket *sockPtr, CWNetworkLev4Address *addrPtr) {
	
	int yes = 1;
	struct addrinfo hints, *res;
	char myport[8];
	CWNetworkLev4Address addrPtrDataChannel;
	struct sockaddr_in sockaddr;
	socklen_t addrlen = sizeof(sockaddr);
	
	struct ifreq interface;
	char *inf = "br-lan";
	
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;  // use IPv4 or IPv6, whichever   AF_UNSPEC
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; 
	sprintf(myport,"%d",7070);
	getaddrinfo(NULL, myport, &hints, &res);

	/* NULL addrPtr means that we don't want to connect to a 
	 * specific address
	 */
	if(sockPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	if(((*sockPtr)=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		CWNetworkRaiseSystemError(CW_ERROR_CREATING);
	}

	setsockopt(*sockPtr, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

	memset(&sockaddr, 0, addrlen);
	sockaddr.sin_family = AF_INET;
	/*< 不绑定端口，由系统分配*/
	sockaddr.sin_port = htons(7070);

	if(bind(*sockPtr, (struct sockaddr *)&sockaddr, addrlen) < 0) {

		close(*sockPtr);
		CWDebugLog("failed to bind Client socket in <%s> line:%d.\n", __func__,__LINE__);
		return CW_FALSE;
	}
	
//	CWLog("Binding Client socket with UDP data port: 6969\n");
	
	strncpy(interface.ifr_name, inf, IFNAMSIZ);
	setsockopt(*sockPtr, SOL_SOCKET, SO_BINDTODEVICE,(char *)&interface, sizeof(interface));
	
	if(addrPtr != NULL) {
		CW_COPY_NET_ADDR_PTR(&addrPtrDataChannel,addrPtr);
		sock_set_port_cw((struct sockaddr*)&addrPtrDataChannel, htons(WLTP_DATA_PORT_AC));
		CWUseSockNtop((struct sockaddr*)&addrPtrDataChannel, CWDebugLog(str););

		if(connect((*sockPtr), (struct sockaddr*)&addrPtrDataChannel, CWNetworkGetAddressSize(&addrPtrDataChannel)) < 0) {

			CWNetworkRaiseSystemError(CW_ERROR_CREATING);
		}
	}
	
	return CW_TRUE;
}


/*
 * Given an host int the form of C string (e.g. "192.168.1.2" or "localhost"),
 * returns the address.
 */
CWBool CWNetworkGetAddressForHost(char *host, CWNetworkLev4Address *addrPtr) {

	struct addrinfo hints, *res, *ressave;
	char serviceName[5];
	CWSocket sock;
	
	if(host == NULL || addrPtr == NULL)
		return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CW_ZERO_MEMORY(&hints, sizeof(struct addrinfo));
	
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	
	/* endianness will be handled by getaddrinfo */
	snprintf(serviceName, 5, "%d", CW_CONTROL_PORT);
	
	if (getaddrinfo(host, serviceName, &hints, &res) !=0 ) {

		return CWErrorRaise(CW_ERROR_GENERAL, "Can't resolve hostname");
	}
	
	ressave = res;
	
	do {
		if((sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
			/* try next address */
			continue;
		}
		/* success */
		break;
	} while ( (res = res->ai_next) != NULL);
	
	close(sock);
	
	if(res == NULL) { 
		/* error on last iteration */
		CWNetworkRaiseSystemError(CW_ERROR_CREATING);
	}
	
	CW_COPY_NET_ADDR_PTR(addrPtr, (res->ai_addr));
	freeaddrinfo(ressave);
	
	return CW_TRUE;
}

/*< 获取对端AC的mac地址*/
CWBool CWNetworkGetMacForHost(int sockfd, struct sockaddr_in *addr, char *eth, char *buf)  
{  
    struct arpreq arpreq;
	
    memset( &arpreq, 0, sizeof( struct arpreq ));  
	
//	printf("peer ip is %s#\n", inet_ntoa(addr->sin_addr));
    memcpy( &arpreq.arp_pa, addr, sizeof( struct sockaddr_in ));  
    strcpy(arpreq.arp_dev, eth);  
    arpreq.arp_pa.sa_family = AF_INET;  
    arpreq.arp_ha.sa_family = AF_UNSPEC;  
    if(ioctl( sockfd, SIOCGARP, &arpreq ) < 0 )
        return CW_FALSE; 
    else  
    {  
        unsigned char* ptr = (unsigned char *)arpreq.arp_ha.sa_data;  
		memcpy(buf, ptr, 6);
//		printf("get ac mac: ##%02x:%02x:%02x:%02x:%02x:%02x#\n",ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
    }  
		
    return CW_TRUE;  
}   

/*< 获取设备自身得IP地址*/
CWBool CWNetworkGetWTPIP(char *strValue)
{
	int sock;
    struct sockaddr_in sin;
    struct ifreq ifr;
	char str[32] = {0};
	int buf[32] = {0};

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1)
    {
        CWDTTLog("getWTPIP: socket :%s", strerror(errno));
        return CW_FALSE;
    }

    strncpy(ifr.ifr_name, "br-lan", IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
        CWDTTLog("getWTPIP: ioctl :%s", strerror(errno));
		close(sock);
		sock = -1;
        return CW_FALSE;
    }

    memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
	
    sprintf(str, "%s", inet_ntoa(sin.sin_addr));

	sscanf(str, "%d.%d.%d.%d", buf, buf+1,buf+2,buf+3);
	close(sock);
	sock = -1;

	strValue[0] = buf[0];strValue[1] = buf[1];strValue[2] = buf[2];strValue[3] = buf[3];

    return CW_TRUE;
}


