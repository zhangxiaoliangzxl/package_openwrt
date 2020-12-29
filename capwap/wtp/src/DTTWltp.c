#include "CWAC.h"
#include "CWStevens.h"

#include "CWWTP.h"
#include "DTTWltp.h"
#include "DTTConfigUpdate.h"

uint32_t wltp_pkt_seq = 0;

CWSocket 		gWTPWltpSocket = -1;
struct sockaddr_un wtp_lsock_sndpkt_to_ap_addr;
struct sockaddr_un wtp_lsock_sndpkt_to_ac_addr;

uint32_t get_wltp_id(void)
{
	uint32_t index = 0;
			
	index = wltp_pkt_seq++;
			
	return index;
}

uint32_t get_wltp_id_for_fragment(void)
{
	uint32_t index = 0;
			
	index = wltp_pkt_seq++;
	/*分配给第二个分片*/
	wltp_pkt_seq++;
	
	return index;
}


CWTimerID wltpKeepAliveTimer = 0;
CWTimerID wltpReceivePktTimer = 0;
int gCWWltpKeepAlive = CW_WLTP_KEEPALIVE_DEFAULT;

CWNetworkLev4Address preferredAddress_wltp;

/*
*	Description: add the head(16 bytes) of wltp protocol for WS
*/
int LoadWltpHeader(void *data, uint32_t seq, uint16_t length, uint16_t fragment)
{

	wltp_header *head = NULL;
		
	if (data == NULL)
	{
		return -1;
	}

	if(WLTP_HEADER_LEN != sizeof(wltp_header))
	{
		return -1;
	}

	head = (wltp_header *)data;
	
	head->protocol = htons(WLTP_PROTOCOL);
	head->type = htons(WLTP_TYPE);
	head->seq = htonl(seq);
	head->length = htons(length);
	head->fragment = htons(fragment);
	head->rssi = htonl(0);
	head->vapIndex = 0;
	head->pad1 = 0;
	/*< 协议里面使用的是第一个模板ID*/
	head->configid = htons(gTemplateID[0]);
	head->pad2 = htonl(0);

	return 0;
}

void WltpSendPkt(char *pkt_data, uint16_t pkt_leng)
{
	char wltp_1pkt_data[1800] = {0};

	if (pkt_leng <= MAX_LENGTH_FOR_MAC_WLTP)
	{
		uint32_t seq;

		seq = get_wltp_id();
		/* wltp_header_assembly */
		LoadWltpHeader(wltp_1pkt_data, seq, pkt_leng, 0);
		memcpy(&wltp_1pkt_data[WLTP_HEADER_LEN], pkt_data, pkt_leng);

//		send(gWTPDataSocket, wltp_1pkt_data, pkt_leng + WLTP_HEADER_LEN, 0);
#if 1
		if(!CWErr(CWNetworkSendUnsafeUnconnected(gWTPDataSocket,
							 &preferredAddress_wltp,
							 wltp_1pkt_data, 
							 pkt_leng + WLTP_HEADER_LEN))) {
		
			CWLog("Critical Error Sending Wltp Packet!!!\n");
		}
#endif
	}
	else
	{
		uint32_t first_seq;
		uint32_t second_seq;

		/*为了避免序列号不连续，一次申请两个序列号*/	
		first_seq = get_wltp_id_for_fragment();
		second_seq = first_seq + 1;

		/*按协议规定长度域应该指当前报文的数据长度*/
		/*但这里需要填充确是未分片前报文的数据长度*/
		LoadWltpHeader(wltp_1pkt_data, first_seq, pkt_leng, FIRST_FRAGMENT_FLAG);
		memcpy(&wltp_1pkt_data[WLTP_HEADER_LEN], pkt_data, MAX_FRAGMENT_LENGTH);
		if(!CWErr(CWNetworkSendUnsafeUnconnected(gWTPDataSocket,
							 &preferredAddress_wltp,
							 wltp_1pkt_data, 
							 MAX_FRAGMENT_LENGTH + WLTP_HEADER_LEN))) {
		
			CWLog("Critical Error Sending Wltp Packet!!!\n");
		}
#if 0
		printf("-------------------1111-----------------\n ");
		int i =0; 
		for(i = 0;i < 16;i++)
						{
							printf("%02x ", *((unsigned char *)(&wltp_1pkt_data[WLTP_HEADER_LEN+i])));
						
							if(!((i+1) % 16) && i != 0)
								printf("\n");
							if(!((i+1) % 8) && (((i+1) / 8)%2) && i != 0)
								printf("	");
						}
		for(i = 0;i < 16;i++)
						{
							printf("%02x ", *((unsigned char *)(&wltp_1pkt_data[WLTP_HEADER_LEN+MAX_FRAGMENT_LENGTH-16+i])));
						
							if(!((i+1) % 16) && i != 0)
								printf("\n");
							if(!((i+1) % 8) && (((i+1) / 8)%2) && i != 0)
								printf("	");
						}
#endif
		LoadWltpHeader(wltp_1pkt_data, second_seq, pkt_leng - MAX_FRAGMENT_LENGTH, SECOND_FRAGMENT_FLAG);
		memcpy(&wltp_1pkt_data[WLTP_HEADER_LEN], &pkt_data[MAX_FRAGMENT_LENGTH], pkt_leng - MAX_FRAGMENT_LENGTH);
		if(!CWErr(CWNetworkSendUnsafeUnconnected(gWTPDataSocket,
							 &preferredAddress_wltp,
							 wltp_1pkt_data, 
							 pkt_leng - MAX_FRAGMENT_LENGTH + WLTP_HEADER_LEN))) {
		
			CWLog("Critical Error Sending Wltp Packet!!!\n");
		}
#if 0
		printf("-------------------2222-----------------\n ");
		for(i = 0;i < 16;i++)
						{
							printf("%02x ", *((unsigned char *)(&wltp_1pkt_data[WLTP_HEADER_LEN+i])));
						
							if(!((i+1) % 16) && i != 0)
								printf("\n");
							if(!((i+1) % 8) && (((i+1) / 8)%2) && i != 0)
								printf("	");
						}
		for(i = 0;i < 16;i++)
						{
							printf("%02x ", *((unsigned char *)(&wltp_1pkt_data[WLTP_HEADER_LEN+pkt_leng-MAX_FRAGMENT_LENGTH-16+i])));
						
							if(!((i+1) % 16) && i != 0)
								printf("\n");
							if(!((i+1) % 8) && (((i+1) / 8)%2) && i != 0)
								printf("	");
						}
#endif
	}
}

void CWWLTPKeepAliveExpired(CWTimerArg arg) {
	
	int index = 0;
#ifndef DEBUG_RCV_WLTP_PKT
	char send_data[180] = {0};
#else /* DEBUG_RCV_WLTP_PKT */
	char send_data[1800] = {0};
#endif /* DEBUG_RCV_WLTP_PKT */
	unsigned int vapVlan[MAX_VAP*2] = {0};
	int i = 0;

	timer_rem(wltpKeepAliveTimer, NULL); 	
	CWLog("WTP Wltp KeepAlive Timer Expired!\n");

	memcpy(&send_data[index], "INFO", 4);
	index += 4;
	send_data[index++] = 0x1;
	send_data[index++] = 0xa1;
	/*< gWtpPublicInfo.cardnum为单双卡*/
	*((short *)&send_data[index]) = htons(14+16*gWtpPublicInfo.cardnum);
	index += 2;

	//ELV -- VlanID
	*((short *)&send_data[index]) = htons(0x0a01);
	index += 2;
	*((short *)&send_data[index]) = htons(16*gWtpPublicInfo.cardnum);
	index += 2;
	getAllVapVlanID(vapVlan);

	for(i = 0;i < MAX_VAP*gWtpPublicInfo.cardnum; i++){
		*((short *)&send_data[index]) = htons((unsigned short)vapVlan[i]); //VLAN
		index += 2;
//		if(i == 7 || i == 15)
//			index += 16;
	}

	//ELV -- MAC
	*((short *)&send_data[index]) = htons(0x0a02);
	index += 2;
	*((short *)&send_data[index]) = htons(6);//
	index += 2;
	memcpy(&send_data[index],  gWtpPublicInfo.ethMac, 6);
	index += 6;

#ifndef DEBUG_RCV_WLTP_PKT
	WltpSendPkt(send_data, index);
#else /* DEBUG_RCV_WLTP_PKT */
	WltpSendPkt(send_data, index);

//	if(sendto(gWTPWltpSocket, send_data, 86, 0, (struct sockaddr *)&wtp_lsock_sndpkt_to_ac_addr, sizeof(struct sockaddr_un)) < 0)
//		CWDTTLog("failed to send wltp KeepAlive in <%s> line:%d :  %s\n", __func__,__LINE__, strerror(errno));
#endif /* DEBUG_RCV_WLTP_PKT */

	if ((wltpKeepAliveTimer = timer_add(gCWWltpKeepAlive, 0, CWWLTPKeepAliveExpired, NULL)) == -1) {
		CWLog("Critical Error Resetting Wltp Keep-alive Send-Timer");
		return;
	}
	CWLog("WTP Wltp KeepAlive Timer Reseted!\n");
}

void WltpKeepAlive_settimer(CWNetworkLev4Address preferredAddress)
{
	memset(&preferredAddress_wltp, 0, sizeof(CWNetworkLev4Address));
	sock_cpy_addr_port((struct sockaddr *)&preferredAddress_wltp, (struct sockaddr *)&preferredAddress);
	sock_set_port_cw((struct sockaddr *)&preferredAddress_wltp, htons(WLTP_DATA_PORT_AC));
#ifdef DEBUG_RCV_WLTP_PKT_rev
			struct sockaddr_in	*sin;
			uint32_t the_IP = 0xC0A86F64;//192.168.111.23;

			CWNetworkLev4Address preferredAddress_tst;
			memcpy(&preferredAddress_tst, &preferredAddress, sizeof(preferredAddress)); 
			
			sin = (struct sockaddr_in *) &preferredAddress_tst;
			memcpy(&sin->sin_addr, &the_IP, sizeof(the_IP)); 
			sin->sin_port = WLTP_DATA_PORT_AP;
			printf("1---addr:port(%x,%d)\n", sin->sin_addr, sin->sin_port);

			
			CWNetworkInitSocketClientDataChannel(&tst_skt, &preferredAddress_tst);

			sin = (struct sockaddr_in *) &preferredAddress_wltp;
			memcpy(&sin->sin_addr, &the_IP, sizeof(the_IP)); 
			sin->sin_port = WLTP_DATA_PORT_AC;
			printf("2---addr:port(%x,%d)\n", sin->sin_addr, sin->sin_port);
#endif /* DEBUG_RCV_WLTP_PKT */

	if ((wltpKeepAliveTimer = timer_add(gCWWltpKeepAlive, 0, CWWLTPKeepAliveExpired, NULL)) == -1) {
		CWLog("Critical Error Setting Wltp Keep-alive Send-Timer");
		return;
	}
}

void WltpKeepAlive_stoptimer(void){
	timer_rem(wltpKeepAliveTimer, NULL);
}

void WltpLocalSocket_init()
{
	char cmd[180] = {0};
	struct sockaddr_un local;

	sprintf(cmd, "rm -f %s", WLTP_TRANSFER_PKT_TO_AC);
	system(cmd);
	CWNetworkCloseSocket(gWTPWltpSocket);

	gWTPWltpSocket = socket(AF_UNIX, SOCK_DGRAM, 0);
	if(0 > gWTPWltpSocket) {
		CWLog("Critical Error Init Wltp Local Socket");
		return;
	}

	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, WLTP_TRANSFER_PKT_TO_AC);
	if (bind(gWTPWltpSocket, (struct sockaddr *)&local, strlen(local.sun_path) + sizeof(local.sun_family)) == -1) {
		CWLog("Critical Error Bind Wltp Local Socket");
		
		CWNetworkCloseSocket(gWTPWltpSocket);
		gWTPWltpSocket = -1;
		return;
	}

	wtp_lsock_sndpkt_to_ac_addr.sun_family = AF_UNIX;
	wtp_lsock_sndpkt_to_ap_addr.sun_family = AF_UNIX;
	strcpy(wtp_lsock_sndpkt_to_ac_addr.sun_path, WLTP_TRANSFER_PKT_TO_AC);
	strcpy(wtp_lsock_sndpkt_to_ap_addr.sun_path, WLTP_TRANSFER_PKT_TO_AP);
}

CW_THREAD_RETURN_TYPE CWWltpSendPkt(void *arg)
{
	fd_set fds; 
	uint32_t ret;
	int readBytes = 0;
	struct timeval tv_out;
	char buf[CW_BUFFER_SIZE];

	CWThreadSetSignals(SIG_BLOCK, 1, SIGALRM);
			
	CW_REPEAT_FOREVER 	/* Send data Loop */
	{
		if(0 > gWTPWltpSocket)
		{
			sleep(1);
			continue;
		}

		FD_ZERO(&fds);
		FD_SET(gWTPWltpSocket, &fds);
		
		//等待300毫秒
		tv_out.tv_sec = 1;
		tv_out.tv_usec = 300;
		ret = select(gWTPWltpSocket+1, &fds, NULL, NULL, &tv_out);
		
		if(ret > 0)
		{
			if(FD_ISSET(gWTPWltpSocket, &fds))
			{
				readBytes = recvfrom(gWTPWltpSocket, buf, CW_BUFFER_SIZE - 1, 0, NULL, NULL);
				CWDebugLog("-------------WTP LocalSocket Receive %d bytes.\n", readBytes);

				if(1 < readBytes)
				{//数据包
					WltpSendPkt(buf, readBytes);
				}
				else
				{//1bye 握手包
					buf[0] = WLTP_CONNECT_R;
					sendto(gWTPWltpSocket, buf, readBytes, 0, (struct sockaddr *)&wtp_lsock_sndpkt_to_ap_addr, sizeof(struct sockaddr_un));
				}
			}
		}
	}
}

wltp_fragment_buffer_t wltp_fragment_buffer[WLTP_FRAGMENT_BUFFER_NUM];

CW_THREAD_RETURN_TYPE CWWltpReceivePkt(void *arg)
{
	CWNetworkLev4Address addr;
	int readBytes, writeBytes;
	char buf[CW_BUFFER_SIZE], *buf_w;
	
	int wltp_frgbuf_seq = 0;
	int wltp_frgbuf_seq_1st = 0;
	int wltp_frgbuf_seq_2nd = 0;
	int wltp_frgbuf_cpy_len = 0;
	
	wltp_header *wltp_head = NULL;
	wltp_header *wltp_head_1st = NULL;
	wltp_header *wltp_head_2nd = NULL;

	
	wltp_fragment_buffer_t *wltp_frgbuf_1st;
	wltp_fragment_buffer_t *wltp_frgbuf_2nd;

	CWThreadSetSignals(SIG_BLOCK, 1, SIGALRM);
	memset(wltp_fragment_buffer, 0, sizeof(wltp_fragment_buffer));
			
	CW_REPEAT_FOREVER 	/* Receive data Loop */
	{				
		if(0 > gWTPDataSocket)
		{
			sleep(1);
			continue;
		}

		memset(buf, 0, CW_BUFFER_SIZE);
		
		/* receive the datagram */
		if(!CWErr(CWNetworkReceiveUnsafe(gWTPDataSocket,
						 buf,
						 CW_BUFFER_SIZE-1,
						 0,
						 &addr,
						 &readBytes))) {
			continue;
		}

		wltp_head = (wltp_header *)buf;
		if((WLTP_TYPE == wltp_head->type) && 
			(WLTP_PROTOCOL == wltp_head->protocol))
		{
//			printf("WTP Wltp rcv pkt:seq(%d-hton-%d) leng(%d)!\n", wltp_head->seq, htonl(wltp_head->seq), readBytes);

			switch(wltp_head->fragment)
			{
			case FIRST_FRAGMENT_FLAG:
			case SECOND_FRAGMENT_FLAG:
				wltp_frgbuf_seq = wltp_head->seq % WLTP_FRAGMENT_BUFFER_NUM;
				wltp_frgbuf_cpy_len = (readBytes > WLTP_PKT_BUFFER_LENGTH)?WLTP_PKT_BUFFER_LENGTH:readBytes;

				wltp_fragment_buffer[wltp_frgbuf_seq].length = readBytes;
				wltp_fragment_buffer[wltp_frgbuf_seq].buno = RES_BUSY_16 + wltp_frgbuf_seq;
				memcpy(wltp_fragment_buffer[wltp_frgbuf_seq].wltp_pkt_data, buf, wltp_frgbuf_cpy_len);
				break;
			default:
				break;
			}
			
			switch(wltp_head->fragment)
			{
			case FIRST_FRAGMENT_FLAG:
				wltp_frgbuf_seq_1st = wltp_head->seq % WLTP_FRAGMENT_BUFFER_NUM;
				wltp_frgbuf_seq_2nd = (wltp_head->seq + 1) % WLTP_FRAGMENT_BUFFER_NUM;
				break;
			case SECOND_FRAGMENT_FLAG:
				wltp_frgbuf_seq_2nd = wltp_head->seq % WLTP_FRAGMENT_BUFFER_NUM;
				wltp_frgbuf_seq_1st = (wltp_head->seq - 1) % WLTP_FRAGMENT_BUFFER_NUM;
				break;
			default:
				break;
			}
			
			switch(wltp_head->fragment)
			{
			case FIRST_FRAGMENT_FLAG:
			case SECOND_FRAGMENT_FLAG:
				wltp_frgbuf_1st = &wltp_fragment_buffer[wltp_frgbuf_seq_1st];
				wltp_frgbuf_2nd = &wltp_fragment_buffer[wltp_frgbuf_seq_2nd];

				wltp_head_1st = (wltp_header *)wltp_frgbuf_1st->wltp_pkt_data;
				wltp_head_2nd = (wltp_header *)wltp_frgbuf_2nd->wltp_pkt_data;

				if(0x0 == wltp_frgbuf_1st->buno)
					break;
				if(0x0 == wltp_frgbuf_2nd->buno)
					break;

				if(wltp_head_2nd->seq != (wltp_head_1st->seq + 1))
					break;

				if(wltp_head_1st->fragment != FIRST_FRAGMENT_FLAG)
					break;
				if(wltp_head_2nd->fragment != SECOND_FRAGMENT_FLAG)
					break;

				if(wltp_head_2nd->length != (wltp_frgbuf_2nd->length - sizeof(wltp_header)))
					break;
				if((wltp_head_1st->length - wltp_head_2nd->length) != (wltp_frgbuf_1st->length - sizeof(wltp_header)))
					break;

				if((wltp_frgbuf_1st->length + wltp_frgbuf_2nd->length - sizeof(wltp_header)) > WLTP_PKT_BUFFER_LENGTH)
				{
					memset(wltp_frgbuf_1st, 0, sizeof(wltp_fragment_buffer_t));
					memset(wltp_frgbuf_2nd, 0, sizeof(wltp_fragment_buffer_t));
					break;
				}
				else
				{
					wltp_frgbuf_1st->length += wltp_head_2nd->length;
					memcpy(&wltp_frgbuf_1st->wltp_pkt_data[wltp_frgbuf_1st->length], 
						   &wltp_frgbuf_2nd->wltp_pkt_data[sizeof(wltp_header)],
						   wltp_head_2nd->length);

					writeBytes = wltp_head_1st->length;
					buf_w = (char *)(wltp_frgbuf_1st->wltp_pkt_data) + sizeof(wltp_header);
					sendto(gWTPWltpSocket, buf_w, writeBytes, 0, (struct sockaddr *)&wtp_lsock_sndpkt_to_ap_addr, sizeof(struct sockaddr_un));
					
					memset(wltp_frgbuf_1st, 0, sizeof(wltp_fragment_buffer_t));
					memset(wltp_frgbuf_2nd, 0, sizeof(wltp_fragment_buffer_t));
					break;
				}

				break;
			default:
				break;
			}

		}
		else
		{
			continue;
		}
	}
}

int CWWltpReceivePkt_for_Kmod(char *buf, int buf_leng, int readBytes)
{
	int writeBytes;
	
	int wltp_frgbuf_seq;
	int wltp_frgbuf_seq_1st;
	int wltp_frgbuf_seq_2nd;
	int wltp_frgbuf_cpy_len;
	
	wltp_header *wltp_head = NULL;
	wltp_header *wltp_head_1st = NULL;
	wltp_header *wltp_head_2nd = NULL;

	
	wltp_fragment_buffer_t *wltp_frgbuf_1st;
	wltp_fragment_buffer_t *wltp_frgbuf_2nd;

	wltp_head = (wltp_header *)buf;
	if((WLTP_TYPE == wltp_head->type) && 
		(WLTP_PROTOCOL == wltp_head->protocol))
	{
		switch(wltp_head->fragment)
		{
		case FIRST_FRAGMENT_FLAG:
		case SECOND_FRAGMENT_FLAG:
			wltp_frgbuf_seq = wltp_head->seq % WLTP_FRAGMENT_BUFFER_NUM;
			wltp_frgbuf_cpy_len = (readBytes > WLTP_PKT_BUFFER_LENGTH)?WLTP_PKT_BUFFER_LENGTH:readBytes;

			wltp_fragment_buffer[wltp_frgbuf_seq].length = readBytes;
			wltp_fragment_buffer[wltp_frgbuf_seq].buno = RES_BUSY_16 + wltp_frgbuf_seq;
			memcpy(wltp_fragment_buffer[wltp_frgbuf_seq].wltp_pkt_data, buf, wltp_frgbuf_cpy_len);
#if 0
			if(FIRST_FRAGMENT_FLAG == wltp_head->fragment)
				printf("WTP Wltp rcv pkt fm0:seq(%d-hton-%d) leng(%d)!\n", wltp_head->seq, htonl(wltp_head->seq), readBytes);
			else
				printf("WTP Wltp rcv pkt fm1:seq(%d-hton-%d) leng(%d)!\n", wltp_head->seq, htonl(wltp_head->seq), readBytes);
#endif
			break;
		default:
			return 3;//非分片WLTP报文
		}
			
		switch(wltp_head->fragment)
		{
		case FIRST_FRAGMENT_FLAG:
			wltp_frgbuf_seq_1st = wltp_head->seq % WLTP_FRAGMENT_BUFFER_NUM;
			wltp_frgbuf_seq_2nd = (wltp_head->seq + 1) % WLTP_FRAGMENT_BUFFER_NUM;
			break;
		case SECOND_FRAGMENT_FLAG:
			wltp_frgbuf_seq_2nd = wltp_head->seq % WLTP_FRAGMENT_BUFFER_NUM;
			wltp_frgbuf_seq_1st = (wltp_head->seq - 1) % WLTP_FRAGMENT_BUFFER_NUM;
			break;
		default:
			break;
		}
			
		do{
			wltp_frgbuf_1st = &wltp_fragment_buffer[wltp_frgbuf_seq_1st];
			wltp_frgbuf_2nd = &wltp_fragment_buffer[wltp_frgbuf_seq_2nd];

			wltp_head_1st = (wltp_header *)wltp_frgbuf_1st->wltp_pkt_data;
			wltp_head_2nd = (wltp_header *)wltp_frgbuf_2nd->wltp_pkt_data;

			if(0x0 == wltp_frgbuf_1st->buno)
				break;
			if(0x0 == wltp_frgbuf_2nd->buno)
				break;

			if(wltp_head_2nd->seq != (wltp_head_1st->seq + 1))
				break;

			if(wltp_head_1st->fragment != FIRST_FRAGMENT_FLAG)
				break;
			if(wltp_head_2nd->fragment != SECOND_FRAGMENT_FLAG)
				break;

			if(wltp_head_2nd->length != (wltp_frgbuf_2nd->length - sizeof(wltp_header)))
				break;
			if((wltp_head_1st->length - wltp_head_2nd->length) != (wltp_frgbuf_1st->length - sizeof(wltp_header)))
				break;

			if((wltp_frgbuf_1st->length + wltp_frgbuf_2nd->length - sizeof(wltp_header)) > WLTP_PKT_BUFFER_LENGTH)
			{
				memset(wltp_frgbuf_1st, 0, sizeof(wltp_fragment_buffer_t));
				memset(wltp_frgbuf_2nd, 0, sizeof(wltp_fragment_buffer_t));
				break;
			}
			else
			{
				wltp_frgbuf_1st->length += wltp_head_2nd->length;
				memcpy(&wltp_frgbuf_1st->wltp_pkt_data[wltp_frgbuf_1st->length], 
					   &wltp_frgbuf_2nd->wltp_pkt_data[sizeof(wltp_header)],
					   wltp_head_2nd->length);

				writeBytes = wltp_head_1st->length  + sizeof(wltp_header);
				if(buf_leng >= writeBytes)
					memcpy(buf, wltp_frgbuf_1st->wltp_pkt_data, writeBytes);
					
				memset(wltp_frgbuf_1st, 0, sizeof(wltp_fragment_buffer_t));
				memset(wltp_frgbuf_2nd, 0, sizeof(wltp_fragment_buffer_t));
				return 2;//WLTP分片报文的收到第二片，完成组包
			}

			return 1;//WLTP分片报文的收到第一片，等待组包
		}while(1);
	}
	else
	{
		return 0;//非WLTP报文
	}

	return 0;
}

#if 0
{
		u32 ret = CWLAN_OK;
		struct sockaddr_un addr;
		struct sockaddr_un local;
		char buffer[128] = {0};
		fd_set fds; 
		char a;
	
		struct timeval tv_out;
		tv_out.tv_sec = 3;//等待10秒
		tv_out.tv_usec = 0;
		
		
		addr.sun_family = AF_UNIX;
		strcpy(addr.sun_path, WLTP_TRANSFER_PKT_TO_AP);
	
		local.sun_family = AF_UNIX;
		strcpy(local.sun_path, WLTP_TRANSFER_PKT_TO_AC);
		if (bind(gWTPWltpSocket, (struct sockaddr *)&local, strlen(local.sun_path) + sizeof(local.sun_family)) == -1) {
			sleep(1);
			continue;
		}

		while(1)
		{
			FD_ZERO(&fds);
			FD_SET(gWTPWltpSocket,&fds);
			
			buffer[0] = STA_UPDATE_CONNECT;
			sendto(gWTPWltpSocket, buffer, strlen(buffer), 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
			printf("send buffer to hostapd:%s\n", buffer);
	
			ret = select(gWTPWltpSocket+1, &fds, &fds, NULL, &tv_out);
			if(ret = 0)
			{
				continue;
			}
			else if(ret < 0)
			{
				return CWLAN_FAIL;
			}
			else
			{
				if(FD_ISSET(gWTPWltpSocket,&fds))
				{
					memset(buffer, 0, sizeof(buffer));
					recvfrom(gWTPWltpSocket, buffer, sizeof(buffer), 0,NULL, NULL);
					printf("recv buffer from hostapd:%d\n", buffer[0]);
					if(buffer[0] = STA_UPDATE_CONNECT_R)
					{
						break;
					}
				}
			}
		}
}

tun_process_result_t tunnel_disassembly(packet_info_t *packet_info)
{
	uint8_t *data_l2 = packet_info->l2_data;
	uint8_t *data_wltp = NULL;
	uint16_t vlan_id = 0;
	uint16_t src_port = 0;
	uint16_t dest_port = 0;
	ip_hdr *iphdr = NULL;
	udp_hdr *udphdr = NULL;
	uint8_t	isHaveActualMac = TRUE;

	if ((data_l2[0] & UNUNICAST_MASK) == UNUNICAST_MASK)
	{
		return TUN_DO_NOTHING;
	}	
	
	if (packet_info->eth_type != ETH_P_IP)
	{
		return TUN_DO_NOTHING;
	}

	vlan_id = packet_info->vlan_id;	
	iphdr = packet_info->l3_h.iph;
	uint8_t tos = (uint8_t)((iphdr->_v_hl_tos & 0xff)>>2);
	uint8_t cos = 0;
	
	if (IPH_V(iphdr) != IPV4_VERSION) 
	{
		return TUN_DO_NOTHING;
	}	 

	if (IPH_PROTO(iphdr) != IP_PROTO_UDP)
	{
		return TUN_DO_NOTHING;
	}
	
	udphdr = packet_info->l4_h.uh;
	src_port = hton16(udphdr->src);
	dest_port = hton16(udphdr->dest);

	if (dest_port == WLTP_DATA_PORT)
	{
		data_wltp = packet_info->l4_h.l4_data + sizeof(struct udp_hdr); //point to wltp header
			
		if (CheckWltpHeader(data_wltp) == -1)
		{
			se_log_new(SE_TUNNEL_LOG108, __FUNCTION__, __LINE__, 
				"CheckWltpHeader fail!\n");		
			return TUN_PACKET_DROP;
		}
	
		/*丢弃不是发往本AC 的隧道报文*/
		if (packet_is_local(data_l2) != MAX_POW_NUM)
		{
			se_log_new(SE_TUNNEL_LOG102, __FUNCTION__, __LINE__, 
						"DMAC is not to My Ac %02x:%02x:%02x:%02x:%02x:%02x!\n", 
						data_l2[0], data_l2[1], data_l2[2], data_l2[3], data_l2[4], data_l2[5]);			
			return TUN_PACKET_DROP;
		}
		
		//paney,2009.9.28:now we receive a wltp packet,first need to do some learn.
		wltp_header *head = (wltp_header *)data_wltp;
		uint8_t *data_inner = (uint8_t *)udphdr +sizeof(udp_hdr) + WLTP_HEADER_LEN;
		packet_info->ws_tunnel_info.ap_ip = hton32(iphdr->src.addr);
		packet_info->ws_tunnel_info.src_port = src_port;
		
//stony 2011.03.24 学习AP 发出的INFO 报文
		if(data_inner[0] == 0x49 && data_inner[1] == 0x4e 			
			&& data_inner[2] == 0x46 && data_inner[3] == 0x4f)		
		{
			/*为了兼容老版本AP， 需要查看所使用的AP 版本*/
			int32_t info_version = check_info_version(head->length, data_inner);

			if (info_version >= RET_INFO_OLD_STYLE)
			{
				ap_list_info_t ap_list_info;
				memset(&ap_list_info, 0x0, sizeof(ap_list_info_t));

				ap_list_info_t ap_list_info_learn;
				memset(&ap_list_info_learn, 0x0, sizeof(ap_list_info_t));

				memcpy(ap_list_info_learn.ap_mac, &data_l2[MAC_ADDRESS_LEN], MAC_ADDRESS_LEN);
				
				if (info_version == RET_INFO_ELV_STYLE)
				{
					/*对于ELV 格式的INFO 报文获取更多的信息*/
					get_info_message(data_inner, &ap_list_info_learn);
				}
				else
				{
					memcpy((uint8_t *)ap_list_info_learn.ap_mac_actual, (uint8_t *)ap_list_info_learn.ap_mac, MAC_ADDRESS_LEN);
				}
				
				SearchHashForApList(ap_list_info_learn.ap_mac_actual, sizeof(ap_list_info_learn.ap_mac_actual), 
								(uint8_t *)&ap_list_info, sizeof(ap_list_info));

				memcpy(ap_list_info.ap_mac, ap_list_info_learn.ap_mac, MAC_ADDRESS_LEN);
				memcpy(ap_list_info.vlan_id, ap_list_info_learn.vlan_id, sizeof(ap_list_info.vlan_id));
				ap_list_info.is_double_card = ap_list_info_learn.is_double_card;
				memcpy(ap_list_info.ap_mac_actual, ap_list_info_learn.ap_mac_actual, MAC_ADDRESS_LEN);
				
				memcpy(&ap_list_info.ap_ip, &packet_info->ws_tunnel_info.ap_ip, sizeof(IPAddr_t));
				ap_list_info.src_port = src_port;

				if (0 != vlan_id)
				{
					memcpy(&ap_list_info.vlan, &data_l2[12], sizeof(ap_list_info.vlan));
					ap_list_info.vlan = hton32(ap_list_info.vlan);
				}
				
				ap_list_info.ac_ip = hton32(iphdr->dest.addr);
				ap_list_info.phy_port = packet_info->from_port;
				//ap_list_info.template_id = (uint16_t)packet_info->ws_tunnel_info.template_id;
				memcpy(ap_list_info.ac_mac, &data_l2[0], MAC_ADDRESS_LEN);
		
				/*根据INFO 报文更新AP List*/
				UpdateHashForApList((uint8_t *)ap_list_info.ap_mac_actual, sizeof(MacAddr_t), (uint8_t *)&ap_list_info, sizeof(ap_list_info_t));	
				/*由于管理隧道建立在主控板上，业务板无法将AP 信息加入到三层表*/
				/*会导致发往AP 的ARP 请求被转发到station*/
				if (g_bme_config->work_mode == BME_MODE_DISTRIBUTED_OPERATION)
				{
					ip_hash_info_t sta_ip_info;
					memset(&sta_ip_info, 0x0, sizeof(sta_ip_info));
					memcpy(sta_ip_info.mac, &data_l2[MAC_ADDRESS_LEN], MAC_ADDRESS_LEN);
					sta_ip_info.port = PORT_FIRST;
					sta_ip_info.pow_port_id = POW8_PORT_ID;
					sta_ip_info.vlan_id = packet_info->vlan_id;
					
					UpdateHashForIp((uint8_t *)&(ap_list_info.ap_ip), sizeof(IPAddr_t), 
						(uint8_t *)&sta_ip_info, sizeof(sta_ip_info), IP_HASH_CALL_FROM_LEARN_APINFO);
				}

			}
			
			return TUN_PACKET_INFO;
		}		


		/*获取AP 使用的模板*/
		packet_info->ws_tunnel_info.template_id = hton16(head->configid);

		/*获取使用的VAP 序列号*/
		if (head->vapIndex <= 7)
		{
			packet_info->ws_tunnel_info.vap_index = head->vapIndex;
		}
		else
		{
			se_log_new(SE_TUNNEL_LOG104, __FUNCTION__, __LINE__, 
						"Invalid vap index(%d) in wltp head!\n", head->vapIndex);
			se_log(SE_LOG_WARN, "Invalid vap index(%d) in wltp head!\n", head->vapIndex);
			return TUN_PACKET_DROP;
		}

		input_get_vap_parm(packet_info);

		/*判断是否为分片报文，对于分片报文需要特别处理*/
		tun_process_result_t return_flag = assembly_fragment_wltp_packet(packet_info);

		if (return_flag == TUN_PACKET_IN_TABLE || return_flag == TUN_PACKET_REPEAT)
		{
			return return_flag;
		}
		
		MacAddr_t eth_mac;
		uint16_t fragment = hton16(head->fragment);
		memcpy(eth_mac, &data_l2[MAC_ADDRESS_LEN], MAC_ADDRESS_LEN);
		
		uint32_t move_flag = BME_RETURN_OK;
		
		/*移除隧道头*/
		if (0 != vlan_id)
		{
			move_flag = move_data_head(packet_info, -ALL_HEADER_SPACE_VLAN_WLTP);
		}
		else
		{
			move_flag = move_data_head(packet_info, -ALL_HEADER_SPACE_WLTP);
		}
		
		if (move_flag != BME_RETURN_OK)
		{
			se_log_new(SE_TUNNEL_LOG109, __FUNCTION__, __LINE__, 
				"move_data_head fail!\n");				
			return TUN_PACKET_DROP;
		}
		

		/*第二个分片无法获取station 信息*/
		if (fragment != SECOND_FRAGMENT_FLAG && packet_info->l2_data_length > ETH_HEAD_LEN)
		{
			uint8_t *data_sta = packet_info->l2_data;
			uint16_t sta_eth_type = zcom_get_ether_type(data_sta);
			IPAddr_t sta_ip_addr = 0;
			
			ip_hash_info_t sta_ip_info;
			memset(&sta_ip_info, 0x0, sizeof(sta_ip_info));
			memcpy(&sta_ip_info.mac, &data_sta[MAC_ADDRESS_LEN], MAC_ADDRESS_LEN);	
			sta_ip_info.port = PORT_WTP;
			
			if (sta_eth_type == ETH_P_8021Q)
			{
				sta_eth_type = hton16(*(uint16_t *)&data_sta[12+4]);
				sta_ip_info.vlan_id = zcom_get_vlan_id(data_sta);
    				cos = (data_sta[14] & ~0x1f)>>5;
    				if (0 == cos)
    				{
    					data_sta[14] = ((tos<<2)&~0x1f) | data_sta[14];
    				}
				data_sta = data_sta + (12+4+2);
			}
			else
			{	
				data_sta = data_sta + (12+2);
			}

			/*stony 120601 获取STA 的认证方式*/
			input_get_sta_auth_type(packet_info, sta_ip_info.vlan_id);
			
#ifndef MAC_KEY_SUPPORT
			VapHashKey.vap_index = packet_info->ws_tunnel_info.vap_index;
			VapHashInfo_t VapHashInfo;
			memset(&VapHashInfo, 0x0, sizeof(VapHashInfo_t));
			VapHashInfo.operation_vlan = sta_ip_info.vlan_id;
			if (VapHashInfo.operation_vlan != 0)
			{
				/*
				 * 记录下AP 的VAP 下有station 的数据
				 * 在往AP 发送广播报文时候据此判断是否往
				 * 该VAP 下发送广播报文
				 * 超时60 分钟
				 */
				UpdateHashForVap((uint8_t *)&VapHashKey, sizeof(VapHashKey_t), (uint8_t *)&VapHashInfo, sizeof(VapHashInfo_t));
			}
#endif
			if (sta_eth_type == ETH_P_IP)
			{
				ip_hdr *iphdr = (ip_hdr *)data_sta;
    				if (tos != (uint8_t)((iphdr->_v_hl_tos & 0xff)>>2))
    				{
    					if (tos != 0)
    					{
    						iphdr->_v_hl_tos = (iphdr->_v_hl_tos & 0xff00)  | (tos<<2);
    						//se_log(SE_LOG_WARN, "tos.....=%x\n, ",iphdr->_v_hl_tos);
    						iphdr->_chksum = 0;
    						IPH_CHKSUM_SET(iphdr, ip_cksum(data_sta, IP_HLEN));
    					}
    				}
				// Modified by TILERA
				// sta_ip_addr = hton32(iphdr->src.addr);
				memcpy(&sta_ip_addr, (char *)(&(iphdr->src.addr)), sizeof(sta_ip_addr)); 
				sta_ip_addr = hton32(sta_ip_addr);

				//if (sta_ip_addr != 0)
				{
					/**
	   				 * STA的相关信息，供WEB认证查询。
					 */
					ap_list_info_t *ap_list_info=NULL;
					sta_list_hash_info_t sta_list_info;
					memset(&sta_list_info, 0x0, sizeof(sta_list_hash_info_t));
					
					/*对于STA INFO hash表:有些信息在快速认证处更新，所有须先读取info信息*/
					if (search_hash_for_sta_list((uint8_t *)(data_inner + MAC_ADDRESS_LEN), MAC_ADDRESS_LEN,
						(uint8_t *)&sta_list_info, sizeof(sta_list_hash_info_t)) == -1)
					{
#ifdef IPv6
						ap_list_info=FindAPByIPAndPort(eth_mac,packet_info->ws_tunnel_info.ap_ip,
						packet_info->ws_tunnel_info.ap_ipv6,packet_info->ws_tunnel_info.src_port);
#else
						ap_list_info=FindAPByIPAndPort(eth_mac,packet_info->ws_tunnel_info.ap_ip,
														packet_info->ws_tunnel_info.src_port);
#endif
						if (NULL != ap_list_info)
						{
							memcpy(sta_list_info.ap_mac, ap_list_info->ap_mac_actual, MAC_ADDRESS_LEN);
						}
						else
						{
							memcpy(sta_list_info.ap_mac, eth_mac, MAC_ADDRESS_LEN);
							isHaveActualMac = FALSE;
						}
					}
					else
					{
						if ((sta_list_info.ap_ip != packet_info->ws_tunnel_info.ap_ip)
							|| (sta_list_info.ap_src_port != packet_info->ws_tunnel_info.src_port))
						{
							sta_list_info.ap_ip = packet_info->ws_tunnel_info.ap_ip;
							sta_list_info.ap_src_port = packet_info->ws_tunnel_info.src_port ;
#ifdef IPv6
							ap_list_info=FindAPByIPAndPort(eth_mac,packet_info->ws_tunnel_info.ap_ip,
							packet_info->ws_tunnel_info.ap_ipv6,packet_info->ws_tunnel_info.src_port);
#else
							ap_list_info=FindAPByIPAndPort(eth_mac,packet_info->ws_tunnel_info.ap_ip,
															packet_info->ws_tunnel_info.src_port);
#endif
							if (NULL != ap_list_info)
							{
								memcpy(sta_list_info.ap_mac, ap_list_info->ap_mac_actual, MAC_ADDRESS_LEN);
							}
							else
							{
								memcpy(sta_list_info.ap_mac, eth_mac, MAC_ADDRESS_LEN);
								isHaveActualMac = FALSE;
							}
						}					
					}
					sta_list_info.sta_ip = sta_ip_addr;
					memcpy(sta_list_info.sta_mac, (uint8_t *)(data_inner + MAC_ADDRESS_LEN), MAC_ADDRESS_LEN);
					//memcpy(sta_list_info.ap_mac, ap_list_info->ap_mac_actual, MAC_ADDRESS_LEN);
					sta_list_info.vlan_id = sta_ip_info.vlan_id;
					
					sta_list_info.ap_ip = packet_info->ws_tunnel_info.ap_ip;
					memcpy(sta_list_info.ap_ipv6.s6_addr,packet_info->ws_tunnel_info.ap_ipv6.s6_addr,sizeof(ipv6_addr));
					sta_list_info.ulflagIpa = 0;
					
					sta_list_info.temp_index= packet_info->ws_tunnel_info.template_id;
					sta_list_info.vap_index = packet_info->ws_tunnel_info.vap_index;
					sta_list_info.auth_type = packet_info->ws_tunnel_info.auth_type;
					
					if (packet_info->ws_tunnel_info.is_speed_auth == 1)
					{
						/*第一次来的STA须更新其WEB认状态为初始化状态*/
						/*状态为受制与hash表存活周期*/
						if (0 == sta_list_info.ismacauth)
						{
							sta_list_info.authflag = STALIST_WEBAUTH_FAIL;
							sta_list_info.ismacauth = 1;
						}	
					}
					else
					{
						sta_list_info.ismacauth = 0;
					}

					strcpy(sta_list_info.ssid, packet_info->ws_tunnel_info.ssid);
					
					/*stony 130219*/
					sta_list_hash_update_flag_t sta_list_hash_update_flag;
					memset(&sta_list_hash_update_flag, 0x0, sizeof(sta_list_hash_update_flag));
					sta_list_hash_update_flag.update_auth_status = FALSE;
					sta_list_hash_update_flag.update_last_online_time = FALSE;
		
					update_hash_for_sta_list(sta_list_info.sta_mac,MAC_ADDRESS_LEN, 
						(uint8_t *)&sta_list_info, sizeof(sta_list_hash_info_t), &sta_list_hash_update_flag);

					if (isHaveActualMac == FALSE)
					{
						se_log(SE_LOG_WARN, "No Actual Mac TUN_PACKET_DROP!Sta Mac:%02X-%02X-%02X-%02X-%02X-%02X\n"
							, sta_list_info.sta_mac[0], sta_list_info.sta_mac[1], sta_list_info.sta_mac[2]
							, sta_list_info.sta_mac[3], sta_list_info.sta_mac[4], sta_list_info.sta_mac[5]);
						return TUN_PACKET_DROP;
					}
					//ap_list_info->useAging= zcom_get_sys_time();;
					//UpdateHashForApList((uint8_t *)ap_list_info->ap_mac_actual, sizeof(MacAddr_t), (uint8_t *)ap_list_info, sizeof(ap_list_info_t));	

					/**				 
					 * 将station 的IP 地址更新至三层hash 表				 
					 * 由于隧道输出模块会对ARP 请求报文做优化
					 * 需要查询该表，如果走二层模式或者在业务板该表
					 * 就不会被更新。导致优化失效。 因此提前学习三层表。
					 */
					 if (sta_ip_addr !=0)
					 {
						 UpdateHashForIp((uint8_t *)&(sta_ip_addr), sizeof(IPAddr_t), 
						 	(uint8_t *)&sta_ip_info, sizeof(sta_ip_info), IP_HASH_CALL_FROM_TUNNEL);
					 }
				}
			}
			else if (g_bme_config->ipv6flag && sta_eth_type == ETH_P_IPV6)
			{
				ip_v6_hdr *ipv6hdr = (ip_v6_hdr *)data_sta;
				ipv6_addr sta_ip_addr;
				//se_printf(SE_PRINT_ERROR, "in qos pkts traffic_class=%d\n", tos);
				if (0 != tos && tos != get_ipv6_traffic_class(ipv6hdr))
				{
					//se_printf(SE_PRINT_ERROR, "in qos pkts traffic_class=%d\n", tos);
					set_ipv6_traffic_class(ipv6hdr, tos);
				}

				memcpy(sta_ip_addr.s6_addr, ipv6hdr->saddr.s6_addr, sizeof(sta_ip_addr)); 

				if ((sta_ip_addr.s6_addr32[0] & htonl(0xFFFFFFFF) 
					&& ((sta_ip_addr.s6_addr32[0] & htonl(0xFFFFFFFF)) != 0XFE800000))
					||(((sta_ip_addr.s6_addr32[0] & htonl(0xFFFFFFFF)) == 0XFE800000)
					&&( ipv6hdr->daddr.s6_addr32[0] == 0XFF020000 && ipv6hdr->daddr.s6_addr32[3] == 0X00010002)))
				{
					/**
	   				 * STA的相关信息，供WEB认证查询。
					 */
					ap_list_info_t *ap_list_info=NULL;
					sta_list_hash_info_t sta_list_info;
					memset(&sta_list_info, 0x0, sizeof(sta_list_hash_info_t));
					
					/*对于STA INFO hash表:有些信息在快速认证处更新，所有须先读取info信息*/
					if (search_hash_for_sta_list((uint8_t *)(data_inner + MAC_ADDRESS_LEN), MAC_ADDRESS_LEN,
						(uint8_t *)&sta_list_info, sizeof(sta_list_hash_info_t)) == -1)
					{
#ifdef IPv6
						ap_list_info=FindAPByIPAndPort(eth_mac,packet_info->ws_tunnel_info.ap_ip,
						packet_info->ws_tunnel_info.ap_ipv6,packet_info->ws_tunnel_info.src_port);
#else
						ap_list_info=FindAPByIPAndPort(eth_mac,packet_info->ws_tunnel_info.ap_ip,
														packet_info->ws_tunnel_info.src_port);
#endif
						if (NULL != ap_list_info)
						{
							memcpy(sta_list_info.ap_mac, ap_list_info->ap_mac_actual, MAC_ADDRESS_LEN);
						}
						else
						{
							memcpy(sta_list_info.ap_mac, eth_mac, MAC_ADDRESS_LEN);
							isHaveActualMac = FALSE;
						}
					}
					else
					{
						if ((sta_list_info.ap_ip != packet_info->ws_tunnel_info.ap_ip)
							|| (sta_list_info.ap_src_port != packet_info->ws_tunnel_info.src_port))
						{
							sta_list_info.ap_ip = packet_info->ws_tunnel_info.ap_ip;
							sta_list_info.ap_src_port = packet_info->ws_tunnel_info.src_port ;
#ifdef IPv6
							ap_list_info=FindAPByIPAndPort(eth_mac,packet_info->ws_tunnel_info.ap_ip,
							packet_info->ws_tunnel_info.ap_ipv6,packet_info->ws_tunnel_info.src_port);
#else
							ap_list_info=FindAPByIPAndPort(eth_mac,packet_info->ws_tunnel_info.ap_ip,
															packet_info->ws_tunnel_info.src_port);
#endif
							if (NULL != ap_list_info)
							{
								memcpy(sta_list_info.ap_mac, ap_list_info->ap_mac_actual, MAC_ADDRESS_LEN);
							}
							else
							{
								memcpy(sta_list_info.ap_mac, eth_mac, MAC_ADDRESS_LEN);
								isHaveActualMac = FALSE;
							}
						}					
					}
					//sta使用链路地址发送的时候，不更新staip地址信息。
					if (data_inner[0] != IPV6_UNUNICAST_MAC)
					{
						memcpy(sta_list_info.sta_ipv6.s6_addr, sta_ip_addr.s6_addr,sizeof(ipv6_addr));
					}
					else
					{
						memcpy(sta_list_info.sta_link_ipv6.s6_addr, sta_ip_addr.s6_addr,sizeof(ipv6_addr));
					}
					memcpy(sta_list_info.sta_mac, (uint8_t *)(data_inner + MAC_ADDRESS_LEN), MAC_ADDRESS_LEN);
					//memcpy(sta_list_info.ap_mac, ap_list_info->ap_mac_actual, MAC_ADDRESS_LEN);

					sta_list_info.vlan_id = sta_ip_info.vlan_id;
					
					sta_list_info.temp_index= packet_info->ws_tunnel_info.template_id;
					sta_list_info.vap_index = packet_info->ws_tunnel_info.vap_index;
					sta_list_info.auth_type = packet_info->ws_tunnel_info.auth_type;
					
					sta_list_info.ap_ip = packet_info->ws_tunnel_info.ap_ip;
					memcpy(sta_list_info.ap_ipv6.s6_addr,packet_info->ws_tunnel_info.ap_ipv6.s6_addr,sizeof(ipv6_addr));
					sta_list_info.ulflagIpa = 0;

					if (packet_info->ws_tunnel_info.is_speed_auth == 1)
					{
						/*第一次来的STA须更新其WEB认状态为初始化状态*/
						/*状态为受制与hash表存活周期*/
						if (0 == sta_list_info.ismacauth)
						{
							sta_list_info.authflag = STALIST_WEBAUTH_FAIL;
							sta_list_info.ismacauth = 1;
						}	
					}
					else
					{
						sta_list_info.ismacauth = 0;
					}	

					strcpy(sta_list_info.ssid, packet_info->ws_tunnel_info.ssid);
					/*stony 130219*/
					sta_list_hash_update_flag_t sta_list_hash_update_flag;
					memset(&sta_list_hash_update_flag, 0x0, sizeof(sta_list_hash_update_flag));
					sta_list_hash_update_flag.update_auth_status = FALSE;
					sta_list_hash_update_flag.update_last_online_time = FALSE;
					
					update_hash_for_sta_list(sta_list_info.sta_mac,MAC_ADDRESS_LEN, 
						(uint8_t *)&sta_list_info, sizeof(sta_list_hash_info_t), &sta_list_hash_update_flag);

					if (isHaveActualMac == FALSE)
					{
						se_log(SE_LOG_WARN, "No Actual Mac TUN_PACKET_DROP!Sta Mac:%02X-%02X-%02X-%02X-%02X-%02X\n"
							, sta_list_info.sta_mac[0], sta_list_info.sta_mac[1], sta_list_info.sta_mac[2]
							, sta_list_info.sta_mac[3], sta_list_info.sta_mac[4], sta_list_info.sta_mac[5]);
						return TUN_PACKET_DROP;
					}
					//ap_list_info->useAging= zcom_get_sys_time();;
					//UpdateHashForApList((uint8_t *)ap_list_info->ap_mac_actual, sizeof(MacAddr_t), (uint8_t *)ap_list_info, sizeof(ap_list_info_t));	

					/**				 
					 * 将station 的IP 地址更新至三层hash 表				 
					 * 由于隧道输出模块会对ARP 请求报文做优化
					 * 需要查询该表，如果走二层模式或者在业务板该表
					 * 就不会被更新。导致优化失效。 因此提前学习三层表。
					 */
					 if (sta_ip_addr.s6_addr32[0] & htonl(0xFFFFFFFF) 
							&& ((sta_ip_addr.s6_addr32[0] & htonl(0xFFFFFFFF)) != 0XFE800000))
					 {
					 	UpdateHashForIp(sta_list_info.sta_ipv6.s6_addr, sizeof(ipv6_addr), 
					 		(uint8_t *)&sta_ip_info, sizeof(sta_ip_info), IP_HASH_CALL_FROM_TUNNEL);
					 }
				}
			}
		}
		return return_flag;
	}
	
  	return TUN_DO_NOTHING;		
}
#endif /* 0 or 1 */

