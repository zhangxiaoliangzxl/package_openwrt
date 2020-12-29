/*******************************************************************************************
 * Copyright (c) 2006-7 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica *
 *                      Universita' Campus BioMedico - Italy                               *
 *                                                                                         *
 * This program is free software; you can redistribute it and/or modify it under the terms *
 * of the GNU General Public License as published by the Free Software Foundation; either  *
 * version 2 of the License, or (at your option) any later version.                        *
 *                                                                                         *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY         *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 	       *
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
#include "dtt.h"

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

/*____________________________________________________________________________*/
/*  *****************************___ASSEMBLE___*****************************  */
CWBool CWAssembleMsgElemACName(CWProtocolMessage *msgPtr) 
{
	char *name;
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	name = CWWTPGetACName();
//	CWDebugLog("AC Name: %s", name);
	
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, strlen(name), return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWProtocolStoreStr(msgPtr, name);
				
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_AC_NAME_CW_TYPE);
}

CWBool CWAssembleMsgElemACNameWithIndex(CWProtocolMessage *msgPtr) 
{
	const int ac_Index_length=1;
	CWACNamesWithIndex ACsinfo;
	CWProtocolMessage *msgs;
	int len = 0;
	int i;
	int j;
	
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	if(!CWWTPGetACNameWithIndex(&ACsinfo)){
		return CW_FALSE;
	}
	
	CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgs, ACsinfo.count, return  CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	// create message
	for(i = 0; i < ACsinfo.count; i++) {
		// create message
		CW_CREATE_PROTOCOL_MESSAGE(msgs[i], ac_Index_length+strlen(ACsinfo.ACNameIndex[i].ACName), return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		CWProtocolStore8(&(msgs[i]), ACsinfo.ACNameIndex[i].index); // ID of the AC
		CWProtocolStoreStr(&(msgs[i]), ACsinfo.ACNameIndex[i].ACName); // name of the AC
		if(!(CWAssembleMsgElem(&(msgs[i]), CW_MSG_ELEMENT_AC_NAME_INDEX_CW_TYPE))) {
			for(j = i; j >= 0; j--) { CW_FREE_PROTOCOL_MESSAGE(msgs[j]);}
			CW_FREE_OBJECT(ACsinfo.ACNameIndex);
			CW_FREE_OBJECT(msgs);
			return CW_FALSE;
		}
//		CWDebugLog("AC Name with index: %d - %s", ACsinfo.ACNameIndex[i].index, ACsinfo.ACNameIndex[i].ACName);
		len += msgs[i].offset;
	}
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, len, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < ACsinfo.count; i++) {
		CWProtocolStoreMessage(msgPtr, &(msgs[i]));
		CW_FREE_PROTOCOL_MESSAGE(msgs[i]);
	}
	
	CW_FREE_OBJECT(msgs);

 	/*
         * They free ACNameIndex, which is an array of CWACNameWithIndexValues,
         * but nobody cares to free the actual strings that were allocated as fields
         * of the CWACNameWithIndexValues structures in the CWWTPGetACNameWithIndex() 
         * function.. Here we take care of this.
         *
         * BUG ML06
         * 16/10/2009 - Donato Capitella 
         */
        CW_FREE_OBJECT(ACsinfo.ACNameIndex[0].ACName);
        CW_FREE_OBJECT(ACsinfo.ACNameIndex[1].ACName);


	CW_FREE_OBJECT(ACsinfo.ACNameIndex);
	
	return CW_TRUE;
}

CWBool CWAssembleMsgElemDataTransferData(CWProtocolMessage *msgPtr, int data_type) {
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	char* debug_data= " #### DATA DEBUG INFO #### ";   //to be changed...
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, 2 + strlen(debug_data) , return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	

	CWProtocolStore8(msgPtr, data_type);
	CWProtocolStore8(msgPtr,strlen(debug_data));
	CWProtocolStoreStr(msgPtr, debug_data);
	
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_DATA_TRANSFER_DATA_CW_TYPE);
}

CWBool CWAssembleMsgElemDiscoveryType(CWProtocolMessage *msgPtr) {
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, 1, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWLog("Discovery Type: %d", CWWTPGetDiscoveryType());

	CWProtocolStore8(msgPtr, CWWTPGetDiscoveryType());

	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_DISCOVERY_TYPE_CW_TYPE);
}

CWBool CWAssembleMsgElemLocationData(CWProtocolMessage *msgPtr) {
	char *location;
	
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	location = CWWTPGetLocation();
	
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, strlen(location), return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
//	CWDebugLog("Location Data: %s", location);
	CWProtocolStoreStr(msgPtr, location);
					
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_LOCATION_DATA_CW_TYPE);	
}

CWBool CWAssembleMsgElemStatisticsTimer(CWProtocolMessage *msgPtr)
{	
	const int statistics_timer_length= 2;
	
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, statistics_timer_length, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWProtocolStore16(msgPtr, CWWTPGetStatisticsTimer());
	
//	CWDebugLog("Statistics Timer: %d", CWWTPGetStatisticsTimer());
	
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_STATISTICS_TIMER_CW_TYPE);	
}

CWBool CWAssembleMsgElemWTPBoardData(CWProtocolMessage *msgPtr) 
{
	const int VENDOR_ID_LENGTH = 4; 	//Vendor Identifier is 4 bytes long
	const int TLV_HEADER_LENGTH = 4; 	//Type and Length of a TLV field is 4 byte long 
	CWWTPVendorInfos infos;
	int i, size = 0;
	
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	 // get infos
	if(!CWWTPGetBoardData(&infos)) {
		return CW_FALSE;
	}
	
	//Calculate msg elem size
	size = VENDOR_ID_LENGTH;
	for(i = 0; i < infos.vendorInfosCount; i++) 
		{size += (TLV_HEADER_LENGTH + ((infos.vendorInfos)[i]).length);}
	
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, size, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWProtocolStore32(msgPtr, ((infos.vendorInfos)[0].vendorIdentifier));
	for(i = 0; i < infos.vendorInfosCount; i++) 
	{
		CWProtocolStore16(msgPtr, ((infos.vendorInfos)[i].type));
		CWProtocolStore16(msgPtr, ((infos.vendorInfos)[i].length));
		
		if((infos.vendorInfos)[i].length == 4) {
			*((infos.vendorInfos)[i].valuePtr) = htonl(*((infos.vendorInfos)[i].valuePtr));
		}
	
		CWProtocolStoreRawBytes(msgPtr, (char*) ((infos.vendorInfos)[i].valuePtr), (infos.vendorInfos)[i].length);
		
		CWLog("Board Data: %d - %d - %d - %d", (infos.vendorInfos)[i].vendorIdentifier, (infos.vendorInfos)[i].type, (infos.vendorInfos)[i].length, *((infos.vendorInfos)[i].valuePtr));
	}

	CWWTPDestroyVendorInfos(&infos);

	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_WTP_BOARD_DATA_CW_TYPE);
}

CWBool CWAssembleMsgElemWTPDescriptor(CWProtocolMessage *msgPtr) {
	const int GENERIC_RADIO_INFO_LENGTH = 4;//First 4 bytes for Max Radios, Radios In Use and Encryption Capability 
	const int VENDOR_ID_LENGTH = 4; 	//Vendor Identifier is 4 bytes long
	const int TLV_HEADER_LENGTH = 4; 	//Type and Length of a TLV field is 4 byte long 
	CWWTPVendorInfos infos;
	int i, size = 0;
	
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	// get infos
	if(!CWWTPGetVendorInfos(&infos)) { 
		return CW_FALSE;
	}
	
	//Calculate msg elem size
	size = GENERIC_RADIO_INFO_LENGTH;
	for(i = 0; i < infos.vendorInfosCount; i++) 
		{size += (VENDOR_ID_LENGTH + TLV_HEADER_LENGTH + ((infos.vendorInfos)[i]).length);}
		
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, size, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWProtocolStore8(msgPtr, CWWTPGetMaxRadios()); // number of radios supported by the WTP
	CWProtocolStore8(msgPtr, CWWTPGetRadiosInUse()); // number of radios present in the WTP
	CWProtocolStore16(msgPtr, CWWTPGetEncCapabilities()); // encryption capabilities
 
	for(i = 0; i < infos.vendorInfosCount; i++) {
		CWProtocolStore32(msgPtr, ((infos.vendorInfos)[i].vendorIdentifier));
		CWProtocolStore16(msgPtr, ((infos.vendorInfos)[i].type));
		CWProtocolStore16(msgPtr, ((infos.vendorInfos)[i].length));
		
		if((infos.vendorInfos)[i].length == 4) {
			*((infos.vendorInfos)[i].valuePtr) = htonl(*((infos.vendorInfos)[i].valuePtr));
		}
	
		CWProtocolStoreRawBytes(msgPtr, (char*) ((infos.vendorInfos)[i].valuePtr), (infos.vendorInfos)[i].length);

		CWLog("WTP Descriptor Vendor ID: %d", (infos.vendorInfos)[i].vendorIdentifier);
		CWLog("WTP Descriptor Type: %d", (infos.vendorInfos)[i].type);
		CWLog("WTP Descriptor Length: %d", (infos.vendorInfos)[i].length);
		CWLog("WTP Descriptor Value: %d", *((infos.vendorInfos)[i].valuePtr));

		CWLog("Vendor Info \"%d\" = %d - %d - %d", i, (infos.vendorInfos)[i].vendorIdentifier, (infos.vendorInfos)[i].type, (infos.vendorInfos)[i].length);
	}
	
	CWWTPDestroyVendorInfos(&infos);
	
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_WTP_DESCRIPTOR_CW_TYPE);
}

CWBool CWAssembleMsgElemWTPFrameTunnelMode(CWProtocolMessage *msgPtr) {
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, 1, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWLog("Frame Tunnel Mode: %d", CWWTPGetFrameTunnelMode());
	CWProtocolStore8(msgPtr, CWWTPGetFrameTunnelMode()); // frame encryption

	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_WTP_FRAME_TUNNEL_MODE_CW_TYPE);
}

CWBool CWAssembleMsgElemWTPIPv4Address(CWProtocolMessage *msgPtr) {
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, 4, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

//	CWDebugLog("WTP IPv4 Address: %d", CWWTPGetIPv4Address());
	CWProtocolStore32(msgPtr, CWWTPGetIPv4Address());

	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_WTP_IPV4_ADDRESS_CW_TYPE);
}

CWBool CWAssembleMsgElemWTPMACType(CWProtocolMessage *msgPtr) {
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, 1, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWLog("WTP MAC Type: %d", CWWTPGetMACType());
	CWProtocolStore8(msgPtr, CWWTPGetMACType()); // mode of operation of the WTP (local, split, ...)
	
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_WTP_MAC_TYPE_CW_TYPE);
}

CWBool getWTPName(char **gname, char *bufname, int len)
{
	char *cmd = "uci get system.@system[0].hostname";
	char buffer[128] = {0};

	FILE *fp = NULL;

	fp = popen(cmd, "r");
	if(fp == NULL)
		return CW_FALSE;
	while(fgets(buffer, 128, fp))
	{
		buffer[strlen(buffer) - 1] = '\0';
	}
	/*< 在gWTPName中保存全局的apname*/
	if(bufname != NULL){
		CW_COPY_MEMORY(bufname, buffer, len);
	}
	else{
		CW_CREATE_STRING_ERR(*gname, len, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		CW_COPY_MEMORY(*gname, buffer, len);
	}
	pclose(fp);
	fp = NULL;
	return CW_TRUE;
}

int getWTPMac(char *mac)
{
	char *cmd = NULL;
	int tmp[6] = {0};
    FILE *fp = NULL;
	char buf[32] = {0};

	printf("get mac gAPIndex=%d\n", gAPIndex);
	if(gAPIndex == 1)
		cmd = "cat /sys/class/net/wifi0/address";
	else if(gAPIndex == 2)
		cmd = "cat /sys/class/net/wifi1/address";
	
	fp = popen(cmd, "r");
	fgets(buf, 31, fp);
	buf[strlen(buf)-1]='\0';

	sscanf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", tmp, tmp+1, tmp+2, tmp+3, tmp+4, tmp+5);
	
	mac[0] = tmp[0];mac[1] = tmp[1];mac[2] = tmp[2];
	mac[3] = tmp[3];mac[4] = tmp[4];mac[5] = tmp[5];

	pclose(fp);
	fp = NULL;
	return 0;
}

CWBool CWAssembleMsgElemWTPVendorSpecificPayloadWTPMAC(CWProtocolMessage *msgPtr, int offset) {
	
	const int VENDOR_ID_LENGTH = 4; 	//Vendor Identifier is 4 bytes long
	const int PL_HEADER_LENGTH = 4; 	//PayLoad lenth is 4 byte long 
	int len = 0;
//	char *mac = NULL;
	
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	len = VENDOR_ID_LENGTH + PL_HEADER_LENGTH + offset;
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, len, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWProtocolStore32(msgPtr, CW_VENDOR_ID); // z-com
	CWProtocolStore16(msgPtr, CW_DTT_MSG_ELEMENT_GENETIC_GET_WTP_MAC);
	CWProtocolStore16(msgPtr, 6);

//	CW_CREATE_OBJECT_SIZE_ERR(mac, 6, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
//	CW_ZERO_MEMORY(mac, 6);
//	getWTPMac(mac);

//	CWLog("%02x:%02x:%02x:%02x:%02x:%02x\n", *(unsigned char *)mac, *(unsigned char *)(mac+1),  *(unsigned char *)(mac+2),  *(unsigned char *)(mac+3), 
//		 *(unsigned char *)(mac+4),  *(unsigned char *)(mac+5));

	CWProtocolStoreRawBytes(msgPtr, g_DevMAC, 6);
//	CW_FREE_OBJECT(mac);
	
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE);
}

CWBool CWAssembleMsgElemWTPVendorSpecificPayloadUnkown(CWProtocolMessage *msgPtr, int offset) {

	if(gCWAPCardCount == CW_ONE_CARD)
		return CW_TRUE;
	const int VENDOR_ID_LENGTH = 4; 	//Vendor Identifier is 4 bytes long
	const int PL_HEADER_LENGTH = 4; 	//PayLoad lenth is 4 byte long 
	int len = 0;
//	char *mac = NULL;
	
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	len = VENDOR_ID_LENGTH + PL_HEADER_LENGTH + offset;
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, len, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWProtocolStore32(msgPtr, CW_VENDOR_ID); // z-com
	CWProtocolStore16(msgPtr, CW_DTT_MSG_ELEMENT_GENETIC_DOUBLE_CARD_GET_WTP_ORTHER_MAC);
	CWProtocolStore16(msgPtr,6);

//	CW_CREATE_OBJECT_SIZE_ERR(mac, 6, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
//	if(gAPIndex == 1){
//		mac[0] = 0x0;mac[1] = 0x14;mac[2] = 0xd5;mac[3] = 0x92;mac[4] = 0xb2;mac[5] = 0x92;
//	}
//	else{
//		mac[0] = 0x0;mac[1] = 0x14;mac[2] = 0xd5;mac[3] = 0x92;mac[4] = 0xb2;mac[5] = 0x91;
//	}
    CWLog("*******%s**********\n", __FUNCTION__);
	CWProtocolStoreRawBytes(msgPtr, g_SlaveDevMAC, 6);
	
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE);
}

CWBool CWAssembleMsgElemWTPVendorSpecificPayloadWTPVersion(CWProtocolMessage *msgPtr, int offset) {
	
	const int VENDOR_ID_LENGTH = 4; 	//Vendor Identifier is 4 bytes long
	const int PL_HEADER_LENGTH = 4; 	//PayLoad lenth is 4 byte long 
	int len = 0;
	char fill[192] = {0};
	char *version = NULL;
	
	//char tmp_HwMode[48] = {0};
	//char tmp_sn[64] = {0};
	
//	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	len = VENDOR_ID_LENGTH + PL_HEADER_LENGTH + offset;
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, len, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	CWProtocolStore32(msgPtr, CW_VENDOR_ID); // z-com
	CWProtocolStore16(msgPtr, CW_DTT_MSG_ELEMENT_GENETIC_GET_WTP_INFO);
	CWProtocolStore16(msgPtr, 192);

//	CW_CREATE_OBJECT_SIZE_ERR(version, 192, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
//	CW_ZERO_MEMORY(version, 192);
	
//	CW_COPY_MEMORY(version, "ZDC_ZN7100_V2", 13);
//	CW_COPY_MEMORY(version + 64, "1.1.9(Test)10", 13);
//	CW_COPY_MEMORY(version, g_DevHwMode, 48);
	/*< 星网云联特殊需求，内部版本号为SN的前12个字符*/
//	CW_COPY_MEMORY(version + 64, g_DevSn, 12);
//	CW_COPY_MEMORY(version + 64, g_DevHideFwMode, strlen(g_DevHideFwMode));

//	CWProtocolStoreRawBytes(msgPtr, version, 192);
	//getConfigbinInfo("hwmode", tmp_HwMode, 48, NULL);
	//getConfigbinInfo("sn", tmp_sn, 64, NULL);
    //strcpy(tmp_sn, "V334R126A160000001");
    //strcpy(tmp_HwMode, "ZDC_MIPS_ZN7100");
	
    CWProtocolStoreRawBytes(msgPtr, g_DevHwMode, 48);
	CWProtocolStoreRawBytes(msgPtr, fill, 16);
	CWProtocolStoreRawBytes(msgPtr, g_DevSn, 12);
	CWProtocolStoreRawBytes(msgPtr, fill, 116);
	
//	CW_FREE_OBJECT(version);
	
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_VENDOR_SPEC_PAYLOAD_CW_TYPE);
}


CWBool CWAssembleMsgElemWTPName(CWProtocolMessage *msgPtr) {
	char name[32] = {0};
	
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	if(NULL == CWWTPGetName()){
		if(!getWTPName(NULL, (char *)name, 32))
			return CW_FALSE;
	}else{
		CW_COPY_MEMORY(name, CWWTPGetName(), strlen(CWWTPGetName()));
	}
	// create message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, strlen(name), return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
//	CWDebugLog("WTPName: %s", name);
	CWProtocolStoreRawBytes(msgPtr, name, strlen(name));
	
	return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_WTP_NAME_CW_TYPE);	
} 

CWBool CWAssembleMsgElemRadioAdminState(CWProtocolMessage *msgPtr) 
{
	const int radio_Admin_State_Length=2;
	CWRadiosAdminInfo infos;
	CWProtocolMessage *msgs;
	int len = 0;
	int i;
	int j;
	
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	if(!CWGetWTPRadiosAdminState(&infos)) {
		return CW_FALSE;
	}
	
	CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgs, (infos.radiosCount), return  CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < infos.radiosCount; i++) {
		// create message
		CW_CREATE_PROTOCOL_MESSAGE(msgs[i], radio_Admin_State_Length, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		CWProtocolStore8(&(msgs[i]), infos.radios[i].ID); // ID of the radio
		CWProtocolStore8(&(msgs[i]), infos.radios[i].state); // state of the radio
		//CWProtocolStore8(&(msgs[i]), infos.radios[i].cause);
		
		if(!(CWAssembleMsgElem(&(msgs[i]), CW_MSG_ELEMENT_RADIO_ADMIN_STATE_CW_TYPE))) {
			for(j = i; j >= 0; j--) { CW_FREE_PROTOCOL_MESSAGE(msgs[j]);}
			CW_FREE_OBJECT(infos.radios);
			CW_FREE_OBJECT(msgs);
			return CW_FALSE;
		}
		
		len += msgs[i].offset;
//		CWDebugLog("Radio Admin State: %d - %d - %d", infos.radios[i].ID, infos.radios[i].state, infos.radios[i].cause);
	}
	
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, len, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < infos.radiosCount; i++) {
		CWProtocolStoreMessage(msgPtr, &(msgs[i]));
		CW_FREE_PROTOCOL_MESSAGE(msgs[i]);
	}
	
	CW_FREE_OBJECT(msgs);
	CW_FREE_OBJECT(infos.radios);

	return CW_TRUE;
}

//if radioID is negative return Radio Operational State for all radios
CWBool CWAssembleMsgElemRadioOperationalState(int radioID, CWProtocolMessage *msgPtr) 
{
	const int radio_Operational_State_Length=3;
	CWRadiosOperationalInfo infos;
	CWProtocolMessage *msgs;
	int len = 0;
	int i;

	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

	if(!(CWGetWTPRadiosOperationalState(radioID,&infos))) {
		return CW_FALSE;
	}

	CW_CREATE_PROTOCOL_MSG_ARRAY_ERR(msgs, (infos.radiosCount), return  CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < infos.radiosCount; i++) {
		// create message
		CW_CREATE_PROTOCOL_MESSAGE(msgs[i], radio_Operational_State_Length, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		CWProtocolStore8(&(msgs[i]), infos.radios[i].ID); // ID of the radio
		CWProtocolStore8(&(msgs[i]), infos.radios[i].state); // state of the radio
		CWProtocolStore8(&(msgs[i]), infos.radios[i].cause);
		
		if(!(CWAssembleMsgElem(&(msgs[i]), CW_MSG_ELEMENT_RADIO_OPERAT_STATE_CW_TYPE))) {
			int j;
			for(j = i; j >= 0; j--) { CW_FREE_PROTOCOL_MESSAGE(msgs[j]);}
			CW_FREE_OBJECT(infos.radios);
			CW_FREE_OBJECT(msgs);
			return CW_FALSE;
		}
		
		len += msgs[i].offset;
//		CWDebugLog("Radio Operational State: %d - %d - %d", infos.radios[i].ID, infos.radios[i].state, infos.radios[i].cause);
	}
	
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, len, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < infos.radiosCount; i++) {
		CWProtocolStoreMessage(msgPtr, &(msgs[i]));
		CW_FREE_PROTOCOL_MESSAGE(msgs[i]);
	}
	
	CW_FREE_OBJECT(msgs);
	CW_FREE_OBJECT(infos.radios);

	return CW_TRUE;
}

/*
CWBool CWAssembleMsgElemWTPRadioInformation(CWProtocolMessage *msgPtr) {
	CWProtocolMessage *msgs;
	CWRadiosInformation infos;
	
	int len = 0;
	int i;
	
	if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);
	
	CWDebugLog("Assemble WTP Radio Info");
	
	if(!CWWTPGetRadiosInformation(&infos)) {
		return CW_FALSE;
	}
	
	// create one message element for each radio
	
	CW_CREATE_ARRAY_ERR(msgs, (infos.radiosCount), CWProtocolMessage, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < infos.radiosCount; i++) {
		// create message
		CW_CREATE_PROTOCOL_MESSAGE(msgs[i], 5, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
		CWProtocolStore8(&(msgs[i]), infos.radios[i].ID); // ID of the radio
		CWProtocolStore32(&(msgs[i]), infos.radios[i].type); // type of the radio
		
		CWDebugLog("WTPRadioInformation: %d - %d", infos.radios[i].ID, infos.radios[i].type);
		
		if(!(CWAssembleMsgElem(&(msgs[i]), CW_MSG_ELEMENT_WTP_RADIO_INFO_CW_TYPE))) {
			int j;
			for(j = i; j >= 0; j--) { CW_FREE_PROTOCOL_MESSAGE(msgs[j]);}
			CW_FREE_OBJECT(infos.radios);
			CW_FREE_OBJECT(msgs);
			return CW_FALSE;
		}
		
		len += msgs[i].offset;
	}
	
	// return all the messages as one big message
	CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, len, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < infos.radiosCount; i++) {
		CWProtocolStoreMessage(msgPtr, &(msgs[i]));
		CW_FREE_PROTOCOL_MESSAGE(msgs[i]);
	}
	
	CW_FREE_OBJECT(msgs);
	CW_FREE_OBJECT(infos.radios);
	
	return CW_TRUE;
}
*/

/*_________________________________________________________________________*/
/*  *****************************___PARSE___*****************************  */
CWBool CWParseACDescriptor(CWProtocolMessage *msgPtr, int len, CWACInfoValues *valPtr) {
	int i=0, theOffset=0;
		
	CWParseMessageElementStart();
	
	valPtr->stations= CWProtocolRetrieve16(msgPtr);
//	CWDebugLog("AC Descriptor Stations: %d", valPtr->stations);
	
	valPtr->limit	= CWProtocolRetrieve16(msgPtr);
//	CWDebugLog("AC Descriptor Limit: %d", valPtr->limit);
	
	valPtr->activeWTPs= CWProtocolRetrieve16(msgPtr);
//	CWDebugLog("AC Descriptor Active WTPs: %d", valPtr->activeWTPs);
	
	valPtr->maxWTPs	= CWProtocolRetrieve16(msgPtr);
//	CWDebugLog("AC Descriptor Max WTPs: %d",	valPtr->maxWTPs);
	
	valPtr->security= CWProtocolRetrieve8(msgPtr);
//	CWDebugLog("AC Descriptor Security: %d",	valPtr->security);
	
	valPtr->RMACField= CWProtocolRetrieve8(msgPtr);
//	CWDebugLog("AC Descriptor Radio MAC Field: %d",	valPtr->security);

//	valPtr->WirelessField= CWProtocolRetrieve8(msgPtr);
//	CWDebugLog("AC Descriptor Wireless Field: %d",	valPtr->security);

	CWProtocolRetrieve8(msgPtr);			//Reserved

	valPtr->DTLSPolicy= CWProtocolRetrieve8(msgPtr); // DTLS Policy
//	CWDebugLog("DTLS Policy: %d",	valPtr->DTLSPolicy);

	valPtr->vendorInfos.vendorInfosCount = 0;
	
	theOffset = msgPtr->offset;
	
	// see how many vendor ID we have in the message
	while((msgPtr->offset-oldOffset) < len) {	// oldOffset stores msgPtr->offset's value at the beginning of this function.
							// See the definition of the CWParseMessageElementStart() macro.
		unsigned short tmp;		

		//CWDebugLog("differenza:%d, offset:%d, oldOffset:%d", (msgPtr->offset-oldOffset), (msgPtr->offset), oldOffset);

		CWProtocolRetrieve32(msgPtr);
//		CWDebugLog("ID: %d", id); // ID
		
		CWProtocolRetrieve16(msgPtr);
//		CWDebugLog("TYPE: %d",type); // type
		
		tmp = CWProtocolRetrieve16(msgPtr);
		msgPtr->offset += tmp; // len
//		CWDebugLog("offset %d", msgPtr->offset);
		valPtr->vendorInfos.vendorInfosCount++;
	}
	
	msgPtr->offset = theOffset;
	
	// actually read each vendor ID
	CW_CREATE_ARRAY_ERR(valPtr->vendorInfos.vendorInfos, valPtr->vendorInfos.vendorInfosCount, CWACVendorInfoValues,
		return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
//	CWDebugLog("len %d", len);
//	CWDebugLog("vendorInfosCount %d", valPtr->vendorInfos.vendorInfosCount);
	for(i = 0; i < valPtr->vendorInfos.vendorInfosCount; i++) {
//		CWDebugLog("vendorInfosCount %d vs %d", i, valPtr->vendorInfos.vendorInfosCount);
		(valPtr->vendorInfos.vendorInfos)[i].vendorIdentifier = CWProtocolRetrieve32(msgPtr);
		(valPtr->vendorInfos.vendorInfos)[i].type = CWProtocolRetrieve16(msgPtr);																
		(valPtr->vendorInfos.vendorInfos)[i].length = CWProtocolRetrieve16(msgPtr);
		(valPtr->vendorInfos.vendorInfos)[i].valuePtr = (int*) (CWProtocolRetrieveRawBytes(msgPtr, (valPtr->vendorInfos.vendorInfos)[i].length));
		
		if((valPtr->vendorInfos.vendorInfos)[i].valuePtr == NULL) return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL);
		
		if((valPtr->vendorInfos.vendorInfos)[i].length == 4) {
			*((valPtr->vendorInfos.vendorInfos)[i].valuePtr) = ntohl(*((valPtr->vendorInfos.vendorInfos)[i].valuePtr));
		}
		
//		CWDebugLog("AC Descriptor Vendor ID: %d", (valPtr->vendorInfos.vendorInfos)[i].vendorIdentifier);
//		CWDebugLog("AC Descriptor Type: %d", (valPtr->vendorInfos.vendorInfos)[i].type);
//		CWDebugLog("AC Descriptor Value: %d", *((valPtr->vendorInfos.vendorInfos)[i].valuePtr));
	}		
//	CWDebugLog("AC Descriptor Out");
	CWParseMessageElementEnd();
}

CWBool CWParseACIPv4List(CWProtocolMessage *msgPtr, int len, ACIPv4ListValues *valPtr) {
	int i;
	CWParseMessageElementStart();
	
	if(len == 0 || ((len % 4) != 0)) return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Malformed AC IPv4 List Messame Element");
	
	valPtr->ACIPv4ListCount = (len/4);
	
	CW_CREATE_ARRAY_ERR(valPtr->ACIPv4List, valPtr->ACIPv4ListCount, int, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < valPtr->ACIPv4ListCount; i++) {
		struct sockaddr_in addr;
		(valPtr->ACIPv4List)[i] = CWProtocolRetrieve32(msgPtr);
//		CWDebugLog("AC IPv4 List (%d): %d", i+1, (valPtr->ACIPv4List)[i]);
		addr.sin_addr.s_addr = (valPtr->ACIPv4List)[i];
		addr.sin_family = AF_INET;
		addr.sin_port = 1024;
		CWUseSockNtop(&addr, CWDebugLog(str););
	}
	
	CWParseMessageElementEnd();
}

CWBool CWParseACIPv6List(CWProtocolMessage *msgPtr, int len, ACIPv6ListValues *valPtr) 
{
	int i;
	CWParseMessageElementStart();
	
	if(len == 0 || ((len % 16) != 0)) return CWErrorRaise(CW_ERROR_INVALID_FORMAT, "Malformed AC IPv6 List Messame Element");
	
	valPtr->ACIPv6ListCount = (len/16);
	
	CW_CREATE_ARRAY_ERR(valPtr->ACIPv6List, valPtr->ACIPv6ListCount, struct in6_addr, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););
	
	for(i = 0; i < valPtr->ACIPv6ListCount; i++) {
		struct sockaddr_in6 addr;
   		
		/*
                 * BUG ML09
                 * 19/10/2009 - Donato Capitella
                 */                
		void *ptr;
                ptr =  CWProtocolRetrieveRawBytes(msgPtr, 16);
                CW_COPY_MEMORY(&((valPtr->ACIPv6List)[i]), ptr, 16);
                CW_FREE_OBJECT(ptr);
		CW_COPY_MEMORY(&(addr.sin6_addr), &((valPtr->ACIPv6List)[i]), 16);
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(CW_CONTROL_PORT);
		
//		CWUseSockNtop(&addr, CWDebugLog("AC IPv6 List: %s",str););
	}
	
	CWParseMessageElementEnd();
}

CWBool CWParseAddStation(CWProtocolMessage *msgPtr, int len) 
{
	unsigned char Length=0;
	unsigned char* StationMacAddress;
	
	//CWParseMessageElementStart();	 sostituire al posto delle righe successive quando passer貌 valPtr alla funzione CWarseAddStation
	/*--------------------------------------------------------------------------------------*/
	int oldOffset;												
			if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);	
						oldOffset = msgPtr->offset;
	/*----------------------------------------------------------------------------------*/
	
	
	CWProtocolRetrieve8(msgPtr);
	//CWDebugLog("radio ID %d",radioID);
	Length = CWProtocolRetrieve8(msgPtr);
	//CWDebugLog("Length of mac address field %d",Length);
	StationMacAddress = (unsigned char*)CWProtocolRetrieveRawBytes(msgPtr, Length);
	
	    
      
	CWDebugLog("STATION'S MAC ADDRESS TO FORWARD TRAFFIC: %02X:%02X:%02X:%02X:%02X:%02X",  
								StationMacAddress[0] & 0xFF,
      								StationMacAddress[1] & 0xFF,
      								StationMacAddress[2] & 0xFF,
      								StationMacAddress[3] & 0xFF,
      								StationMacAddress[4] & 0xFF,
      								StationMacAddress[5] & 0xFF);
	

	CWParseMessageElementEnd();  
}

CWBool CWParseCWControlIPv4Addresses(CWProtocolMessage *msgPtr, int len, CWProtocolIPv4NetworkInterface *valPtr) {
	CWParseMessageElementStart();

	valPtr->addr.sin_addr.s_addr = htonl(CWProtocolRetrieve32(msgPtr));
	valPtr->addr.sin_family = AF_INET;
	valPtr->addr.sin_port = htons(CW_CONTROL_PORT);
	
	CWUseSockNtop((&(valPtr->addr)), CWDebugLog("Interface Address: %s", str););
	
	valPtr->WTPCount = CWProtocolRetrieve16(msgPtr);
//	CWDebugLog("WTP Count: %d",	valPtr->WTPCount);
	
	CWParseMessageElementEnd();
}

CWBool CWParseCWControlIPv6Addresses(CWProtocolMessage *msgPtr, int len, CWProtocolIPv6NetworkInterface *valPtr) {
	CWParseMessageElementStart();
	
	CW_COPY_MEMORY(&(valPtr->addr.sin6_addr), CWProtocolRetrieveRawBytes(msgPtr, 16), 16);
	valPtr->addr.sin6_family = AF_INET6;
	valPtr->addr.sin6_port = htons(CW_CONTROL_PORT);
	
	CWUseSockNtop((&(valPtr->addr)), CWDebugLog("Interface Address: %s", str););
	
	valPtr->WTPCount = CWProtocolRetrieve16(msgPtr);
//	CWDebugLog("WTP Count: %d",	valPtr->WTPCount);
	
	CWParseMessageElementEnd();
}

CWBool CWParseCWTimers (CWProtocolMessage *msgPtr, int len, CWProtocolConfigureResponseValues *valPtr)
{
	CWParseMessageElementStart();
	
	valPtr->discoveryTimer	= CWProtocolRetrieve8(msgPtr);	
//	CWDebugLog("Discovery Timer: %d", valPtr->discoveryTimer);
	valPtr->echoRequestTimer = CWProtocolRetrieve8(msgPtr);
//	CWDebugLog("Echo Timer: %d", valPtr->echoRequestTimer);
	
	CWParseMessageElementEnd();
}

CWBool CWParseDecryptErrorReportPeriod (CWProtocolMessage *msgPtr, int len, WTPDecryptErrorReportValues *valPtr)
{
	CWParseMessageElementStart();
	
	valPtr->radioID = CWProtocolRetrieve8(msgPtr);
	valPtr->reportInterval = CWProtocolRetrieve16(msgPtr);
//	CWDebugLog("Decrypt Error Report Period: %d - %d", valPtr->radioID, valPtr->reportInterval);
	
	CWParseMessageElementEnd();
}

CWBool CWParseIdleTimeout (CWProtocolMessage *msgPtr, int len, CWProtocolConfigureResponseValues *valPtr)
{
	CWParseMessageElementStart();
	
	valPtr->idleTimeout = CWProtocolRetrieve32(msgPtr);	
//	CWDebugLog("Idle Timeout: %d", valPtr->idleTimeout);
		
	CWParseMessageElementEnd();
}

CWBool CWParseWTPFallback (CWProtocolMessage *msgPtr, int len, CWProtocolConfigureResponseValues *valPtr)
{
	CWParseMessageElementStart();
	
	valPtr->fallback = CWProtocolRetrieve8(msgPtr);	
//	CWDebugLog("WTP Fallback: %d", valPtr->fallback);
		
	CWParseMessageElementEnd();
}

void CWWTPResetRebootStatistics(WTPRebootStatisticsInfo *rebootStatistics)
{
	rebootStatistics->rebootCount=0;
	rebootStatistics->ACInitiatedCount=0;
	rebootStatistics->linkFailurerCount=0;
	rebootStatistics->SWFailureCount=0;
	rebootStatistics->HWFailuireCount=0;
	rebootStatistics->otherFailureCount=0;
	rebootStatistics->unknownFailureCount=0;
	rebootStatistics->lastFailureType=NOT_SUPPORTED;
}	
CWBool CWAssembleMsgElemWTPRebootStatistics(CWProtocolMessage *msgPtr)
{
        const int reboot_statistics_length= 15;

        if(msgPtr == NULL) return CWErrorRaise(CW_ERROR_WRONG_ARG, NULL);

        CW_CREATE_PROTOCOL_MESSAGE(*msgPtr, reboot_statistics_length, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY, NULL););

        CWProtocolStore16(msgPtr, gWTPRebootStatistics.rebootCount);
        CWProtocolStore16(msgPtr, gWTPRebootStatistics.ACInitiatedCount);
        CWProtocolStore16(msgPtr, gWTPRebootStatistics.linkFailurerCount);
        CWProtocolStore16(msgPtr, gWTPRebootStatistics.SWFailureCount);
        CWProtocolStore16(msgPtr, gWTPRebootStatistics.HWFailuireCount);
        CWProtocolStore16(msgPtr, gWTPRebootStatistics.otherFailureCount);
        CWProtocolStore16(msgPtr, gWTPRebootStatistics.unknownFailureCount);
        CWProtocolStore8(msgPtr, gWTPRebootStatistics.lastFailureType);

//      CWDebugLog("");
//      CWDebugLog("WTPRebootStat(1): %d - %d - %d", gWTPRebootStatistics.rebootCount, gWTPRebootStatistics.ACInitiatedCount, gWTPRebootStatistics.linkFailurerCount);
//      CWDebugLog("WTPRebootStat(2): %d - %d - %d", gWTPRebootStatistics.SWFailureCount, gWTPRebootStatistics.HWFailuireCount, gWTPRebootStatistics.otherFailureCount);
//      CWDebugLog("WTPRebootStat(3): %d - %d", gWTPRebootStatistics.unknownFailureCount, gWTPRebootStatistics.lastFailureType);

        return CWAssembleMsgElem(msgPtr, CW_MSG_ELEMENT_WTP_REBOOT_STATISTICS_CW_TYPE);
}

