/************************************************************************************************
 * Copyright (c) DTT																			*
 *																								*
 * -------------------------------------------------------------------------------------------- *
 * Project:  DTT Capwap																			*
 *																								*
 * Authors : Suhongbo (suhongbo@datang.com)
 *
 ************************************************************************************************/
#ifndef __CAPWAP_DTTWTP_PROTOCOL_HEADER__
#define __CAPWAP_DTTWTP_PROTOCOL_HEADER__


CWBool CWAssembleMsgElemWTPVendorSpecificPayloadWTPVersion(CWProtocolMessage *msgPtr, int offset);
CWBool getWTPName(char **gname, char *bufname, int len);

#endif
