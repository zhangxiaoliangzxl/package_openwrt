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


#include "CWCommon.h"

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

#define CW_SETTINGS_FILE 	"/usr/capwap/settings.wtp.txt"

FILE* gSettingsFile=NULL;
char* gInterfaceName=NULL;
char* gWanIfname=NULL;
int wanSwitchPort = 0;

void CWExtractValue(char* start, char** startValue, char** endValue, int* offset)
{
	*offset=strspn (start+1, " \t\n\r");
	*startValue = start +1+ *offset;

	*offset=strcspn (*startValue, " \t\n\r");
	*endValue = *startValue + *offset -1;
}

CWBool CWParseSettingsFile(unsigned int *WtpMaxTxpower)
{
	char *line = NULL;
	char* startValue=NULL;
	char* endValue=NULL;
	int offset = 0;
		
	gSettingsFile = fopen (CW_SETTINGS_FILE, "rb");
	if (gSettingsFile == NULL) {
		CWErrorRaiseSystemError(CW_ERROR_GENERAL);
	}
	
	while((line = (char*)CWGetCommand(gSettingsFile)) != NULL) 
	{
		char* startTag=NULL;
		char* endTag=NULL;
		
		if((startTag=strchr (line, '<'))==NULL) 
		{
			CW_FREE_OBJECT(line);
			continue;
		}

		if((endTag=strchr (line, '>'))==NULL) 
		{
			CW_FREE_OBJECT(line);
			continue;
		}
			
		if (!strncmp(startTag+1, "IF_NAME", endTag-startTag-1))
		{
			startValue=NULL;
			endValue=NULL;
			offset = 0;

			CWExtractValue(endTag, &startValue, &endValue, &offset);

			CW_CREATE_STRING_ERR(gInterfaceName, offset+1, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY,NULL););
			strncpy(gInterfaceName, startValue, offset);
			gInterfaceName[offset] ='\0';
			CW_FREE_OBJECT(line);
			continue;	
		}

		if (!strncmp(startTag+1, "WAN_IFNAME", endTag-startTag-1))
		{
			startValue=NULL;
			endValue=NULL;
			offset = 0;

			CWExtractValue(endTag, &startValue, &endValue, &offset);

			CW_CREATE_STRING_ERR(gWanIfname, 16, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY,NULL););
			strncpy(gWanIfname, startValue, offset);
			gWanIfname[offset] ='\0';
			CW_FREE_OBJECT(line);
			continue;	
		}
		
		if (!strncmp(startTag+1, "MAX_TXPOWER", endTag-startTag-1))
		{
			startValue=NULL;
			endValue=NULL;
			offset = 0;

			char *buf = NULL;

			CWExtractValue(endTag, &startValue, &endValue, &offset);

			CW_CREATE_STRING_ERR(buf, offset+1, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY,NULL););

			strncpy(buf, startValue, offset);
			buf[offset] ='\0';
			
			*WtpMaxTxpower = atoi(buf);
			
			CW_FREE_OBJECT(line);
			CW_FREE_OBJECT(buf);
			continue;	
		}
		if (!strncmp(startTag+1, "WAN_SWITCH_PORT", endTag-startTag-1))
		{
			startValue=NULL;
			endValue=NULL;
			offset = 0;

			char *buf = NULL;

			CWExtractValue(endTag, &startValue, &endValue, &offset);

			CW_CREATE_STRING_ERR(buf, offset+1, return CWErrorRaise(CW_ERROR_OUT_OF_MEMORY,NULL););

			strncpy(buf, startValue, offset);
			buf[offset] ='\0';
			
			wanSwitchPort = atoi(buf);
			
			CW_FREE_OBJECT(line);
			CW_FREE_OBJECT(buf);
			continue;	
		}

		CW_FREE_OBJECT(line);
	}
	return CW_TRUE;
}
