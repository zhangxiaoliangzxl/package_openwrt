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
#include "CWWTP.h"
//#define WRITE_STD_OUTPUT 1 

#ifdef DMALLOC
#include "../dmalloc-5.5.0/dmalloc.h"
#endif

static FILE *gLogFile = NULL;

#ifndef CW_SINGLE_THREAD
	CWThreadMutex gFileMutex;
#endif

void CWLogInitFile(char *fileName)
{
	if(fileName == NULL) {
		CWDTTLog("Wrong File Name for Log File");
		exit(1);
	}
	
	if((gLogFile = fopen(fileName, "w+")) == NULL) {
		CWDTTLog("Can't open log file: %s", strerror(errno));
		exit(1);
	}
	
#ifndef CW_SINGLE_THREAD
	if(!CWCreateThreadMutex(&gFileMutex)) {
		CWDTTLog("Can't Init File Mutex for Log");
		exit(1);
	}
#endif

}


CWBool checkResetFile()
{
	long fileSize=0;
     
	if((fileSize=ftell(gLogFile))==-1)
	{
		printf("An error with log file occurred: %s\n", strerror(errno));
		return 0;
	}
	
	if (fileSize >= gMaxLogFileSize)
	{
        fclose(gLogFile);
        gLogFile = NULL;
		if((gLogFile = fopen(WTP_LOG_FILE_NAME, "w+")) == NULL) 
		{
            printf("open logfile error!\n");
            return 0;
		}
	}

	return 1;
}


void CWLogCloseFile() {
	#ifndef CW_SINGLE_THREAD
		CWDestroyThreadMutex(&gFileMutex);
	#endif
	
	fclose(gLogFile);
}


__inline__ void get_now_time_date(char *time_data)
{
    time_t rawtime;
    struct tm * timeinfo;
    char buffer [64];

    time (&rawtime);
    timeinfo = localtime (&rawtime);

    strftime (buffer,sizeof(buffer),"%Y/%m/%d %H:%M:%S",timeinfo);
    sprintf(time_data, "%s", buffer); 
    return ;
}



__inline__ void CWVLog(const char *format, va_list args) {
	char *logStr = NULL;
	//time_t now;
	//char *nowReadable = NULL;
    char time_data[32] = {0};
		
	if(format == NULL) return;
	
	//now = time(NULL);
	//nowReadable = ctime(&now);
	
	//nowReadable[strlen(nowReadable)-1] = '\0';
	
	// return in case of memory err: we're not performing a critical task
	get_now_time_date(time_data);
    
	CW_CREATE_STRING_ERR(logStr, (strlen(format)+strlen(time_data)+100), return;);
	
	//sprintf(logStr, "[CAPWAP::%s]\t\t %s\n", nowReadable, format);
	sprintf(logStr, "[CAPWAP %s]\t%08x\t %s\n", time_data, (unsigned int)CWThreadSelf(), format);

	if(gLogFile != NULL) {
		char fileLine[256];

        
		#ifndef CW_SINGLE_THREAD
			CWThreadMutexLock(&gFileMutex);
		#endif
        fseek(gLogFile, 0L, SEEK_END);
		
		vsnprintf(fileLine, 255, logStr, args);

        if(!checkResetFile()) 
		{
			CWThreadMutexUnlock(&gFileMutex);
			exit (1);
		}
		
        if (gLogFile != NULL) {
    		fwrite(fileLine, strlen(fileLine), 1, gLogFile);
    		fflush(gLogFile);
        }
		
		#ifndef CW_SINGLE_THREAD
			CWThreadMutexUnlock(&gFileMutex);
		#endif
		
	}
#ifdef WRITE_STD_OUTPUT
	vprintf(logStr, args);
#endif	
	
	CW_FREE_OBJECT(logStr);
}

__inline__ void CWLog(const char *format, ...) {
	va_list args;
	
	va_start(args, format);
	//if (gEnabledLog)
		{CWVLog(format,args);}
	va_end(args);
}

__inline__ void CWDTTLog(const char *format, ...) {
	va_list args;
	
	va_start(args, format);
//	if (gEnabledLog)
		{CWVLog(format,args);}
	va_end(args);
}

__inline__ void CWDebugLog(const char *format, ...) {
	#ifdef CW_DEBUGGING
		char *logStr = NULL;
		va_list args;
        char time_data[32] = {0};
 		//time_t now;
		//char *nowReadable = NULL;
		
		//if (!gEnabledLog) {return;}
		
		if(format == NULL) {
#ifdef WRITE_STD_OUTPUT
			printf("\n");
#endif
			return;
		}
		
		//now = time(NULL);
		//nowReadable = ctime(&now);
		
		//nowReadable[strlen(nowReadable)-1] = '\0';
		
		// return in case of memory err: we're not performing a critical task
        get_now_time_date(time_data);
		CW_CREATE_STRING_ERR(logStr, (strlen(format)+strlen(time_data)+100), return;);
		
		//sprintf(logStr, "[[CAPWAP::%s]]\t\t %s\n", nowReadable, format);
		sprintf(logStr, "[CAPWAP %s]\t%08x\t %s\n", time_data, (unsigned int)CWThreadSelf(), format);

		va_start(args, format);
		
		if(gLogFile != NULL) {
			char fileLine[256];

            
			#ifndef CW_SINGLE_THREAD
				CWThreadMutexLock(&gFileMutex);
			#endif
            fseek(gLogFile, 0L, SEEK_END);
			
			vsnprintf(fileLine, 255, logStr, args);

			if(!checkResetFile()) 
			{
				CWThreadMutexUnlock(&gFileMutex);
				exit (1);
			}
            
            if (gLogFile != NULL) {
    			fwrite(fileLine, strlen(fileLine), 1, gLogFile);
    			fflush(gLogFile);
            }
			
			#ifndef CW_SINGLE_THREAD
			CWThreadMutexUnlock(&gFileMutex);
			#endif
			
		}
#ifdef WRITE_STD_OUTPUT	
		vprintf(logStr, args);
#endif
		
		va_end(args);
		CW_FREE_OBJECT(logStr);
	#endif
}
