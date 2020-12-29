#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "DTTConfigbin.h"

#define MAC_OFFSET 0
#define MODEL_OFFSET 0x30
#define SN_OFFSET 0x60
#define FW_OFFSET 0x90
#define HW_OFFSET 0xc0

#define MAC_LENGTH 6
#define MODEL_LENGTH 48
#define SN_LENGTH 48
#define FW_LENGTH 48
#define HW_LENGTH 48


static void printf_mac(char *type, FILE *fp, char *strvalue, int len)
{
	int offset = 0;
	int i = 0;
	char buffer[256] = {0};

	fseek(fp, MAC_OFFSET, SEEK_SET);
	fread(buffer, 6, 1, fp);

	if(!strcmp(type, "wan")){
		offset = 0;
//		printf("%s mac addr: \t\t", type);
	}
	else if(!strcmp(type, "wlan0")){
		offset = 1;
//		printf("%s mac addr: \t", type);
	}
	else if(!strcmp(type, "wlan1")){
		offset = 2;
//		printf("%s mac addr: \t", type);
	}

//	printf("len:%d\n", len);
    while(i < 6){
		if(i < 5)
			strvalue[i] = *((unsigned char*)(buffer+i));
		else
		    strvalue[i] = *((unsigned char*)(buffer+i))+offset;
		i ++;
    }
//	printf("\n");
}

static void print_general(int offset, char *buffer, char *strvalue, int len)
{
	int i = 0;

	while(i < offset){
		if(0xff != *((unsigned char*)(buffer+i))){
			snprintf(strvalue+i, len, "%c", *((unsigned char*)(buffer+i)));
//			printf("%c", *((unsigned char*)(buffer+i)));
		}
		i++;
	}
//	printf("\nstrvalue:%s\n", strvalue);
}

static void print_model(FILE *fp, char *strvalue, int len)
{
	char buffer[256] = {0};
	
    fseek(fp, MODEL_OFFSET, SEEK_SET);
    fread(buffer, MODEL_LENGTH, 1, fp);
//    printf("Device model: \t\t");
    print_general(MODEL_LENGTH, buffer, strvalue, len);
}

static void print_sn(FILE *fp, char *strvalue, int len)
{
	char buffer[256] = {0};

    fseek(fp, SN_OFFSET, SEEK_SET);
    fread(buffer, SN_LENGTH, 1, fp);
//    printf("Device S/N: \t\t");
    print_general(SN_LENGTH, buffer, strvalue, len);
}
static void print_fw(FILE *fp, char *strvalue, int len)
{
	char buffer[256] = {0};

    fseek(fp, FW_OFFSET, SEEK_SET);
    fread(buffer, FW_LENGTH, 1, fp);
//    printf("Device Fw Mode: \t");
    print_general(FW_LENGTH, buffer, strvalue, len);
}

static void print_hw(FILE *fp, char *strvalue, int len)
{
	char buffer[256] = {0};

    fseek(fp, HW_OFFSET, SEEK_SET);
    fread(buffer, HW_LENGTH, 1, fp);
//    printf("Device Hw Mode: \t");
    print_general(HW_LENGTH, buffer, strvalue, len);
}

#if 0

static void help()
{
	printf("Usage:\n");
	printf("\t\tget [option]\t\t(all | model | mac | SN)\n");
	printf("\t\tset <option> <value>\t(model | mac | SN)\n");
	printf("\t\t\tIf there is space in value, please use \"\"\n");
	printf("For example: \n");
	printf("\tconfigbin set mac 00:11:22:33:44:5d\n");
	printf("\tconfigbin set model \"test demo-1\"\n");
}

static void print_all(FILE *fp)
{
    printf_mac("wan", fp);
    printf_mac("wlan0", fp);
    printf_mac("wlan1", fp);

	print_model(fp);

	print_sn(fp);
}
static void erase_value(int size, FILE *fp)
{
	char fillChar = 0xFF;
	int i = 0;
	
	while(i < size){
		fwrite(&fillChar, 1, 1, fp);
		i ++;
	}
}

static void write_mac(char *buf, FILE *fp)
{
	unsigned int tmpmac[6] = {0};
	unsigned char mac[6] = {0};
	int i = 0;

	sscanf(buf, "%x:%x:%x:%x:%x:%x", tmpmac, tmpmac+1, tmpmac+2, tmpmac+3, tmpmac+4, tmpmac+5);

	while(i < 6){
		mac[i] = tmpmac[i];
		i ++;
	}
	i = 0;
//	printf("%x:%x:%x:%x:%x:%x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	fseek(fp, MAC_OFFSET, SEEK_SET);
	while(i < 6){
		fwrite(mac+i, 1, 1, fp);
		i ++;
	}
}
#endif
int getConfigbinInfo(char *type, char *buf, int len, char *card)
{
	FILE *fp = NULL;
	int blocknum = 0;
	char cmd[32] = {0};

	if(!buf)
		return -1;
#if 1
	fp = popen("cat /proc/mtd | grep art", "r");
	if(!fp)
		return -1;
	if(NULL != fgets(buf, len, fp))
		blocknum = strtoul(buf+3, NULL, 10);
	
	pclose(fp);
	fp = NULL;
#endif
	sprintf(cmd, "/dev/mtdblock%d", blocknum);
	//sprintf(cmd, "/etc/cfg.bin");
	
	fp = fopen(cmd, "r+");
	if(!fp)
		return -1;

	memset(buf, 0, len);
	if(!strcmp(type, "mac")){
		printf_mac(card, fp, buf, len);
	}/*
    else if(!strcmp(type, "model")){
		print_model(fp, buf, len);
	}else if(!strcmp(type, "sn")){
		print_sn(fp, buf, len);
	}else if(!strcmp(type, "fwmode")){
		print_fw(fp, buf, len);
	}else if(!strcmp(type, "hwmode")){
		print_hw(fp, buf, len);
	}*/
	
	fclose(fp);
	fp = NULL;

	return 0;
}

int getConfigbinMac(char *type, char *buf, int len, char *card)
{
	FILE *fp = NULL;
	int blocknum = 0;
	char cmd[32] = {0};

	if(!buf)
		return -1;
#if 1
	fp = popen("cat /proc/mtd | grep art", "r");
	if(!fp)
		return -1;
	if(NULL != fgets(buf, len, fp))
		blocknum = strtoul(buf+3, NULL, 10);
	
	pclose(fp);
	fp = NULL;
#endif
	sprintf(cmd, "/dev/mtdblock%d", blocknum);
	//sprintf(cmd, "/etc/cfg.bin");
	
	fp = fopen(cmd, "r+");
	if(!fp)
		return -1;

	memset(buf, 0, len);
	if(!strcmp(type, "mac")){
		printf_mac(card, fp, buf, len);
	}/*
    else if(!strcmp(type, "model")){
		print_model(fp, buf, len);
	}else if(!strcmp(type, "sn")){
		print_sn(fp, buf, len);
	}else if(!strcmp(type, "fwmode")){
		print_fw(fp, buf, len);
	}else if(!strcmp(type, "hwmode")){
		print_hw(fp, buf, len);
	}*/
	
	fclose(fp);
	fp = NULL;

	return 0;
}


