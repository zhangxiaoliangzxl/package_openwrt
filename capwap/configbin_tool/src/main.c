#include <stdio.h>
#include <string.h>
#include <errno.h>

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


static void printf_mac(char *type, FILE *fp)
{
	int offset = 0;
	int i = 0;
	char buffer[256] = {0};

	fseek(fp, MAC_OFFSET, SEEK_SET);
	fread(buffer, 6, 1, fp);

	if(!strcmp(type, "wan")){
		offset = 0;
		printf("%s mac addr: \t\t", type);
	}
	else if(!strcmp(type, "wlan0")){
		offset = 0;
		printf("%s mac addr: \t", type);
	}
	else if(!strcmp(type, "wlan1")){
		offset = 1;
		printf("%s mac addr: \t", type);
	}

        while(i < 6){
			if(i < 5)
				printf("%02X:", *((unsigned char*)(buffer+i)));
			else
			    printf("%02X", *((unsigned char*)(buffer+i))+offset);
			i ++;
        }
	printf("\n");
}

static void print_general(int offset, char *buffer)
{
	int i = 0;

	while(i < offset){
		if(0xff != *((unsigned char*)(buffer+i)))
			printf("%c", *((unsigned char*)(buffer+i)));
		i++;
	}
	printf("\n");
}

static void print_model(FILE *fp)
{
	char buffer[256] = {0};
	
    fseek(fp, MODEL_OFFSET, SEEK_SET);
    fread(buffer, MODEL_LENGTH, 1, fp);
    printf("Device model: \t\t");
    print_general(MODEL_LENGTH, buffer);
}

static void print_sn(FILE *fp)
{
	char buffer[256] = {0};

    fseek(fp, SN_OFFSET, SEEK_SET);
    fread(buffer, SN_LENGTH, 1, fp);
    printf("Device S/N: \t\t");
    print_general(SN_LENGTH, buffer);
}

static void print_fw(FILE *fp)
{
	char buffer[256] = {0};

    fseek(fp, FW_OFFSET, SEEK_SET);
    fread(buffer, FW_LENGTH, 1, fp);
    printf("Device Fw Mode: \t");
    print_general(FW_LENGTH, buffer);
}

static void print_hw(FILE *fp)
{
	char buffer[256] = {0};

    fseek(fp, HW_OFFSET, SEEK_SET);
    fread(buffer, HW_LENGTH, 1, fp);
    printf("Device Hw Mode: \t");
    print_general(HW_LENGTH, buffer);
}

static void help()
{
	printf("Usage:\n");
	printf("\t\tget [option]\t\t(all | model | mac | SN | fwmode | hwmode)\n");
	printf("\t\tset <option> <value>\t(model | mac | SN | fwmode | hwmode)\n");
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
	
	print_fw(fp);
	print_hw(fp);
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

int main(int argc, char *argv[])
{
	FILE *fp = NULL;
	char buf[128] = {0};	
	int i = 0;
	char a = 1;
	int blocknum = 0;
        char cmd[32] = {0};

	fp = popen("cat /proc/mtd | grep cfg", "r");
        if(!fp)
                return -1;
        if(NULL != fgets(buf, sizeof(buf), fp))
                blocknum = strtoul(buf+3, NULL, 10);

        pclose(fp);
        fp = NULL;
        sprintf(cmd, "/dev/mtdblock%d", blocknum);

	fp = fopen(cmd, "r+");
	if(!fp)
		return 0;

	switch(argc)
	{
		case 1:
			help();
			goto EXIT;
		case 2:
			if(!strcmp(argv[1], "get"))
				print_all(fp);
			else{
				help();
				goto EXIT;
			}
			break;
		case 3:
			if(!strcmp(argv[1], "get")){
				if(!strcmp(argv[2], "all"))
					print_all(fp);
				else if(!strcmp(argv[2], "model"))
					print_model(fp);
				else if(!strcmp(argv[2], "mac")){
					printf_mac("wan", fp);
				        printf_mac("wlan0", fp);
				        printf_mac("wlan1", fp);
				}
				else if(!strcmp(argv[2], "SN"))
					print_sn(fp);
				else if(!strcmp(argv[2], "hwmode"))
					print_hw(fp);
				else if(!strcmp(argv[2], "fwmode"))
					print_fw(fp);
				else{
					help();
					goto EXIT;
				}
			}
            else{
                    help();
                    goto EXIT;
            }
			break;
		case 4:
			if(!strcmp(argv[1], "set")){
				if(!strcmp(argv[2], "model")){
					fseek(fp, MODEL_OFFSET, SEEK_SET);
					erase_value(MODEL_LENGTH, fp);
					fseek(fp, MODEL_OFFSET, SEEK_SET);
					fwrite(argv[3], strlen(argv[3]), 1, fp);
				}
				else if(!strcmp(argv[2], "mac")){
					fseek(fp, MAC_OFFSET, SEEK_SET);
					erase_value(MAC_LENGTH, fp);
					write_mac(argv[3], fp);
				}
				else if(!strcmp(argv[2], "SN")){
					fseek(fp, SN_OFFSET, SEEK_SET);
					erase_value(SN_LENGTH, fp);
					fseek(fp, SN_OFFSET, SEEK_SET);
					fwrite(argv[3], strlen(argv[3]), 1, fp);
				}
				else if(!strcmp(argv[2], "fwmode")){
					fseek(fp, FW_OFFSET, SEEK_SET);
					erase_value(FW_LENGTH, fp);
					fseek(fp, FW_OFFSET, SEEK_SET);
					fwrite(argv[3], strlen(argv[3]), 1, fp);
				}
				else if(!strcmp(argv[2], "hwmode")){
					fseek(fp, HW_OFFSET, SEEK_SET);
					erase_value(HW_LENGTH, fp);
					fseek(fp, HW_OFFSET, SEEK_SET);
					fwrite(argv[3], strlen(argv[3]), 1, fp);
				}
				else{
					help();
					goto EXIT;
				}
			}
			else{
                    help();
                    goto EXIT;
            }
			break;
		default:
			help();
			goto EXIT;
	}

EXIT:
	fclose(fp);
	fp = NULL;

	return 0;
}
