#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "pspi.h"

static struct cfg_info *info;
static uchar mac_default[]={0xf0, 0x17, 0x01, 0x02, 0x03, 0x04};
void bootMAC_get(uchar *mac);

void error_exit(char *msg)
{
	printf("Oopsssss:%s!\n", msg);
	exit(-1);
}

void cfg_write(struct cfg_info *info)
{
	int fd, ret = 0;
	char errorMsg[ERMSG_LEN];
	fd = open(mtdev, O_RDWR);
	if(fd < 0)
	{
		sprintf(errorMsg, "open dev %s error!", mtdev);
		error_exit(errorMsg);
	}
	ret = write(fd, (void*)info, sizeof(struct cfg_info));
	if(ret < 0)
	{
		error_exit("cfg_write error!");
	}
	close(fd);
}

void cfg_read(struct cfg_info *info)
{
	int fd, ret;
	char errorMsg[ERMSG_LEN];

	fd = open(mtdev, O_RDONLY);
	if(fd < 0)
	{
		sprintf(errorMsg, "open dev %s error!", mtdev);
		error_exit(errorMsg);
	}
	
	ret = read(fd, (void*)info, sizeof(struct cfg_info));
	if(ret < 0)
	{
		error_exit("cfg_read error!");
	}
	close(fd);
}

void hex_print(uchar *data, uint len)
{
	uint i = 0;
	for(; i < len; i++)
	{
		printf("%.2x", data[i]);
	}
}

void cfg_print(struct cfg_info *info)
{
	printf("<------chunk start------>\n");
	printf("mac addr	:");
	hex_print(info->mac, 6);
	printf("\n");
	printf("product		:%s\n", info->type);
	printf("SN number	:%s\n", info->snum);
	printf("system ver	:%s\n", info->sver);
	printf("hware ver	:%s\n", info->hver);
	printf("active key	:%s\n", info->lkey);
	printf("<------chunk stop------->\n");
}

void str2hex(char *in, size_t len, uchar *out)
{
	unsigned int i, t, hn, ln;
	for (t = 0,i = 0; i < len; i+=2,++t)
	{
		hn = in[i] > '9' ? (in[i]) - (in[i] >= 'a' ? 'a' : 'A') + 10 : in[i] - '0';
		ln = in[i+1] > '9' ? (in[i+1]) - (in[i] >= 'a' ? 'a' : 'A') + 10 : in[i+1] - '0';
		out[t] = (hn << 4 ) | ln;
	}
}

void print_usage(const char* name)
{
	printf("\nUsage: %s\n\n"

			"General Options: Description (default value)\n"
			"  -h\t\tHelp\n"
			"  -v <version string>\t\tset system version\n"
			"  -V <version string>\t\tset hardware version\n"
			"  -s <snum string>\tset SN number\n"
			"  -t <product string>\tset product type\n"
			"  -m <mac string>\tset macaddr without \':\'\n"
			"\n",
			name);
}

void param_default()
{
	uchar mac[6];
	memset(info, 0x00, sizeof(struct cfg_info));
	//memcpy(info->mac, mac_default, 6);
	bootMAC_get(mac);
	memcpy(info->mac, mac, 6);

	memcpy(info->type, PVER, strlen(PVER));
	memcpy(info->sver, SVER, strlen(SVER));
	memcpy(info->hver, HVER, strlen(HVER));
	memcpy(info->snum, SNUM, strlen(SNUM));
	memcpy(info->lkey, LKEY, strlen(LKEY));
}

void mac_update()
{
	int fd, ret;
	uchar mac[6];
    char errorMsg[ERMSG_LEN];
	bootMAC_get(mac);

    fd = open(mtdev, O_WRONLY);
    if(fd < 0)
    {
        sprintf(errorMsg, "open dev %s error!", mtdev);
        error_exit(errorMsg);
    }

	ret = write(fd, mac, 6);
	if(ret < 0)
	{
        sprintf(errorMsg, "write dev %s error!", mtdev);
        error_exit(errorMsg);
	}
	close(fd);
}

void info_default()
{
    int fd;
    char errorMsg[ERMSG_LEN];
    uchar umac[6];
    cfg_read(info);
    memcpy(umac, info->mac, 6);

    memset(info, 0x00, sizeof(struct cfg_info));
    memcpy(info->mac, umac, 6);
    memcpy(info->type, PVER, strlen(PVER));
    memcpy(info->sver, SVER, strlen(SVER));
    memcpy(info->hver, HVER, strlen(HVER));
    memcpy(info->snum, SNUM, strlen(SNUM));
    memcpy(info->lkey, LKEY, strlen(LKEY));

    fd = open(mtdev, O_WRONLY);
    if(fd < 0)
    {
        sprintf(errorMsg, "open dev %s error!", mtdev);
        error_exit(errorMsg);
    }

#if 0
    /*skip mac address*/
    ret = lseek(fd, 0x1, SEEK_SET);
    if(ret < 0)
    {
        sprintf(errorMsg, "lseek fd %s error!", mtdev);
        error_exit(errorMsg);
    }

    printf("-->-->%d\n", ret);

    ret = write(fd, (void*)&(info->type), sizeof(struct cfg_info)-MAC_LEN);
    if(ret < 0)
    {
        error_exit("info cfg_write error!");
    }
#else
    cfg_write(info);
#endif

    close(fd);
}

void bootMAC_get(uchar *mac)
{
	int fd, ret;
	char errorMsg[ERMSG_LEN];
	fd = open("/dev/mtdblock0", O_RDONLY);
	if(fd < 0)
	{
		sprintf(errorMsg, "open dev %s error!", mtdev);
		error_exit(errorMsg);
	}

	ret = lseek(fd, 0x1fc00, SEEK_SET);
	if(ret < 0)
	{
		sprintf(errorMsg, "lseek fd %s error!", mtdev);
		error_exit(errorMsg);
	}
	ret = read(fd, mac, 6);
	if(ret < 0)
	{
		sprintf(errorMsg, "read mac @ fd %s error!", mtdev);
		error_exit(errorMsg);
	}
}

void param_parse(int argc, char *argv[])
{
	int c;
	while ((c = getopt(argc, argv, "m:v:V:s:t:l:hdgD")) > 0)
	{
		switch (c)
		{
			case 'm':
				str2hex(optarg, strlen(optarg), info->mac);
				break;
			case 't':
				memcpy((char*)info->type, optarg, 
						strlen(optarg) < TYPE_LEN ? strlen(optarg):TYPE_LEN);
				break;
			case 'v':
				memcpy((char*)info->sver, optarg,
						strlen(optarg) < SVER_LEN ? strlen(optarg):SVER_LEN);
				break;
			case 'V':
				memcpy((char*)info->hver, optarg,
						strlen(optarg) < HVER_LEN ? strlen(optarg):HVER_LEN);
				break;
			case 's':
				memcpy((char*)info->snum, optarg,
						strlen(optarg) < SN_LEN ? strlen(optarg): SN_LEN);
				break;
			case 'l':
				cfg_read(info);
				memcpy((char*)info->lkey, optarg, 
						strlen(optarg) < LKEY_LEN ? strlen(optarg):LKEY_LEN);
				cfg_write(info);
				break;
			case 'g':
				cfg_read(info);
				cfg_print(info);
				exit(0);
				break;
			case 'd':	//复位（不包括MAC地址, 首次启动使用）
				param_default();
				cfg_write(info);
				break;
			case 'D':	//更新MAC地址
				mac_update();
				break;
			case 'h':
			case '?':
				print_usage(argv[0]);
				exit(0);
				break;
			default:
				print_usage(argv[0]);
				exit(-1);
				break;
		}
	}
}

int main (int argc, char *argv[])
{
	info = (struct cfg_info*)calloc(sizeof(char), sizeof(struct cfg_info));

	if(argc < 2)
	{
		print_usage(argv[0]);
		exit(-1);
	}

	param_parse(argc, argv);
	free(info);
	info = NULL;
	return 0;
}
