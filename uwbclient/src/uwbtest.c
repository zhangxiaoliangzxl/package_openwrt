/*************************************************************************
>  File Name: uwbtest.c
>  Author: zxl
>  Mail:
>  Created Time: Thu 11 Jun 2020 09:02:32 AM CST
*************************************************************************/

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

int init_com(char *device)
{
	int fd = 0;
	struct termios Opt;

	fd = open(device, O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (fd < 0)
	{
		return fd;
	}

	tcgetattr(fd, &Opt);

	cfsetispeed(&Opt, B921600);
	cfsetospeed(&Opt, B921600);
	Opt.c_lflag &= ~ICANON;
	Opt.c_lflag &= ~IEXTEN;
	Opt.c_lflag &= ~ISIG;
	Opt.c_lflag &= ~ECHO;

	Opt.c_iflag = 0;

	Opt.c_oflag = 0;

	if (tcsetattr(fd, TCSANOW, &Opt) != 0)
	{
		return -1;
	}

	return fd;
}

void usage(void)
{
	printf(
		"usage: uwbclient testmode(1 uwb/ 2 433M / 3 blue) ttydev(/dev/ttyS0,/dev/ttyUSB0,...) sleep "
		"us(100,200,500...) \n");
}

/* main */
int main(int argc, char *argv[])
{
	long long i;
	int j;
	int fd = 0;
	char *device;
	int sleepcnt = 0;
	int testmode = 0;

	struct timeval begin, end;
	long long curtime, lasttime;

	char *testdata = NULL;
	int testdata_len = 0;
	char testdata_uwb[] = {0x7e, 0xff, 0xd0, 0x7d, 0x3e, 0xb4, 0xb1, 0x7d, 0x20, 0x34, 0x2c, 0xdf, 0x7d,
						   0x20, 0xdc, 0x7d, 0x20, 0x7d, 0x20, 0x7d, 0x20, 0x7d, 0x20, 0x7d, 0x20, 0x7d,
						   0x20, 0x7d, 0x20, 0x7d, 0x20, 0x7d, 0x20, 0x7d, 0x25, 0x7d, 0x20, 0x7d, 0x20,
						   0x7d, 0x20, 0x7d, 0x20, 0x7d, 0x20, 0x7d, 0x20, 0x7d, 0x20, 0x7d, 0x20, 0x7d,
						   0x21, 0x4a, 0x7d, 0x23, 0x7d, 0x20, 0x93, 0xd2, 0xff, 0x7e};
	char testdata_433[] =
		"RF433M[-56]{AID:65535,TID:99,SEQ:251,NUM:6,DATA:{[0,0,0,-66,96],[0,10196,14042,-64,96],[0,0,4690,-66,96],[0,"
		"10196,14046,-69,96],[0,0,4687,-70,96],[0,10196,14109,-65,96]}};\nRF433M[-30]{AID:65535,TID:65535,SEQ:18,NUM:6,"
		"DATA:{[0,10196,14042,-66,96],[0,0,4687,-75,96],[0,0,4690,-69,96],[0,0,4689,-76,96],[0,0,4690,-72,96],[0,0,0,-"
		"63,96]}};\nRF433M[-56]{AID:65535,TID:99,SEQ:252,NUM:3,DATA:{[0,0,0,-63,96],[0,10196,14042,-70,96],[0,0,4688,-"
		"68,96]}};\n";

	char testdata_blue[] = {"ADDR:f3:53:4a:a6:29:76,UUID:00000000-0000-0801-a000-000000000812,MAJOR:13398,MINOR:255,RSSI:-86,R2OM:-61;\n"
							"IDSN:0004004465,MAC:ff:ff:00:3d:1b:70,TH:27.1,TE:28,WS:2,RSSI:-41;\n"
							"RDL52B1:d5:84:25:3f:c9:cc,RDLT:0.0,RDLH:0.0,ACCG:0.02,RSSI:-43;\n"
							"RDL52B2:d5:84:25:3f:c9:cc,MAJOR:256,MINOR:512,TXP:7,BCI:59,BAT:201,RSSI:-47;\n"};

	if (argc < 3)
	{
		usage();
		return 0;
	}

	testmode = atoi(argv[1]);

	device = argv[2];
	fd = init_com(device);

	if (fd < 0)
	{
		printf("open %s error !\n", device);
		return 0;
	}

	sleepcnt = atoi(argv[3]);

	switch (testmode)
	{
		case 1:
			testdata = testdata_uwb;
			testdata_len = sizeof(testdata_uwb);
			break;
		case 2:
			testdata = testdata_433;
			testdata_len = strlen(testdata_433);
			break;
		case 3:
			testdata = testdata_blue;
			testdata_len = strlen(testdata_blue);
			break;
		default:
			printf("unkown testmode, exit !\n");
			return 0;
	}

	/*send data*/
	i = 0;
	j = 0;

	gettimeofday(&begin, NULL);
	lasttime = (long long)begin.tv_sec * 1000 + (long long)begin.tv_usec / 1000;
	printf("%lld\n", lasttime);

	while (1)
	{
		write(fd, testdata, testdata_len);
		i++;
		j++;
		if (j >= 1000)
		{
			j = 0;
			printf("send num %lld \n", i);

			gettimeofday(&begin, NULL);
			curtime = (long long)begin.tv_sec * 1000 + (long long)begin.tv_usec / 1000;
			printf("%lld\n", curtime);
			printf("send 1000 data use %lld ms\n", curtime - lasttime);

			lasttime = curtime;
		}

		usleep(sleepcnt);
	}

	return 0;
}
