#include "elog/elog.h"
#include "init.h"
#include "self.h"
#include "utils.h"

extern int heartup_sleep;
/* system no wait, notice vfork not return */
void system_nowait(const char *comand)
{
	int ret = fork();
	if (ret == 0)
	{
		int retGrandSon = fork();
		if (retGrandSon == 0)
		{
			sleep(2);
			execl("/bin/sh", "sh", "-c", comand, (char *)0);
		}
		else
		{
			_exit(0);
		}
	}
	else
	{
		printf("vfork create son process with retcode : %d\n", ret);
		if (ret > 0)
		{
			if (waitpid(ret, NULL, 0) != ret) /* wait for first child */
			{
				printf("waitpid fail with return code %d\n", ret);
			}
		}
	}
}

int _popen(const char *cmd, char *resault, int resault_len)
{
	FILE *fd;
	if (cmd == NULL)
	{
		printf("cmd is null !\n");
		return -1;
	}

	if ((fd = popen(cmd, "r")) != NULL)
	{
		memset(resault, 0, resault_len);
		if (fgets(resault, resault_len - 1, fd))
		{
			if (resault[strlen(resault) - 1] == 0x0a)
			{
				resault[strlen(resault) - 1] = '\0';
			}
		}
		pclose(fd);
		return 0;
	}

	return -1;
}

/* get_hostip_by_url */
int get_hostip_by_url(char *url, char *hostip)
{
	char array[128] = {0};
	int i = 0;

	strncpy(array, url, 128);
	char *p = array;
	memset(hostip, 0, sizeof(hostip));

	while (*p)
	{
		for (; *p && (*p < '0' || *p > '9'); p++)
			;
		for (; *p && (*p == '.' || (*p >= '0' && *p <= '9')); p++)
		{
			sprintf(&hostip[i], "%c", *p);
			i++;
		}
		break;
	}
	// printf("hostip is %s\n", hostip);
	return 0;
}

/* must free host and abs_path*/
int parse_url(const char *url, const char *protocl, char *host, unsigned int *port, char *abs_path)
{
	int ret = -1;

	if (url == NULL)
	{
		return ret;
	}

	char *url_dup = strdup(url);
	char *p_slash = NULL; // first '/'
	char *p_colon = NULL; // first ':'
	char *start = 0;

	if (strncmp(url_dup, protocl, strlen(protocl)) == 0)
	{
		start = url_dup + strlen(protocl) + 2; // '//'
		p_slash = strchr(start, '/');
		if (p_slash != NULL)
		{
			strcpy(abs_path, p_slash);
			*p_slash = '\0';
		}

		p_colon = strchr(start, ':');
		if (p_colon != NULL)
		{
			*port = atoi(p_colon + 1);
			*p_colon = '\0';
		}
		else
		{
			*port = 0;
		}

		strcpy(host, start);

		ret = 1;
	}

	if (url_dup != NULL)
	{
		free(url_dup);
		url_dup = NULL;
	}

	return ret;
}

/*get key value*/
static void trim(char *strIn, char *strOut)
{
	char *start, *end, *temp;
	temp = strIn;

	while (*temp == ' ')
	{
		++temp;
	}

	start = temp;
	temp = strIn + strlen(strIn) - 1;

	while (*temp == ' ')
	{
		--temp;
	}

	end = temp;

	for (strIn = start; strIn <= end;)
	{
		*strOut++ = *strIn++;
	}

	*strOut = '\0';
	return;
}

void get_value_by_key(char *keyAndValue, char *key, char *outvalue)
{
	char value[1024] = {0};
	char *p = keyAndValue;

	p = strstr(keyAndValue, key);
	if (p == NULL)
	{
		// printf("not find the key[%s] in str\n", key);
		return;
	}

	p += strlen(key);
	trim(p, value);

	p = strstr(value, "=");
	if (p == NULL)
	{
		printf("not find = in str\n");
		return;
	}
	p += strlen("=");
	trim(p, value);

	p = strstr(value, ",");
	if (p != NULL)
	{
		*p = '\0';
	}

	p = value;
	trim(p, value);
	sprintf(outvalue, "%s", value);

	return;
}

/*get broadcast*/

int get_broadcast_by_ifname(char *ifname, char *broadcast)
{
	char cmd[256] = {0};

	sprintf(cmd, "ifconfig %s | grep Bcast | awk -F':' '{print $3}' | awk '{print $1}'", ifname);
	memset(broadcast, 0, sizeof(broadcast));

	FILE *fp = popen(cmd, "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return -1;
	}
	fgets(broadcast, IPLEN, fp);
	pclose(fp);

	return 0;
}

/*get ap ip*/
int get_ap_ip(void)
{
	FILE *fp = NULL;
	char ip[32] = {0};
	int ret = 0;

	memset(ip, 0, sizeof(ip));

	fp = popen("uci_get_ip lan", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return -1;
	}
	fgets(ip, sizeof(ip), fp);

	if (strlen(ip) > 7)
	{
		ret = 1;
	}

	pclose(fp);

	return ret;
}

void ac_is_running(void)
{
}

/* get the system type code */
int getsystype(const char *type)
{
	return 0;
}

static int get_jsonint(cJSON *node)
{
	int value = 0;

	if (node->type == cJSON_Number)
	{
		value = node->valueint;
	}
	else if (node->type == cJSON_String && strlen(node->valuestring))
	{
		value = atoi(node->valuestring);
	}

	return value;
}

/*********************************************
 *函数名：
 *        get_*
 *函数功能：
 *        get函数组，分别从ap中获得相应的心跳参数
 *********************************************/
int getGet(char *dest, char *cmd, int n)
{
	memset(dest, 0, n);
	FILE *fp = popen(cmd, "r");
	if (NULL == fp)
	{
		log_e("popen error!");
		return -1;
	}
	fread(dest, 1, n, fp);
	pclose(fp);
	return 0;
}

int get_disabled(void)
{
	char buf[32] = {0};
	memset(buf, 0, sizeof(buf));
	FILE *fp = popen("uci -q get aconf.client.disabled | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return -1;
	}
	fgets(buf, sizeof(buf), fp);
	pclose(fp);
	return atoi(buf);
}

void get_rssi(int *rssi)
{
	char buf[32] = {0};
	/* 获取rssi门限 */
	FILE *fp = popen("uci -q get aconf.client.rssi | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	fgets(buf, sizeof(buf), fp);
	pclose(fp);
	*rssi = atoi(buf);
}

void get_server_ip(char *ip)
{
	/* 获取server ip */
	FILE *fp = popen("uci -q get aconf.normal.sip| tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	fgets(ip, LITTLEBUF, fp);
	pclose(fp);
}

void get_mac(char *mac)
{
	FILE *fp = popen("ifconfig eth0 | grep HWaddr | awk '{print $5}' | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	fgets(mac, MACLEN, fp);
	pclose(fp);
}

void get_lan_ip(char *ip)
{
	/* 获取内网ip地址 */
	FILE *fp = popen("ifconfig br-lan | grep 'inet addr' | awk '{print $2}' | sed '{s/addr://g}' | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	fgets(ip, IPLEN, fp);
	pclose(fp);
}

void get_wan_ip(char *ip)
{
	/* 获取外网ip地址 */
	FILE *fp = popen("ifconfig eth0.2 | grep 'inet addr' | awk '{print $2}' | sed '{s/addr://g}' | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	fgets(ip, IPLEN, fp);
	pclose(fp);
}

void get_devnumbers(unsigned long *num)
{
	char buf[LITTLEBUF] = {0};
	/* 获取当前设备连接数 */
	FILE *fp = popen("iw wlan0 station dump | grep Station | wc -l | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	fgets(buf, sizeof(buf), fp);
	//    log_i("%s\n", buf);
	*num = (unsigned long)atoi(buf);
	//    log_i("%d\n", devnumbers);
	pclose(fp);
}

void get_ssid(char *ssid)
{
	/* 获取ssid */
	FILE *fp = popen("uci -q get wireless.wmesh.mesh_id | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	fgets(ssid, 128, fp);
	pclose(fp);
}

void get_channel(unsigned long *channel)
{
	char buf[LITTLEBUF] = {0};
	/* 获取channel */
	FILE *fp = popen("uci -q get wireless.radio0.channel | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	fgets(buf, sizeof(buf), fp);
	pclose(fp);
	*channel = atoi(buf);
}

void get_dimension(unsigned long *dimension)
{
	char buf[LITTLEBUF] = {0};

	FILE *fp = popen("dimension_get | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("dimension_get popen error");
		return;
	}
	fgets(buf, sizeof(buf), fp);
	pclose(fp);

	if (strlen(buf) > 0)
	{
		*dimension = atoi(buf);
	}
	else
	{
		*dimension = 0;
	}
}

void get_ap_type(char *ap_type)
{
	FILE *fp = popen("cat /etc/hw_type | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	memset(ap_type, 0, 32);
	fgets(ap_type, 32, fp);
	pclose(fp);
}

void get_ap_version(char *ap_version)
{
	FILE *fp = popen("cat /etc/build_version | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	memset(ap_version, 0, 32);
	fgets(ap_version, 32, fp);
	pclose(fp);
}

void get_probe_stat(unsigned long *stat)
{
	char buf[LITTLEBUF] = {0};
	memset(buf, 0, sizeof(buf));
	/* 获取探针状态 */
	FILE *fp = popen("pidof cscan | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	fgets(buf, sizeof(buf), fp);
	pclose(fp);
	if (strlen(buf))
		*stat = 0;
	else
		*stat = 1;
}

#if 1
int process_check_state(const char *ProcessName)
{
	int stat = 0;
	char buf[LITTLEBUF] = {0};
	memset(buf, 0, sizeof(buf));
	sprintf(buf, "pidof %s | tr -d '\n'", ProcessName);
	FILE *fp = popen(buf, "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return 0;
	}

	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	pclose(fp);
	if (strlen(buf))
		stat = 1;

	return stat;
}

static void get_jiffies(char *data_time)
{
	struct timeval tv;
	char time[20] = {0};
	char *p = NULL;

	gettimeofday(&tv, NULL);

	sprintf(time, "%ld%03ld", tv.tv_sec, tv.tv_usec / 1000);

	p = time;
	while (*p) *data_time++ = *p++;
}

/* uwb stat 0/1/2/3*/
void get_uwb_stat(unsigned long *stat)
{
	char buf[128] = {0};
	FILE *fp = NULL;
	char jiffies_buf[20] = {0};

	/* uwb disabled */
	fp = popen("uci get uwbcon.con.disabled 2>/dev/null | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	pclose(fp);

	if (0 == strcmp(buf, "1"))
	{
		*stat = 1;
		return;
	}

	/* tty is ok */
	/* get tty port */
	fp = popen("uci get uwbcon.con.tty 2>/dev/null | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	pclose(fp);

	if (strlen(buf) > 1)
	{
		if ((access(buf, F_OK)) != 0)
		{
			*stat = 3;
			return;
		}
	}
	else
	{
		*stat = 3;
		return;
	}

	/* uwb data is ok */
	/* get uwb data jiffies */
	memset(buf, 0, sizeof(buf));
	sprintf(buf, "cat %s 2>/dev/null | tr -d '\n'", UWB_JIFFIES);
	fp = popen(buf, "r");
	if (fp == NULL)
	{
		log_e("popen error");
		*stat = 2;
		return;
	}

	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	pclose(fp);

	if (strlen(buf) > 1)
	{
		/*get current jiffies*/
		memset(jiffies_buf, 0, sizeof(jiffies_buf));
		get_jiffies(jiffies_buf);
		// log_i("cur_time %s, uwb_time %s", jiffies_buf, buf);
		if ((strtoull(jiffies_buf, (char **)NULL, 10) - strtoull(buf, (char **)NULL, 10))
			> 3 * 60 * 1000) // 3min = 3*60*1000 ms
		{
			*stat = 2;
			return;
		}
	}
	else
	{
		*stat = 2;
		return;
	}

	/* uwb is ok */
	*stat = 0;
	return;
}

void get_blue_stat(unsigned long *stat)
{
	char buf[LITTLEBUF] = {0};
	FILE *fp = NULL;
	// schar jiffies_buf[20] = {0};

	/* blue disabled */
	fp = popen("uci get blconfig.con.disabled 2>/dev/null | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	pclose(fp);

	if (0 == strcmp(buf, "1"))
	{
		*stat = 1;
		return;
	}

	/* tty is ok */
	/* get tty port */
	fp = popen("uci get blconfig.con.tty 2>/dev/null | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	pclose(fp);

	if (strlen(buf) > 1)
	{
		if ((access(buf, F_OK)) != 0)
		{
			*stat = 3;
			return;
		}
	}
	else
	{
		*stat = 3;
		return;
	}

	/* blue is ok */
	*stat = 0;
	return;
}

void get_433_stat(unsigned long *stat)
{
	char buf[LITTLEBUF] = {0};
	FILE *fp = NULL;
	// schar jiffies_buf[20] = {0};

	/* blue disabled */
	fp = popen("uci get 433Mcon.con.disabled 2>/dev/null | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	pclose(fp);

	if (0 == strcmp(buf, "1"))
	{
		*stat = 1;
		return;
	}

	/* tty is ok */
	/* get tty port */
	fp = popen("uci get 433Mcon.con.tty 2>/dev/null | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	pclose(fp);

	if (strlen(buf) > 1)
	{
		if ((access(buf, F_OK)) != 0)
		{
			*stat = 3;
			return;
		}
	}
	else
	{
		*stat = 3;
		return;
	}

	*stat = 0;
	return;
}

void get_alarm_state(unsigned long *stat)
{
	char buf[256] = {0};
	FILE *fp = NULL;

	/* alarm disabled */
	fp = popen("uci get alarm.main.disabled 2>/dev/null | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	pclose(fp);

	if (0 == strcmp(buf, "1"))
	{
		*stat = 1;
		return;
	}

	/* get alarm_services state */
	memset(buf, 0, sizeof(buf));
	sprintf(buf, "cat %s 2>/dev/null | tr -d '\n'", ALARM_STATE);
	fp = popen(buf, "r");
	if (fp == NULL)
	{
		log_e("popen error");
		*stat = 2;
		return;
	}

	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	pclose(fp);

	if (strlen(buf) > 0)
	{
		if (strcmp(buf, "1"))
		{
			*stat = 3;
			return;
		}
	}
	else
	{
		*stat = 2;
		return;
	}

	/* alarm state is ok */
	*stat = 0;

	return;
}

void get_uwb_realinfo(void *uwbinfo)
{
	char buf[LITTLEBUF] = {0};
	FILE *fp = NULL;

	UWBINFO *uwb_info = (UWBINFO *)uwbinfo;
	memset(uwb_info, 0, sizeof(UWBINFO));

	/*/tmp/matid*/
	fp = popen("cat /tmp/uwb_matid 2>/dev/null | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
	}
	else
	{
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf), fp);
		pclose(fp);
		if (strlen(buf) < 1)
		{
			snprintf(uwb_info->matid, sizeof(uwb_info->matid), "0");
		}
		else
		{
			snprintf(uwb_info->matid, sizeof(uwb_info->matid), "%s", buf);
		}
	}

	/*/tmp/localid*/
	fp = popen("cat /tmp/uwb_localid 2>/dev/null | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
	}
	else
	{
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf), fp);
		pclose(fp);
		if (strlen(buf) < 1)
		{
			snprintf(uwb_info->localid, sizeof(uwb_info->localid), "0");
		}
		else
		{
			snprintf(uwb_info->localid, sizeof(uwb_info->localid), "%s", buf);
		}
	}

	/*/tmp/uwb/uwb_runtime*/
	fp = popen("cat /tmp/uwb_runtime 2>/dev/null | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
	}
	else
	{
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf), fp);
		pclose(fp);
		if (strlen(buf) < 1)
		{
			snprintf(uwb_info->runtime, sizeof(uwb_info->runtime), "0");
		}
		else
		{
			snprintf(uwb_info->runtime, sizeof(uwb_info->runtime), "%s", buf);
		}
	}

	/*/tmp/uwb/uwb_payload*/
	fp = popen("cat /tmp/uwb_payload 2>/dev/null | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
	}
	else
	{
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf), fp);
		pclose(fp);
		if (strlen(buf) < 1)
		{
			snprintf(uwb_info->payload, sizeof(uwb_info->payload), "0");
		}
		else
		{
			snprintf(uwb_info->payload, sizeof(uwb_info->payload), "%s", buf);
		}
	}

	/*/tmp/uwb_upgrade*/
	fp = popen("cat /tmp/uwb_upgrade 2>/dev/null | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		snprintf(uwb_info->upgrade, sizeof(uwb_info->upgrade), "%d", 0);
	}
	else
	{
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf), fp);
		pclose(fp);
		if (strlen(buf) < 1)
		{
			snprintf(uwb_info->upgrade, sizeof(uwb_info->upgrade), "%d", 0);
		}
		else
		{
			snprintf(uwb_info->upgrade, sizeof(uwb_info->upgrade), "%s", buf);
		}
	}

	/*/tmp/uwb_version*/
	fp = popen("cat /tmp/uwb_version 2>/dev/null | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		snprintf(uwb_info->uwbversion, sizeof(uwb_info->uwbversion), "unknown");
	}
	else
	{
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf), fp);
		pclose(fp);

		if (strlen(buf) < 1)
		{
			snprintf(uwb_info->uwbversion, sizeof(uwb_info->uwbversion), "unknown");
		}
		else
		{
			snprintf(uwb_info->uwbversion, sizeof(uwb_info->uwbversion), "%s", buf);
		}
	}

	return;
}

#endif

void get_info(char *hwtype, char *systemtype, char *systemversion)
{
	/* 获取hwtype，systemtype， systemversion */
	FILE *fp = popen("cat /etc/info", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	fgets(hwtype, LITTLEBUF, fp);
	fgets(systemtype, LITTLEBUF, fp);
	fgets(systemversion, LITTLEBUF, fp);
	hwtype[strlen(hwtype) - 1] = '\0';
	systemtype[strlen(systemtype) - 1] = '\0';
	systemversion[strlen(systemversion) - 1] = '\0';
	pclose(fp);

	getGet(systemtype, "uci -q get version.main_version.sys_version | tr -d '\n'", 32);
}

void get_time(unsigned long *cpuruntime, unsigned long *freetime)
{
	char buf[LITTLEBUF] = {0}, time1[LITTLEBUF] = {0}, time2[LITTLEBUF] = {0};
	/* 获取运行时间，空闲时间 */
	FILE *fp = popen("cat /proc/uptime", "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	fgets(buf, sizeof(buf), fp);
	pclose(fp);
	sscanf(buf, "%[^ ] %s", time1, time2);
	*cpuruntime = (unsigned long)atoi(time1);
	*freetime = (unsigned long)atoi(time2);
}

/***************************************************
 *函数名：
 *        md5key
 *函数功能：
 *        该函数按照给定的格式产生相应的MD5值
 *函数参数：
 *         key是指向用来存储最后产生的key值得内存空间，
 *注释：key所指向的内存空间必须大于32个字节的内存空间
 ***************************************************/
void md5key(char *key, void *data)
{
	char buf[256] = {0}, cmd_sh[256] = {0};
	sprintf(cmd_sh, "echo -n %d | md5sum | awk '{print $1}' | tr -d '\n'", (int)data);
	FILE *fp = popen(cmd_sh, "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	fgets(buf, sizeof(buf), fp);
	pclose(fp);

	sprintf(cmd_sh, "echo -n 'airocov178%s' | md5sum | awk '{print $1}' | tr -d '\n'", buf);
	fp = popen(cmd_sh, "r");
	if (fp == NULL)
	{
		log_e("popen error");
		return;
	}
	fgets(key, sizeof(buf), fp);
	pclose(fp);
}

int check_key(char *key)
{
	int timestamp = (int)time(NULL);
	char mkey[256] = {0};
	md5key(mkey, (void *)(timestamp / 60));
	if (!strncmp(key, mkey, 32))
	{
		// log_i("%s", mkey);
		return 0;
	}
	md5key(mkey, (void *)((timestamp / 60) - 1));
	if (!strncmp(key, mkey, 32))
	{
		// log_i("%s", mkey);
		return 0;
	}
	md5key(mkey, (void *)((timestamp / 60) + 1));
	if (!strncmp(key, mkey, 32))
	{
		// log_i("%s", mkey);
		return 0;
	}
	return 1;
}

/*************************************************
 *函数名：
 *        data_init
 *函数功能：
 *        该函数仅对心跳的一些全局变量进行初始化
 ************************************************/
void data_init(int type)
{
	char buf[64] = {0};
	/* 获取mac地址 */
	get_mac(apmac);

	/* 获取内网ip地址 */
lan:
	get_lan_ip(lanip);
	if (!strlen(lanip))
	{
		sleep(3);
		goto lan;
	}

	/*get ap type and version*/
gettype:
	get_ap_type(ap_type);
	if (!strlen(ap_type))
	{
		sleep(3);
		goto gettype;
	}

	get_ap_version(ap_version);

	get_dimension(&devdimension);

	/* 获取ssid */
	get_ssid(ssid);
	/* 获取channel */
	get_channel(&channel);
	get_probe_stat(&probestat);

	get_uwb_stat(&uwbstat);

	memset(buf, 0, sizeof(buf));
	sprintf(buf, "echo %lu > %s/uwb", uwbstat, STATUS_PATH);
	system(buf);

	get_blue_stat(&bluestat);

	memset(buf, 0, sizeof(buf));
	sprintf(buf, "echo %lu > %s/blue", bluestat, STATUS_PATH);
	system(buf);

	get_433_stat(&wireless433stat);

	get_alarm_state(&alarmstate);

	/* 获取hwtype，systemtype， systemversion */
	// get_info(hwtype, systemtype, systemversion);

	/*get uwb real info*/
	get_uwb_realinfo(&_uwbinfo);

	/* 获取运行时间，空闲时间 */
	get_time(&cpuruntime, &freetime);

	starttime = (unsigned long)time(NULL) - cpuruntime;
}

/********************************************
 *函数名：env_check
 *函数功能：
 *            该函数实现对网络环境的检测
 *返回值：
 *             0:表示网络通畅
 *            !0:表示网络不畅通
 ********************************************/
int env_check(char *ip)
{
	int ret = 0;
	char buf[4] = {0};
	char cmd[256] = {0};
	sprintf(cmd, "if ping -c 1 -W 3 %s >/dev/null 2>&1;then echo 1;else echo 0; fi", ip);
	getGet(buf, cmd, sizeof(buf));
	ret = atoi(buf);
	return ret;
}

int get_radionumber(void)
{
	char buf[4] = {0};
	int ret = 0;
	ret = getGet(buf, "uci show wireless | grep =wifi-device | wc -l | tr -d '\n'", sizeof(buf));
	if (ret < 0)
	{
		log_e("get radio number error.");
		return -1;
	}
	return atoi(buf);
}

void get_txpower(const char *radio, cJSON *item)
{
	char cmd[256] = {0};
	char buf[4] = {0};
	sprintf(cmd, "uci -q get wireless.%s.txpower | tr -d '\n'", radio);
	getGet(buf, cmd, sizeof(buf));
	cJSON_AddStringToObject(item, "txpower", buf);
}

void get_radio_channel(const char *radio, cJSON *item)
{
	char cmd[256] = {0};
	char buf[4] = {0};
	sprintf(cmd, "uci -q get wireless.%s.channel | tr -d '\n'", radio);
	getGet(buf, cmd, sizeof(buf));
	cJSON_AddStringToObject(item, "channel", buf);
}

void get_radio_hwmode(const char *radio, cJSON *item)
{
	char cmd[256] = {0};
	char buf[4] = {0};
	sprintf(cmd, "uci -q get wireless.%s.hwmode | tr -d '\n'", radio);
	getGet(buf, cmd, sizeof(buf));
	cJSON_AddStringToObject(item, "hwmode", buf);
}

void get_radio_htmode(const char *radio, cJSON *item)
{
	char cmd[256] = {0};
	char buf[4] = {0};
	sprintf(cmd, "uci -q get wireless.%s.htmode | tr -d '\n'", radio);
	getGet(buf, cmd, sizeof(buf));
	cJSON_AddStringToObject(item, "htmode", buf);
}

int get_radio_ssidnum(const char *radio)
{
	char cmd[256] = {0};
	char buf[4] = {0};
	sprintf(cmd, "uci show wireless | grep device=\'\%s\'  | wc -l | tr -d '\n'", radio);
	getGet(buf, cmd, sizeof(buf));
	return atoi(buf);
}

void get_radio_ssidc(const char *radio, cJSON *item)
{
	cJSON_AddNumberToObject(item, "ssidc", get_radio_ssidnum(radio));
}

int getRadioDisabled(const char *radio)
{
	char cmd[256] = {0};
	char buf[4] = {0};
	sprintf(cmd, "uci -q get wireless.%s.disabled | tr -d '\n'", radio);
	getGet(buf, cmd, sizeof(buf));
	return atoi(buf);
}

void get_radio_disabled(const char *radio, cJSON *item)
{
	int disabled = getRadioDisabled(radio);
	cJSON_AddNumberToObject(item, "disabled", disabled);
}

void get_wireless_heart(const char *radio, cJSON *item)
{
	get_txpower(radio, item);
	get_radio_channel(radio, item);
	get_radio_hwmode(radio, item);
	get_radio_htmode(radio, item);
	get_radio_ssidc(radio, item);
}

void get_radio(const char *radio, cJSON *wireless)
{
	cJSON *object = cJSON_CreateObject();
	cJSON *item = cJSON_CreateObject();
	cJSON_AddItemToObject(object, radio, item);
	cJSON_AddItemToArray(wireless, object);

	get_wireless_heart(radio, item);
}

void get_wireless(cJSON *wireless)
{
	int num, i;
	char radio[8] = {0};
	num = get_radionumber();
	for (i = 0; i < num; i++)
	{
		sprintf(radio, "radio%d", i);
		get_radio(radio, wireless);
	}
}

/********************************************
 *函数名：heart_init
 *函数功能
 *            该函数实现对心跳的初始化
 *返回值：
 *            函数返回一个已经初始化好的cJSON对象的指针
 *********************************************/
cJSON *heart_init(const int systype)
{
	cJSON *heart = cJSON_CreateObject();
	cJSON_AddStringToObject(heart, "lanip", lanip);

	cJSON_AddStringToObject(heart, "aptype", ap_type);
	cJSON_AddStringToObject(heart, "apversion", ap_version);

	if (systype == FIT)
	{
		cJSON_AddNumberToObject(heart, "probestat", probestat);
	}

	cJSON_AddNumberToObject(heart, "uwbstat", uwbstat);
	cJSON_AddNumberToObject(heart, "alarmstate", alarmstate);
	cJSON_AddNumberToObject(heart, "bluestat", bluestat);
	cJSON_AddNumberToObject(heart, "433stat", wireless433stat);
	cJSON_AddNumberToObject(heart, "devnumbers", devnumbers);
	cJSON_AddNumberToObject(heart, "freetime", freetime);
	cJSON_AddNumberToObject(heart, "cpuruntime", cpuruntime);
	cJSON_AddNumberToObject(heart, "devmode", systype - 1);
	cJSON_AddStringToObject(heart, "version", "ac_new_v2.0");
	cJSON_AddNumberToObject(heart, "dimension", devdimension);

	/*add uwb info*/
	cJSON *uwb_json = cJSON_CreateObject();
	cJSON_AddItemToObject(heart, "uwbinfo", uwb_json);
	UWBINFO *uwb_info = (UWBINFO *)&_uwbinfo;
	cJSON_AddStringToObject(uwb_json, "matid", uwb_info->matid);
	cJSON_AddStringToObject(uwb_json, "localid", uwb_info->localid);
	cJSON_AddStringToObject(uwb_json, "runtime", uwb_info->runtime);
	cJSON_AddStringToObject(uwb_json, "payload", uwb_info->payload);
	cJSON_AddStringToObject(uwb_json, "upgrade", uwb_info->upgrade);
	cJSON_AddStringToObject(uwb_json, "uwbversion", uwb_info->uwbversion);

	return heart;
}

/********************************************
 *函数名：server_check
 *函数功能：
 *            该函数实现对服务器功能的检测，务器是否在正常工作
 *返回值：
 *             0:表示服务器工作正常
 *            !0:表示服务器故障
 ********************************************/
int server_check(const char *cloudinterface, const int encryption, const char *mac, int type)
{
	char buf[BUFSIZE] = {0}, key[256] = {0};
	char url[BUFSIZE] = {0};
	cJSON *ret = NULL, *tmp = NULL;
	int curl_ret = 0;

	md5key(key, (void *)(time(NULL) / 60));
	sprintf(url, "%s/checkacserver?apmac=%s&key=%s&type=check&version=%d", cloudinterface, mac, key, type);
	log_i("%s", url);
	memset(buf, 0, sizeof(buf));
	curl_ret = curl_request(url, GET, NULL, buf);

	if (curl_ret < 0)
	{
		goto err;
	}

	log_i("return: %s", buf);
	if (strlen(buf) == 0)
		goto err;

	ret = cJSON_Parse(buf);
	if (ret == NULL)
		goto err;

	if (cJSON_GetObjectItem(ret, ERRORCODE) == NULL || cJSON_GetObjectItem(ret, "key") == NULL)
	{
		log_e("return not find key or code !");
		goto err;
	}

	tmp = cJSON_GetObjectItem(ret, "key");
	if (!check_key(tmp->valuestring))
	{
		tmp = cJSON_GetObjectItem(ret, ERRORCODE);
		if (tmp->valueint == 200)
		{
			// tmp = cJSON_GetObjectItem(ret, DESCRIPTION);
			cJSON_Delete(ret);
			return 0;
		}
		// tmp = cJSON_GetObjectItem(ret, DESCRIPTION);
		// log_i("description: %s", tmp->valuestring);
		log_d("error code: %d", tmp->valueint);
		cJSON_Delete(ret);
		// get_mac(apmac);
		goto err;
	}
	cJSON_Delete(ret);
	system("acscript cmdtime");
	log_e("The key check failed");

err:
	sleep(10);
	return -1;
}

/********************************************************
 *函数名：
 *        heart_update
 *函数功能：
 *        更新心跳
 *函数参数：
 *        heart是指向心跳的cJSON对象的指针
 ********************************************************/
static void heart_update(cJSON *heart)
{
	char buf[64] = {0};
	cJSON *tmp = NULL;

	/*update new lanip*/
	get_lan_ip(lanip);

	/* 获取运行时间，空闲时间 */
	get_time(&cpuruntime, &freetime);

	/* 获取探针状态 */
	get_probe_stat(&probestat);

	/*get uwb blue stat */
	get_uwb_stat(&uwbstat);

	memset(buf, 0, sizeof(buf));
	sprintf(buf, "echo %lu > %s/uwb", uwbstat, STATUS_PATH);
	system(buf);
	// log_i("uwbstat %ld", uwbstat);
	get_blue_stat(&bluestat);

	memset(buf, 0, sizeof(buf));
	sprintf(buf, "echo %lu > %s/blue", bluestat, STATUS_PATH);
	system(buf);

	get_433_stat(&wireless433stat);

	get_alarm_state(&alarmstate);

	tmp = cJSON_GetObjectItem(heart, "lanip");
	strcpy(tmp->valuestring, lanip);

	cJSON_SetNumberValue(cJSON_GetObjectItem(heart, "probestat"), probestat);
	cJSON_SetNumberValue(cJSON_GetObjectItem(heart, "uwbstat"), uwbstat);
	cJSON_SetNumberValue(cJSON_GetObjectItem(heart, "bluestat"), bluestat);
	cJSON_SetNumberValue(cJSON_GetObjectItem(heart, "433stat"), wireless433stat);
	cJSON_SetNumberValue(cJSON_GetObjectItem(heart, "alarmstate"), alarmstate);
	cJSON_SetNumberValue(cJSON_GetObjectItem(heart, "devnumbers"), devnumbers);
	cJSON_SetNumberValue(cJSON_GetObjectItem(heart, "cpuruntime"), cpuruntime);
	cJSON_SetNumberValue(cJSON_GetObjectItem(heart, "freetime"), freetime);
	cJSON_SetNumberValue(cJSON_GetObjectItem(heart, "dimension"), devdimension);

	get_uwb_realinfo(&_uwbinfo);
	UWBINFO *uwb_info = (UWBINFO *)&_uwbinfo;
	/*update uwb info*/
	cJSON *uwb_json = cJSON_GetObjectItem(heart, "uwbinfo");
	cJSON_DeleteItemFromObject(uwb_json, "matid");
	cJSON_DeleteItemFromObject(uwb_json, "localid");
	cJSON_DeleteItemFromObject(uwb_json, "runtime");
	cJSON_DeleteItemFromObject(uwb_json, "payload");
	cJSON_DeleteItemFromObject(uwb_json, "upgrade");
	cJSON_DeleteItemFromObject(uwb_json, "uwbversion");

	cJSON_AddStringToObject(uwb_json, "matid", uwb_info->matid);
	cJSON_AddStringToObject(uwb_json, "localid", uwb_info->localid);
	cJSON_AddStringToObject(uwb_json, "runtime", uwb_info->runtime);
	cJSON_AddStringToObject(uwb_json, "payload", uwb_info->payload);
	cJSON_AddStringToObject(uwb_json, "upgrade", uwb_info->upgrade);
	cJSON_AddStringToObject(uwb_json, "uwbversion", uwb_info->uwbversion);
}

/********************************************
 *函数名：heart_up
 *函数功能：
 *            该函数实现向服务器上报心跳
 *函数参数：cJSON *heart, heart 代表已经初始化完成的心跳的cJSON对象的首地址
 *返回值：
 *            cJSON * ,表示返回值是上报心跳成功后，服务器返回的cJSON对象的首地址
 *            返回cJSON格式：{errorcode:1/-1,description:fail/success,\
 *            cmdtype:generate/netconf, cmdurl:http//:ac.airocov.com, cmd:upgradesystem}
 *
 ********************************************/
cJSON *heart_up(const char *cloudinterface, const int encryption, cJSON *heart, const char *mac)
{
	cJSON *ret = NULL;
	int curl_ret = 0;
	char key[256] = {0}, url[BUFSIZE] = {0};
	char buf[BUFSIZE] = {0}, mdata[BUFSIZE] = {0};

	heart_update(heart);
	char *s_heart = cJSON_PrintUnformatted(heart);
	log_i("heart_up data [%s]", s_heart);

	md5key(key, (void *)(time(NULL) / 60));
	sprintf(url, "%s/heart?apmac=%s&key=%s&type=heart", cloudinterface, mac, key);
	sprintf(mdata, "data=%s\n", s_heart);
	curl_ret = curl_request(url, POST, mdata, buf);
	free(s_heart);

	/*
	char *tmp = NULL;
	if ((tmp = strstr(buf, "\n")))
		*tmp = '\0';
	if ((tmp = strstr(buf, "\r")))
		*tmp = '\0';
	*/
	log_i("return: %s", buf);
	if (curl_ret < 0 || strlen(buf) == 0)
	{
		ret = NULL;
	}
	else
	{
		ret = cJSON_Parse(buf);
		if (ret == NULL)
		{
			log_e("json parse error");
		}
	}

	return ret;
}

int result_up(const char *cloudinterface, const int encryption, char *data, const char *mac)
{
	char key[256] = {0};
	char url[512] = {0};
	char buf[BUFSIZE] = {0}, mdata[BUFSIZE] = {0};
	int i = 10;
	int ret = -1;

	while (i > 0)
	{
		i--;
		md5key(key, (void *)(time(NULL) / 60));
		sprintf(url, "%s/judge?apmac=%s&result=1&key=%s&type=setval", cloudinterface, mac, key);
		// log_i("%s", url);
		log_i("result_up: %s", data);
		sprintf(mdata, "data=%s", data);
		curl_request(url, POST, mdata, buf);
		log_i("return: %s", buf);
		if (strlen(buf) == 0)
		{
			continue;
		}
		else
		{
			ret = 0;
			break;
		}
	}

	return ret;
}

/*********************************************
 *函数名：
 *        *_conf
 *函数功能：
 *        *_conf函数组，按照由服务器获得的配置参数对路由器进行配置
 ********************************************/
static void netowrk_interface_section(FILE *fp, cJSON *root)
{
	if (!root)
		return;
	cJSON *tmp = NULL;
	char *type = NULL;
	char *name = NULL;
	/*int number = 0;*/
	char buf[1024] = {0};
	tmp = cJSON_GetObjectItem(root, "section_type");
	if (!tmp || tmp->type != cJSON_String || strcmp("interface", tmp->valuestring))
		return;
	type = tmp->valuestring;

	tmp = cJSON_GetObjectItem(root, "section_name");
	if (!tmp || tmp->type != cJSON_String || !strcmp("loopback", tmp->valuestring))
		return;
	name = tmp->valuestring;

	if (!name || !type)
		return;

	tmp = cJSON_GetObjectItem(root, "action");
	if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
	{
		if (!strcmp("new", tmp->valuestring))
		{
			fputs("uci add network interface\n", fp);
			sprintf(buf, "uci rename network.@interface[%d]=%s\n", interface_num++, name);
			fputs(buf, fp);
		}
		else if (!strcmp("del", tmp->valuestring))
		{
			sprintf(buf, "uci delete network.%s\n", name);
			fputs(buf, fp);
			interface_num--;
			return;
		}
	}

	tmp = cJSON_GetObjectItem(root, "ifname");
	if (tmp && tmp->type == cJSON_String)
	{
		sprintf(buf, "uci set network.%s.ifname='%s'\n", name, tmp->valuestring);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "proto");
	if (tmp && tmp->type == cJSON_String)
	{
		sprintf(buf, "uci set network.%s.proto='%s'\n", name, tmp->valuestring);
		fputs(buf, fp);
		if (strcmp(tmp->valuestring, "dhcp"))
		{
			sprintf(buf, "uci set network.%s.ipaddr=\n", name);
			fputs(buf, fp);
			sprintf(buf, "uci set network.%s.netmask=\n", name);
			fputs(buf, fp);
			sprintf(buf, "uci set network.%s.gateway=\n", name);
			fputs(buf, fp);
			sprintf(buf, "uci set network.%s.dns=\n", name);
			fputs(buf, fp);
		}
	}

	tmp = cJSON_GetObjectItem(root, "ipaddr");
	if (tmp && tmp->type == cJSON_String)
	{
		sprintf(buf, "uci set network.%s.ipaddr='%s'\n", name, tmp->valuestring);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "netmask");
	if (tmp && tmp->type == cJSON_String)
	{
		sprintf(buf, "uci set network.%s.netmask='%s'\n", name, tmp->valuestring);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "gateway");
	if (tmp && tmp->type == cJSON_String)
	{
		sprintf(buf, "uci set network.%s.gateway='%s'\n", name, tmp->valuestring);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "dns");
	if (tmp && tmp->type == cJSON_String)
	{
		sprintf(buf, "uci set network.%s.dns='%s'\n", name, tmp->valuestring);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "metric");
	if (tmp && tmp->type == cJSON_String)
	{
		sprintf(buf, "uci set network.%s.metric='%s'\n", name, tmp->valuestring);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "type");
	if (tmp && tmp->type == cJSON_String)
	{
		sprintf(buf, "uci set network.%s.type='%s'\n", name, tmp->valuestring);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "metric");
	if (tmp)
	{
		if (tmp->type == cJSON_String)
		{
			sprintf(buf, "uci set network.%s.metric='%s'\n", name, tmp->valuestring);
			fputs(buf, fp);
		}
		else if (tmp->type == cJSON_Number)
		{
			sprintf(buf, "uci set network.%s.metric='%d'\n", name, tmp->valueint);
			fputs(buf, fp);
		}
	}
}

static void netowrk_interface(FILE *fp, cJSON *root, int n)
{
	int i;
	delc = 0;
	cJSON *tmp = NULL;
	if (root)
		for (i = 0; i < n; i++)
		{
			tmp = cJSON_GetArrayItem(root, i);
			if (tmp)
				netowrk_interface_section(fp, tmp);
		}
}

static void network_switch_vlan_section(FILE *fp, cJSON *root)
{
	if (!root || !fp)
		return;
	cJSON *tmp = NULL;
	/*char *type = NULL;*/
	int number = 0;
	char buf[1024] = {0};
	tmp = cJSON_GetObjectItem(root, "section_type");
	if (!tmp || tmp->type != cJSON_String || strcmp("switch_vlan", tmp->valuestring))
		return;
	/*type = tmp->valuestring;*/

	tmp = cJSON_GetObjectItem(root, "section_number");
	if (!tmp)
		return;
	if (tmp->type == cJSON_String)
		number = atoi(tmp->valuestring) - delc;
	else if (tmp->type == cJSON_Number)
		number = tmp->valueint - delc;
	else
		return;

	tmp = cJSON_GetObjectItem(root, "action");
	if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
	{
		if (!strcmp(tmp->valuestring, "new"))
		{
			fputs("uci add network switch_vlan\n", fp);
			number = switch_vlan_num++;
		}
		else if (!strcmp(tmp->valuestring, "del"))
		{
			sprintf(buf, "uci delete wireless.@switch_vlan[%d]\n", number);
			fputs(buf, fp);
			switch_vlan_num--;
			delc++;
			return;
		}
	}

	tmp = cJSON_GetObjectItem(root, "device");
	if (tmp && tmp->type == cJSON_String)
	{
		sprintf(buf, "uci set network.@switch_vlan[%d].device='%s'\n", number, tmp->valuestring);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "vlan");
	if (tmp)
	{
		if (tmp->type == cJSON_String)
		{
			sprintf(buf, "uci set network.@switch_vlan[%d].vlan='%s'\n", number, tmp->valuestring);
			fputs(buf, fp);
		}
		else if (tmp->type == cJSON_Number)
		{
			sprintf(buf, "uci set network.@switch_vlan[%d].vlan='%d'\n", number, tmp->valueint);
			fputs(buf, fp);
		}
	}

	tmp = cJSON_GetObjectItem(root, "ports");
	if (tmp && tmp->type == cJSON_String)
	{
		sprintf(buf, "uci set network.@switch_vlan[%d].ports='%s'\n", number, tmp->valuestring);
		fputs(buf, fp);
	}
}

static void network_switch_vlan(FILE *fp, cJSON *root, int n)
{
	int i;
	cJSON *tmp = NULL;
	delc = 0;
	if (root)
		for (i = 0; i < n; i++)
		{
			tmp = cJSON_GetArrayItem(root, i);
			if (tmp)
				network_switch_vlan_section(fp, tmp);
		}
}

static void network_conf(FILE *fp, cJSON *root)
{
	if (!root)
		return;

	cJSON *interface = NULL;
	cJSON *switch_vlan = NULL;

	fputs("###config network\n", fp);

	interface = cJSON_GetObjectItem(root, "interface");
	switch_vlan = cJSON_GetObjectItem(root, "switch_vlan");

	if (interface && interface->type == cJSON_Array)
		netowrk_interface(fp, interface, cJSON_GetArraySize(interface));
	if (switch_vlan && switch_vlan->type == cJSON_Array)
		network_switch_vlan(fp, switch_vlan, cJSON_GetArraySize(switch_vlan));

	fputs("uci commit network\n/etc/init.d/network restart &\n", fp);
}

static void wifi_device_section(FILE *fp, cJSON *root)
{
	if (!root)
		return;
	cJSON *tmp = NULL;
	/*int number = 0;*/
	char *name = NULL;
	char *type = NULL;
	char buf[1024] = {0};

	tmp = cJSON_GetObjectItem(root, "section_name");
	if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
		name = tmp->valuestring;

	tmp = cJSON_GetObjectItem(root, "section_type");
	if (tmp && tmp->type == cJSON_String && !strcmp("wifi-device", tmp->valuestring))
		type = tmp->valuestring;

	if (!name || !type)
		return;

	tmp = cJSON_GetObjectItem(root, "channel");
	if (tmp)
	{
		if (tmp->type == cJSON_String && strlen(tmp->valuestring))
			sprintf(buf, "uci set wireless.%s.channel='%s'\n", name, tmp->valuestring);
		else if (tmp->type == cJSON_Number)
			sprintf(buf, "uci set wireless.%s.channel='%d'\n", name, tmp->valueint);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "hwmode");
	if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
	{
		sprintf(buf, "uci set wireless.%s.hwmode='%s'\n", name, tmp->valuestring);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "htmode");
	if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
	{
		sprintf(buf, "uci set wireless.%s.htmode='%s'\n", name, tmp->valuestring);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "disabled");
	if (tmp)
	{
		if (tmp->type == cJSON_String && strlen(tmp->valuestring))
			sprintf(buf, "uci set wireless.%s.disabled='%s'\n", name, tmp->valuestring);
		else if (tmp->type == cJSON_Number)
			sprintf(buf, "uci set wireless.%s.disabled='%d'\n", name, tmp->valueint);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "txpower");
	if (tmp)
	{
		if (tmp->type == cJSON_String && strlen(tmp->valuestring))
			sprintf(buf, "uci set wireless.%s.txpower='%s'\n", name, tmp->valuestring);
		else if (tmp->type == cJSON_Number)
			sprintf(buf, "uci set wireless.%s.txpower='%d'\n", name, tmp->valueint);
		fputs(buf, fp);
	}
}

static void wireless_wifi_device(FILE *fp, cJSON *root, int n)
{
	cJSON *tmp = NULL;
	int i;
	if (!root)
		return;
	for (i = 0; i < n; i++)
	{
		tmp = cJSON_GetArrayItem(root, i);
		if (!tmp)
			continue;
		wifi_device_section(fp, tmp);
	}
}

static void wifi_iface_section(FILE *fp, cJSON *root)
{
	if (!root)
		return;
	cJSON *tmp = NULL;
	int number = 0;
	/*char *name = NULL;*/
	char *type = NULL;
	char buf[1024] = {0};

	tmp = cJSON_GetObjectItem(root, "section_number");
	if (tmp)
	{
		if (tmp->type == cJSON_Number)
			number = tmp->valueint - delc;
		else if (tmp->type == cJSON_String && strlen(tmp->valuestring))
			number = atoi(tmp->valuestring) - delc;
	}
	/*    tmp = cJSON_GetObjectItem(root, "section_name");
		if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
			name = tmp->valuestring;*/

	tmp = cJSON_GetObjectItem(root, "section_type");
	if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
		type = tmp->valuestring;

	if (!type)
		return;

	tmp = cJSON_GetObjectItem(root, "action");
	if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
	{
		if (!strcmp(tmp->valuestring, "new"))
		{
			fputs("uci add wireless wifi-iface\n", fp);
			log_i("uci add wireless wifi-iface");
			number = wifi_iface_num++;
		}
		else if (!strcmp(tmp->valuestring, "del"))
		{
			sprintf(buf, "uci delete wireless.@wifi-iface[%d]\n", number);
			log_i("uci delete wireless.@wifi-iface[%d]", number);
			fputs(buf, fp);
			wifi_iface_num--;
			delc++;
			return;
		}
	}

	tmp = cJSON_GetObjectItem(root, "network");
	if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
	{
		sprintf(buf, "uci -q set wireless.@wifi-iface[%d].network='%s'\n", number, tmp->valuestring);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "ssid");
	if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
	{
		sprintf(buf, "uci -q set wireless.@wifi-iface[%d].ssid='%s'\n", number, tmp->valuestring);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "device");
	if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
	{
		sprintf(buf, "uci -q set wireless.@wifi-iface[%d].device='%s'\n", number, tmp->valuestring);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "mode");
	if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
	{
		sprintf(buf, "uci -q set wireless.@wifi-iface[%d].mode='%s'\n", number, tmp->valuestring);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "disabled");
	if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
	{
		sprintf(buf, "uci -q set wireless.@wifi-iface[%d].disabled='%s'\n", number, tmp->valuestring);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "hidden");
	if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
	{
		sprintf(buf, "uci -q set wireless.@wifi-iface[%d].hidden='%s'\n", number, tmp->valuestring);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "isolate");
	if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
	{
		sprintf(buf, "uci -q set wireless.@wifi-iface[%d].isolate='%s'\n", number, tmp->valuestring);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "maxassoc");
	if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
	{
		sprintf(buf, "uci -q set wireless.@wifi-iface[%d].maxassoc='%s'\n", number, tmp->valuestring);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "encryption");
	if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
	{
		sprintf(buf, "uci -q set wireless.@wifi-iface[%d].encryption='%s'\n", number, tmp->valuestring);
		fputs(buf, fp);

		if (strcmp(tmp->valuestring, "none") && strncmp(tmp->valuestring, "wpa", 3))
		{
			tmp = cJSON_GetObjectItem(root, "key");
			if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
			{
				sprintf(buf, "uci -q set wireless.@wifi-iface[%d].key='%s'\n", number, tmp->valuestring);
				fputs(buf, fp);
			}
			sprintf(buf, "uci -q set wireless.@wifi-iface[%d].auth_server=\n", number);
			fputs(buf, fp);
			sprintf(buf, "uci -q set wireless.@wifi-iface[%d].auth_port=\n", number);
			fputs(buf, fp);
			sprintf(buf, "uci -q set wireless.@wifi-iface[%d].auth_secret=\n", number);
			fputs(buf, fp);
			sprintf(buf, "uci -q set wireless.@wifi-iface[%d].acct_server=\n", number);
			fputs(buf, fp);
			sprintf(buf, "uci -q set wireless.@wifi-iface[%d].acct_port=\n", number);
			fputs(buf, fp);
			sprintf(buf, "uci -q set wireless.@wifi-iface[%d].acct_secret=\n", number);
			fputs(buf, fp);
			sprintf(buf, "uci -q set wireless.@wifi-iface[%d].nasid=\n", number);
			fputs(buf, fp);
		}
		else if (!strncmp(tmp->valuestring, "wpa", 3))
		{
			tmp = cJSON_GetObjectItem(root, "auth_server");
			if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
			{
				sprintf(buf, "uci -q set wireless.@wifi-iface[%d].auth_server='%s'\n", number, tmp->valuestring);
				fputs(buf, fp);
			}

			tmp = cJSON_GetObjectItem(root, "auth_port");
			if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
			{
				sprintf(buf, "uci -q set wireless.@wifi-iface[%d].auth_port='%s'\n", number, tmp->valuestring);
				fputs(buf, fp);
			}

			tmp = cJSON_GetObjectItem(root, "auth_secret");
			if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
			{
				sprintf(buf, "uci -q set wireless.@wifi-iface[%d].auth_secret='%s'\n", number, tmp->valuestring);
				fputs(buf, fp);
			}

			tmp = cJSON_GetObjectItem(root, "acct_server");
			if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
			{
				sprintf(buf, "uci -q set wireless.@wifi-iface[%d].acct_server='%s'\n", number, tmp->valuestring);
				fputs(buf, fp);
			}

			tmp = cJSON_GetObjectItem(root, "acct_port");
			if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
			{
				sprintf(buf, "uci -q set wireless.@wifi-iface[%d].acct_port='%s'\n", number, tmp->valuestring);
				fputs(buf, fp);
			}

			tmp = cJSON_GetObjectItem(root, "acct_secret");
			if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
			{
				sprintf(buf, "uci -q set wireless.@wifi-iface[%d].acct_secret='%s'\n", number, tmp->valuestring);
				fputs(buf, fp);
			}

			tmp = cJSON_GetObjectItem(root, "nasid");
			if (tmp && tmp->type == cJSON_String && strlen(tmp->valuestring))
			{
				sprintf(buf, "uci -q set wireless.@wifi-iface[%d].nasid='%s'\n", number, tmp->valuestring);
				fputs(buf, fp);
			}
			sprintf(buf, "uci -q set wireless.@wifi-iface[%d].key=\n", number);
			fputs(buf, fp);
		}
		else if (!(strncmp(tmp->valuestring, "none", 4)))
		{
			sprintf(buf, "uci -q set wireless.@wifi-iface[%d].auth_server=\n", number);
			fputs(buf, fp);
			sprintf(buf, "uci -q set wireless.@wifi-iface[%d].auth_port=\n", number);
			fputs(buf, fp);
			sprintf(buf, "uci -q set wireless.@wifi-iface[%d].auth_secret=\n", number);
			fputs(buf, fp);
			sprintf(buf, "uci -q set wireless.@wifi-iface[%d].acct_server=\n", number);
			fputs(buf, fp);
			sprintf(buf, "uci -q set wireless.@wifi-iface[%d].acct_port=\n", number);
			fputs(buf, fp);
			sprintf(buf, "uci -q set wireless.@wifi-iface[%d].acct_secret=\n", number);
			fputs(buf, fp);
			sprintf(buf, "uci -q set wireless.@wifi-iface[%d].nasid=\n", number);
			fputs(buf, fp);
			sprintf(buf, "uci -q set wireless.@wifi-iface[%d].key=\n", number);
			fputs(buf, fp);
		}
	}
}

static void wireless_wifi_iface(FILE *fp, cJSON *root, int n)
{
	cJSON *tmp = NULL;
	int i;
	if (!root)
		return;
	delc = 0;
	for (i = 0; i < n; i++)
	{
		tmp = cJSON_GetArrayItem(root, i);
		if (!tmp)
			continue;
		wifi_iface_section(fp, tmp);
	}
}

static void wireless_conf(FILE *fp, cJSON *root)
{
	cJSON *wifi_device = NULL;
	cJSON *wifi_iface = NULL;

	if (!root)
		return;

	fputs("###config wireless\n", fp);

	wifi_device = cJSON_GetObjectItem(root, "wifi-device");
	wifi_iface = cJSON_GetObjectItem(root, "wifi-iface");

	if (wifi_device && wifi_device->type == cJSON_Array)
		wireless_wifi_device(fp, wifi_device, cJSON_GetArraySize(wifi_device));
	if (wifi_iface && wifi_iface->type == cJSON_Array)
		wireless_wifi_iface(fp, wifi_iface, cJSON_GetArraySize(wifi_iface));

	fputs("uci commit wireless\nwifi &\n", fp);
}

static void ac_conf(FILE *fp, cJSON *root)
{
	cJSON *node = NULL;
	cJSON *normal = NULL, *ac_client = NULL;
	int reload = 0;
	char buf[256] = {0};
	memset(buf, 0, sizeof(buf));

	if (root == NULL)
	{
		return;
	}

	normal = cJSON_GetObjectItem(root, "normal");
	ac_client = cJSON_GetObjectItem(root, "client");

	fputs("###config ac\n", fp);

	/* normal */
	if (normal != NULL)
	{
		node = cJSON_GetObjectItem(normal, "acurl");
		if ((node != NULL) && (strlen(node->valuestring) != 0))
		{
			sprintf(buf, "uci -q set aconf.normal.sip='%s'\n", node->valuestring);
			fputs(buf, fp);
			reload = 1;
		}

		node = cJSON_GetObjectItem(normal, "cloudinterface");
		if ((node != NULL) && (strlen(node->valuestring) != 0))
		{
			sprintf(buf, "uci -q set aconf.normal.cloudinterface='%s'\n", node->valuestring);
			fputs(buf, fp);
			reload = 1;
		}

		node = cJSON_GetObjectItem(normal, "disabled");
		if (node != NULL)
		{
			sprintf(buf, "uci -q set aconf.normal.disabled='%d'\n", get_jsonint(node));
			fputs(buf, fp);
			reload = 1;
		}
	}

	if (ac_client != NULL)
	{
		node = cJSON_GetObjectItem(ac_client, "rssi");
		if ((node != NULL) && (strlen(node->valuestring) != 0))
		{
			sprintf(buf, "uci -q set aconf.client.rssi='%s'\n", node->valuestring);
			fputs(buf, fp);
			reload = 1;
		}
		node = cJSON_GetObjectItem(ac_client, "disabled");
		if (node != NULL)
		{
			sprintf(buf, "uci -q set aconf.client.disabled='%d'\n", get_jsonint(node));
			fputs(buf, fp);
			reload = 1;
		}
	}
	if (reload == 1)
	{
		fputs("uci commit aconf\n/etc/init.d/ac_platform restart &\n", fp);
	}
}

static int baudrate_check(int speed)
{
	int ret = 0;
	switch (speed)
	{
		case 9600:
		case 115200:
		case 230400:
		case 460800:
		case 576000:
		case 921600:
			ret = 1;
			break;
		default:
			ret = 0;
			break;
	}

	return ret;
}

static void blue_conf(FILE *fp, cJSON *root)
{
	cJSON *node = NULL, *con = NULL;
	int reload = 0;
	char buf[256] = {0};
	memset(buf, 0, sizeof(buf));

	if (root == NULL)
	{
		return;
	}

	con = cJSON_GetObjectItem(root, "con");

	fputs("###config blue\n", fp);

	if (con != NULL)
	{
		node = cJSON_GetObjectItem(con, "disabled");
		if ((node != NULL))
		{
			sprintf(buf, "uci -q set blconfig.con.disabled='%d'\n", get_jsonint(node));

			fputs(buf, fp);
			reload = 1;
		}

		node = cJSON_GetObjectItem(con, "ip");
		if ((node != NULL) && (strlen(node->valuestring) != 0))
		{
			sprintf(buf, "uci -q set blconfig.con.ip='%s'\n", node->valuestring);
			fputs(buf, fp);
			reload = 1;
		}

		node = cJSON_GetObjectItem(con, "port");
		if ((node != NULL))
		{
			sprintf(buf, "uci -q set blconfig.con.port='%d'\n", get_jsonint(node));

			fputs(buf, fp);
			reload = 1;
		}

#if 0
		node = cJSON_GetObjectItem(con, "USB_interface");
		if ((node != NULL))
		{
			if (node->type == cJSON_Number)
			{
				sprintf(buf, "uci -q set blconfig.con.USB_interface='/dev/ttyUSB%d'\n", node->valueint); /*ttyUSB0*/
			}
			else if (node->type == cJSON_String && strlen(node->valuestring))
			{
				sprintf(buf, "uci -q set blconfig.con.USB_interface='/dev/ttyUSB%d'\n",
						atoi(node->valuestring)); /*ttyUSB0*/
			}

			fputs(buf, fp);
			reload = 1;
		}
#endif
		node = cJSON_GetObjectItem(con, "baudrate");
		if (NULL != node)
		{
			int baudrate = get_jsonint(node);
			if (baudrate_check(baudrate))
			{
				sprintf(buf, "uci -q set blconfig.con.baudrate='%d'\n", baudrate);
				fputs(buf, fp);
				reload = 1;
			}
			else
			{
				/* code */
				log_e("blue baudrate is error, do not config !");
			}
		}

		if (reload == 1)
		{
			fputs("uci commit blconfig\n/etc/init.d/blinit restart &\n", fp);
		}
	}
}

static void blelink_conf(FILE *fp, cJSON *root)
{
	cJSON *node = NULL, *con = NULL;
	int reload = 0;
	char buf[256] = {0};
	memset(buf, 0, sizeof(buf));

	if (root == NULL)
	{
		return;
	}

	con = cJSON_GetObjectItem(root, "common");

	fputs("###config blelink\n", fp);

	if (con != NULL)
	{
		node = cJSON_GetObjectItem(con, "disabled");
		if ((node != NULL))
		{
			sprintf(buf, "uci -q set blelink.common.disabled='%d'\n", get_jsonint(node));

			fputs(buf, fp);
			reload = 1;
		}

		node = cJSON_GetObjectItem(con, "serverhost");
		if ((node != NULL) && (strlen(node->valuestring) != 0))
		{
			sprintf(buf, "uci -q set blelink.common.serverhost='%s'\n", node->valuestring);
			fputs(buf, fp);
			reload = 1;
		}

		node = cJSON_GetObjectItem(con, "serverport");
		if ((node != NULL))
		{
			sprintf(buf, "uci -q set blelink.common.serverport='%d'\n", get_jsonint(node));

			fputs(buf, fp);
			reload = 1;
		}

		node = cJSON_GetObjectItem(con, "baudrate");
		if (NULL != node)
		{
			int baudrate = get_jsonint(node);
			if (baudrate_check(baudrate))
			{
				sprintf(buf, "uci -q set blelink.common.baudrate='%d'\n", baudrate);
				fputs(buf, fp);
				reload = 1;
			}
			else
			{
				/* code */
				log_e("blelink baudrate is error, do not config !");
			}
		}

		if (reload == 1)
		{
			fputs("uci commit blelink\n/etc/init.d/BLElink restart &\n", fp);
		}
	}
}

static void wireless433_conf(FILE *fp, cJSON *root)
{
	cJSON *node = NULL, *con = NULL;
	int reload = 0;
	char buf[256] = {0};
	memset(buf, 0, sizeof(buf));

	if (root == NULL)
	{
		return;
	}

	con = cJSON_GetObjectItem(root, "con");

	fputs("###config 433M###\n", fp);

	if (con != NULL)
	{
		node = cJSON_GetObjectItem(con, "disabled");
		if ((node != NULL))
		{
			sprintf(buf, "uci -q set 433Mcon.con.disabled='%d'\n", get_jsonint(node));

			fputs(buf, fp);
			reload = 1;
		}

		node = cJSON_GetObjectItem(con, "ip");
		if ((node != NULL) && (strlen(node->valuestring) != 0))
		{
			sprintf(buf, "uci -q set 433Mcon.con.ip='%s'\n", node->valuestring);
			fputs(buf, fp);
			reload = 1;
		}

		node = cJSON_GetObjectItem(con, "port");
		if ((node != NULL))
		{
			sprintf(buf, "uci -q set 433Mcon.con.port='%d'\n", get_jsonint(node));

			fputs(buf, fp);
			reload = 1;
		}

		if (reload == 1)
		{
			fputs("uci commit 433Mcon\n/etc/init.d/433wireless restart &\n", fp);
		}
	}
}

static void rtty_conf(FILE *fp, cJSON *root)
{
	cJSON *node = NULL, *con = NULL;
	int reload = 0;
	char buf[256] = {0};
	memset(buf, 0, sizeof(buf));

	if (root == NULL)
	{
		return;
	}

	con = cJSON_GetObjectItem(root, "main");

	fputs("###config rtty###\n", fp);

	if (con != NULL)
	{
		node = cJSON_GetObjectItem(con, "enable");
		if ((node != NULL))
		{
			sprintf(buf, "uci -q set rtty.main.enable='%d'\n", get_jsonint(node));

			fputs(buf, fp);
			reload = 1;
		}

		node = cJSON_GetObjectItem(con, "host");
		if ((node != NULL) && (strlen(node->valuestring) != 0))
		{
			sprintf(buf, "uci -q set rtty.main.host='%s'\n", node->valuestring);
			fputs(buf, fp);
			reload = 1;
		}

		node = cJSON_GetObjectItem(con, "port");
		if ((node != NULL))
		{
			sprintf(buf, "uci -q set rtty.main.port='%d'\n", get_jsonint(node));

			fputs(buf, fp);
			reload = 1;
		}

		node = cJSON_GetObjectItem(con, "ssl");
		if ((node != NULL))
		{
			sprintf(buf, "uci -q set rtty.main.ssl='%d'\n", get_jsonint(node));

			fputs(buf, fp);
			reload = 1;
		}

		node = cJSON_GetObjectItem(con, "token");
		if ((node != NULL) && (strlen(node->valuestring) != 0))
		{
			sprintf(buf, "uci -q set rtty.main.token='%s'\n", node->valuestring);
			fputs(buf, fp);
			reload = 1;
		}

		if (reload == 1)
		{
			fputs("uci commit rtty\n/etc/init.d/rtty restart &\n", fp);
		}
	}
}

static void uwb_conf(FILE *fp, cJSON *root)
{
	cJSON *node = NULL;
	int reload = 0;

	char buf[256] = {0};

	cJSON *con = NULL;

	if (root == NULL)
	{
		return;
	}

	con = cJSON_GetObjectItem(root, "con");

	/* con */
	if (con != NULL)
	{
		fputs("###### uwb main config ######\n", fp);

		node = cJSON_GetObjectItem(con, "disabled");
		if ((node != NULL))
		{
			memset(buf, 0, sizeof(buf));

			sprintf(buf, "uci -q set uwbcon.con.disabled='%d'\n", get_jsonint(node));

			fputs(buf, fp);
			reload = 1;
		}

		node = cJSON_GetObjectItem(con, "ip");
		if ((node != NULL) && (strlen(node->valuestring) != 0))
		{
			memset(buf, 0, sizeof(buf));
			sprintf(buf, "uci -q set uwbcon.con.ip='%s'\n", node->valuestring);
			fputs(buf, fp);
			reload = 1;
		}

		node = cJSON_GetObjectItem(con, "port");
		if ((node != NULL))
		{
			memset(buf, 0, sizeof(buf));

			sprintf(buf, "uci -q set uwbcon.con.port='%d'\n", get_jsonint(node));

			fputs(buf, fp);
			reload = 1;
		}

		node = cJSON_GetObjectItem(con, "tcp_nagle");
		if ((node != NULL))
		{
			memset(buf, 0, sizeof(buf));

			sprintf(buf, "uci -q set uwbcon.con.tcp_nagle='%d'\n", get_jsonint(node));

			fputs(buf, fp);
			reload = 1;
		}

#if 0
		node = cJSON_GetObjectItem(con, "tty");
		if ((node != NULL))
		{
			memset(buf, 0, sizeof(buf));

			if (node->type == cJSON_Number)
			{
				sprintf(buf, "uci -q set uwbcon.con.tty='/dev/ttyUSB%d'\n", node->valueint); /*ttyUSB0*/
			}
			else if (node->type == cJSON_String && strlen(node->valuestring))
			{
				sprintf(buf, "uci -q set uwbcon.con.tty='/dev/ttyUSB%d'\n", atoi(node->valuestring)); /*ttyUSB0*/
			}

			fputs(buf, fp);
			reload = 1;

		}
#endif

		node = cJSON_GetObjectItem(con, "dimension");
		if (node != NULL)
		{
			memset(buf, 0, sizeof(buf));

			devdimension = get_jsonint(node);
			sprintf(buf, "dimension_set %ld\n", devdimension);

			fputs(buf, fp);
		}

		if (reload == 1)
		{
			fputs("uci commit uwbcon\n", fp);
			fputs("###### uwb process need restart ######\n", fp);
			fputs("/etc/init.d/uwb_start restart\n", fp);
		}

		fputs("###### uwb config end ######\n", fp);
	}
}

static void uwbcmd_conf(FILE *fp, cJSON *root)
{
	char buf[256] = {0};
	int listnum = 0;
	int i = 0;

	cJSON *cmdlist = NULL;
	cJSON *listnode = NULL;

	if (root == NULL)
	{
		return;
	}

	cmdlist = cJSON_GetObjectItem(root, "cmdlist");

	fputs("###### uwbcmd list start ######\n", fp);

	/* cmdlist */
	if (cmdlist != NULL && cmdlist->type == cJSON_Array)
	{
		listnum = cJSON_GetArraySize(cmdlist);
		if (listnum < 1 || listnum > 10)
		{
			log_e("cmdlist is null or more then max num!");
		}
		else
		{
			for (i = 0; i < listnum; i++)
			{
				listnode = cJSON_GetArrayItem(cmdlist, i);

				if (NULL == listnode)
				{
					continue;
				}

				if (strlen(listnode->valuestring) < 128)
				{
					memset(buf, 0, sizeof(buf));
					sprintf(buf, "UWB \"%s\"\n", listnode->valuestring);
					fputs(buf, fp);

					if (i < (listnum - 1))
					{
						memset(buf, 0, sizeof(buf));
						sprintf(buf, "usleep 500000\n");
						fputs(buf, fp);
					}
				}
				else
				{
					log_e("cmd value len > 128 !");
				}
			}
		}
	}
	else
	{
		log_e("uwbcmd cmdlist array error!");
	}

	fputs("###### uwbcmd list end ######\n", fp);
}

static void mesh_conf(FILE *fp, cJSON *root)
{
	cJSON *con = NULL;
	cJSON *node = NULL;
	char buf[256] = {0};
	int jsonint = 0;

	if (root == NULL)
	{
		return;
	}

	con = cJSON_GetObjectItem(root, "meshconf");

	fputs("###### config mesh wireless ######\n", fp);

	/* con */
	if (con != NULL)
	{
		log_w("!!! set mesh wireless will reconnect network and affect other services !!!");
		/*mesh_enable*/
		node = cJSON_GetObjectItem(con, "mesh_enable");
		if ((node != NULL))
		{
			memset(buf, 0, sizeof(buf));

			if (node->type == cJSON_Number)
			{
				jsonint = node->valueint;
			}
			else if (node->type == cJSON_String && strlen(node->valuestring))
			{
				jsonint = atoi(node->valuestring);
			}

			sprintf(buf, "uci -q set mesh.meshconf.mesh_enable='%d'\n", jsonint);
			fputs(buf, fp);
		}
		/*meshid*/
		node = cJSON_GetObjectItem(con, "meshid");
		if ((node != NULL))
		{
			memset(buf, 0, sizeof(buf));

			if (node->type == cJSON_String && strlen(node->valuestring) >= 1 && strlen(node->valuestring) <= 32)
			{
				sprintf(buf, "uci -q set mesh.meshconf.meshid='%s'\n", node->valuestring);
			}

			fputs(buf, fp);
		}
		/*meshradio*/
		node = cJSON_GetObjectItem(con, "meshradio");
		if ((node != NULL) && (strlen(node->valuestring) != 0))
		{
			memset(buf, 0, sizeof(buf));
			sprintf(buf, "uci -q set mesh.meshconf.meshradio='%s'\n", node->valuestring);
			fputs(buf, fp);
		}
		/*meshrssithreshold*/
		node = cJSON_GetObjectItem(con, "meshrssithreshold");
		if (node != NULL)
		{
			memset(buf, 0, sizeof(buf));
			if (node->type == cJSON_Number)
			{
				jsonint = node->valueint;
			}
			else if (node->type == cJSON_String && strlen(node->valuestring))
			{
				jsonint = atoi(node->valuestring);
			}

			sprintf(buf, "uci -q set mesh.meshconf.meshrssithreshold='%d'\n", jsonint);
			fputs(buf, fp);
		}
		/*channel_2g*/
		node = cJSON_GetObjectItem(con, "channel_2g");
		if ((node != NULL) && (node->type == cJSON_Number))
		{
			memset(buf, 0, sizeof(buf));
			sprintf(buf, "uci -q set mesh.meshconf.channel_2g='%d'\n", node->valueint);
			fputs(buf, fp);
		}
		/*channel_5g*/
		node = cJSON_GetObjectItem(con, "channel_5g");
		if ((node != NULL) && (node->type == cJSON_Number))
		{
			memset(buf, 0, sizeof(buf));
			sprintf(buf, "uci -q set mesh.meshconf.channel_5g='%d'\n", node->valueint);
			fputs(buf, fp);
		}
		/*meshap_enable*/
		node = cJSON_GetObjectItem(con, "meshap_enable");
		if (node != NULL)
		{
			memset(buf, 0, sizeof(buf));
			if (node->type == cJSON_Number)
			{
				jsonint = node->valueint;
			}
			else if (node->type == cJSON_String && strlen(node->valuestring))
			{
				jsonint = atoi(node->valuestring);
			}
			sprintf(buf, "uci -q set mesh.meshconf.meshap_enable='%d'\n", jsonint);
			fputs(buf, fp);
		}
		/*meshap_ssid*/
		node = cJSON_GetObjectItem(con, "meshap_ssid");
		if ((node != NULL))
		{
			memset(buf, 0, sizeof(buf));

			if (node->type == cJSON_String && strlen(node->valuestring) >= 1 && strlen(node->valuestring) <= 32)
			{
				sprintf(buf, "uci -q set mesh.meshconf.meshap_ssid='%s'\n", node->valuestring);
			}

			fputs(buf, fp);
		}
		/*meshap_encryption*/
		node = cJSON_GetObjectItem(con, "meshap_encryption");
		if (node != NULL)
		{
			memset(buf, 0, sizeof(buf));
			if (node->type == cJSON_Number)
			{
				jsonint = node->valueint;
			}
			else if (node->type == cJSON_String && strlen(node->valuestring))
			{
				jsonint = atoi(node->valuestring);
			}
			sprintf(buf, "uci -q set mesh.meshconf.meshap_encryption='%d'\n", jsonint);
			fputs(buf, fp);
		}
		/*meshap_key*/
		node = cJSON_GetObjectItem(con, "meshap_key");
		if ((node != NULL))
		{
			memset(buf, 0, sizeof(buf));

			if (node->type == cJSON_String && strlen(node->valuestring) >= 8 && strlen(node->valuestring) <= 32)
			{
				sprintf(buf, "uci -q set mesh.meshconf.meshap_key='%s'\n", node->valuestring);
			}

			fputs(buf, fp);
		}

		fputs("uci commit mesh && sleep 20\n", fp);
		fputs("/etc/init.d/set_mesh restart &\n", fp);
	}

	fputs("######config mesh wireless end######\n", fp);
}

static void alarm_conf(FILE *fp, cJSON *root)
{
	cJSON *con = NULL;
	cJSON *node = NULL;
	char buf[256] = {0};

	if (root == NULL)
	{
		return;
	}

	con = cJSON_GetObjectItem(root, "maincon");

	fputs("###### config alarm_services ######\n", fp);

	/* con */
	if (con != NULL)
	{
		node = cJSON_GetObjectItem(con, "disabled");
		if ((node != NULL))
		{
			memset(buf, 0, sizeof(buf));

			sprintf(buf, "uci -q set alarm.main.disabled='%d'\n", get_jsonint(node));

			fputs(buf, fp);
		}

		node = cJSON_GetObjectItem(con, "host");
		if ((node != NULL) && (strlen(node->valuestring) != 0))
		{
			memset(buf, 0, sizeof(buf));
			sprintf(buf, "uci -q set alarm.main.host='%s'\n", node->valuestring);
			fputs(buf, fp);
		}

		node = cJSON_GetObjectItem(con, "port");
		if ((node != NULL))
		{
			memset(buf, 0, sizeof(buf));

			sprintf(buf, "uci -q set alarm.main.port='%d'\n", get_jsonint(node));

			fputs(buf, fp);
		}

		node = cJSON_GetObjectItem(con, "username");
		if ((node != NULL) && node->type == cJSON_String && strlen(node->valuestring))
		{
			if (strlen(node->valuestring) > 32)
			{
				log_e("username long then max length !");
			}
			else
			{
				memset(buf, 0, sizeof(buf));
				sprintf(buf, "uci -q set alarm.main.username='%s'\n", node->valuestring);
				fputs(buf, fp);
			}
		}

		node = cJSON_GetObjectItem(con, "passwd");
		if ((node != NULL) && (strlen(node->valuestring) != 0))
		{
			if (strlen(node->valuestring) > 32)
			{
				log_e("passwd long then max length !");
			}
			else
			{
				memset(buf, 0, sizeof(buf));
				sprintf(buf, "uci -q set alarm.main.passwd='%s'\n", node->valuestring);
				fputs(buf, fp);
			}
		}

		fputs("uci commit alarm\n", fp);
		fputs("/etc/init.d/alarm restart\n", fp);
	}

	fputs("######config alarm_services end######\n", fp);
}

static void probe_freq_conf(cJSON *root, FILE *fp)
{
	cJSON *node = NULL, *tmp = NULL;
	char buf[256] = {0};
	int freq_c, i, arrysize = 0;
	memset(buf, 0, sizeof(buf));

	node = cJSON_GetObjectItem(root, "freq_c");
	if (node == NULL)
	{
		return;
	}
	freq_c = atoi(node->valuestring);

	node = cJSON_GetObjectItem(root, "disabled");
	if ((node != NULL) && (strlen(node->valuestring) != 0))
	{
		sprintf(buf, "uci -q set cscan.@interface1[%d].disabled='%s'\n", freq_c, node->valuestring);
		fputs(buf, fp);
	}

	node = cJSON_GetObjectItem(root, "mode");
	if ((node != NULL) && (strlen(node->valuestring) != 0))
	{
		sprintf(buf, "uci -q set cscan.@interface1[%d].mode='%s'\n", freq_c, node->valuestring);
		fputs(buf, fp);
	}

	node = cJSON_GetObjectItem(root, "ifname");
	if ((node != NULL) && (strlen(node->valuestring) != 0))
	{
		sprintf(buf, "uci -q set cscan.@interface1[%d].ifname='%s'\n", freq_c, node->valuestring);
		fputs(buf, fp);
	}

	node = cJSON_GetObjectItem(root, "dwell");
	if ((node != NULL) && (strlen(node->valuestring) != 0))
	{
		sprintf(buf, "uci -q set cscan.@interface1[%d].dwell='%s'\n", freq_c, node->valuestring);
		fputs(buf, fp);
	}

	node = cJSON_GetObjectItem(root, "filter_mode");
	if ((node != NULL) && (strlen(node->valuestring) != 0))
	{
		sprintf(buf, "uci -q set cscan.@interface1[%d].filter_mode='%s'\n", freq_c, node->valuestring);
		fputs(buf, fp);
	}

	node = cJSON_GetObjectItem(root, "channel");
	if ((node != NULL) && (strlen(node->valuestring) != 0))
	{
		sprintf(buf, "uci -q delete cscan.@interface1[%d].channels\n", freq_c);
		fputs(buf, fp);
		sprintf(buf, "uci -q set cscan.@interface1[%d].channel='%s'\n", freq_c, node->valuestring);
		fputs(buf, fp);
	}

	node = cJSON_GetObjectItem(root, "channels");
	if ((node != NULL))
	{
		arrysize = cJSON_GetArraySize(node);
		if (arrysize)
		{
			sprintf(buf, "uci -q delete cscan.@interface1[%d].channels\n", freq_c);
			fputs(buf, fp);
		}
		for (i = 0; i < arrysize; i++)
		{
			tmp = cJSON_GetArrayItem(node, i);
			if ((tmp != NULL) && (strlen(tmp->valuestring) != 0))
			{
				sprintf(buf, "uci -q add_list cscan.@interface1[%d].channels='%s'\n", freq_c, tmp->valuestring);
				fputs(buf, fp);
			}
		}
	}
}

static void probe_conf(FILE *fp, cJSON *root)
{
	cJSON *node = NULL, *tmp = NULL;
	int arrysize = 0;
	int i;
	char buf[256] = {0};
	memset(buf, 0, sizeof(buf));

	fputs("###config wifi probe\n", fp);

	node = cJSON_GetObjectItem(root, "disabled");
	if ((node != NULL) && (strlen(node->valuestring) != 0))
	{
		sprintf(buf, "uci -q set cscan.scan.disabled='%s'\n", node->valuestring);
		fputs(buf, fp);
	}

	node = cJSON_GetObjectItem(root, "sicunprobeurl");
	if ((node != NULL) && (strlen(node->valuestring) != 0))
	{
		sprintf(buf, "uci -q set cscan.scan.sip='%s'\n", node->valuestring);
		fputs(buf, fp);
	}

	node = cJSON_GetObjectItem(root, "sicnuprobeport");
	if ((node != NULL) && (strlen(node->valuestring) != 0))
	{
		sprintf(buf, "uci -q set cscan.scan.sport='%s'\n", node->valuestring);
		fputs(buf, fp);
	}

	node = cJSON_GetObjectItem(root, "ifun");
	if ((node != NULL) && (strlen(node->valuestring) != 0))
	{
		sprintf(buf, "uci -q set cscan.scan.ifun='%s'\n", node->valuestring);
		fputs(buf, fp);
	}

	node = cJSON_GetObjectItem(root, "macsellect");
	if ((node != NULL) && (strlen(node->valuestring) != 0))
	{
		sprintf(buf, "uci -q set cscan.scan.macsellect='%s'\n", node->valuestring);
		fputs(buf, fp);
	}

	node = cJSON_GetObjectItem(root, "method");
	if ((node != NULL) && (strlen(node->valuestring) != 0))
	{
		sprintf(buf, "uci -q set cscan.scan.method='%s'\n", node->valuestring);
		fputs(buf, fp);

		switch ((node->valuestring)[0])
		{
			case 1:
			case 2:
				sprintf(buf, "uci -q set cscan.scan.ifun=\n");
				fputs(buf, fp);
				break;
			case 3:
			case 4:
				sprintf(buf, "uci -q set cscan.scan.sip=\n");
				fputs(buf, fp);
				sprintf(buf, "uci -q set cscan.scan.sport=\n");
				fputs(buf, fp);
				break;
		}
	}

	node = cJSON_GetObjectItem(root, "probedev");
	if ((node != NULL) && (strlen(node->valuestring) != 0))
	{
		sprintf(buf, "uci -q set cscan.scan.probedev='%s'\n", node->valuestring);
		fputs(buf, fp);
	}

	node = cJSON_GetObjectItem(root, "node_timeout");
	if ((node != NULL) && (strlen(node->valuestring) != 0))
	{
		sprintf(buf, "uci -q set cscan.scan.node_timeout='%s'\n", node->valuestring);
		fputs(buf, fp);
	}

	node = cJSON_GetObjectItem(root, "filter_mac");
	fputs("uci delete cscan.scan.filter_mac\n", fp);
	if ((node != NULL))
	{
		arrysize = cJSON_GetArraySize(node);
		for (i = 0; i < arrysize; i++)
		{
			tmp = cJSON_GetArrayItem(node, i);
			if ((tmp != NULL) && (strlen(tmp->valuestring) != 0))
			{
				sprintf(buf, "uci -q add_list cscan.scan.filter_mac='%s'\n", tmp->valuestring);
				fputs(buf, fp);
			}
		}
	}

	node = cJSON_GetObjectItem(root, "probe_freq");
	if (node != NULL)
	{
		arrysize = cJSON_GetArraySize(node);
		for (i = 0; i < arrysize; i++)
		{
			probe_freq_conf(cJSON_GetArrayItem(node, i), fp);
		}
	}

	fputs("uci commit cscan\n/etc/init.d/cscan restart\n", fp);
}

static void clear_network_conf(FILE *fp)
{
	int i;
	char buf[256] = {0};
	for (i = 0; i < interface_num; i++)
	{
		sprintf(buf, "uci delete network.@interface[0]\n");
		fputs(buf, fp);
	}

	for (i = 0; i < switch_vlan_num; i++)
	{
		sprintf(buf, "uci delete network.@switch_vlan[0]\n");
		fputs(buf, fp);
	}

	fputs("uci add network interface\nuci rename network.@interface[0]='loopback'\n", fp);
	fputs("uci set network.loopback.ifname='lo'\n", fp);
	fputs("uci set network.loopback.proto='static'\n", fp);
	fputs("uci set network.loopback.ipaddr='127.0.0.1'\n", fp);
	fputs("uci set network.loopback.netmask='255.0.0.0'\n", fp);
	interface_num = 1;
	switch_vlan_num = 0;
}

static void network_vlan_conf(FILE *fp, cJSON *root)
{
	cJSON *tmp = NULL;
	char *interface = NULL;
	char buf[256] = {0};
	int vlanid = 0, bridge = 0, metric = 0;
	if (!root || !fp)
		return;
	tmp = cJSON_GetObjectItem(root, "interface");
	if (!tmp || !tmp->valuestring)
		return;
	interface = tmp->valuestring;

	tmp = cJSON_GetObjectItem(root, "bridge");
	if (tmp)
	{
		if (tmp->type == cJSON_String && tmp->valuestring)
			bridge = atoi(tmp->valuestring);
		else if (tmp->type == cJSON_Number)
			bridge = tmp->valueint;
	}

	tmp = cJSON_GetObjectItem(root, "vlanid");
	if (tmp)
	{
		if (tmp->type == cJSON_String && tmp->valuestring)
			vlanid = atoi(tmp->valuestring);
		else if (tmp->type == cJSON_Number)
			vlanid = tmp->valueint;
	}

	fputs("uci add network interface\n", fp);
	sprintf(buf, "uci rename network.@interface[%d]='%s'\n", interface_num++, interface);
	fputs(buf, fp);
	sprintf(buf, "uci set network.%s.proto='dhcp'\n", interface);
	fputs(buf, fp);
	sprintf(buf, "uci set network.%s.ifname='eth0.%d'\n", interface, vlanid);
	fputs(buf, fp);
	if (bridge == 0)
	{
		sprintf(buf, "uci set network.%s.type='bridge'\n", interface);
		fputs(buf, fp);
	}

	tmp = cJSON_GetObjectItem(root, "metric");
	if (tmp)
	{
		if (tmp->type == cJSON_String && tmp->valuestring)
			metric = atoi(tmp->valuestring);
		else if (tmp->type == cJSON_Number)
			metric = tmp->valueint;
		sprintf(buf, "uci set network.%s.metric='%d'\n", interface, metric);
		fputs(buf, fp);
	}

	fputs("uci add network switch_vlan\n", fp);
	sprintf(buf, "uci set network.@switch_vlan[%d].device='switch0'\n", switch_vlan_num);
	fputs(buf, fp);
	sprintf(buf, "uci set network.@switch_vlan[%d].vlan='%d'\n", switch_vlan_num, vlanid);
	fputs(buf, fp);
	if (switch_vlan_num == 0)
		sprintf(buf, "uci set network.@switch_vlan[%d].ports='0t 1 2 3 4 5'\n", switch_vlan_num);
	else
		sprintf(buf, "uci set network.@switch_vlan[%d].ports='0t 1t'\n", switch_vlan_num);
	fputs(buf, fp);
	switch_vlan_num++;
}

static void netowrk_conf_multi(FILE *fp, cJSON *root)
{
	cJSON *tmp = NULL;
	int i;
	int vlansize = 0;

	fputs("###config network\n", fp);

	tmp = cJSON_GetObjectItem(root, "vlan");
	if (!tmp || tmp->type != cJSON_Array)
		return;
	vlansize = cJSON_GetArraySize(tmp);
	if (vlansize <= 0)
		return;
	clear_network_conf(fp);
	for (i = 0; i < vlansize; i++)
	{
		network_vlan_conf(fp, cJSON_GetArrayItem(tmp, i));
	}
	fputs("uci commit network\n/etc/init.d/network restart &\n", fp);
}

/* get capwap enable 0/1*/
int get_enable_capwap(void)
{
	FILE *file = NULL;
	int enable = 0;
	char buf[10];

	memset(buf, 0, sizeof(buf));

	file = popen("uci get wtp.cfg.enable 2>/dev/null | tr -d '\n'", "r");
	if (file)
	{
		fgets(buf, sizeof(buf), file);
	}
	pclose(file);

	if (strlen(buf) > 0)
	{
		enable = atoi(buf);
	}

	// log_i("capwap enable is %d", enable);

	return enable;
}

/********************************************
 *函数名：net_conf
 *函数参数：
 *            cmdrul是服务器提供的获得ap配置信息的接口
 *函数功能：
 *            该函数实现从服务器获得相应的配置参数，并且根据该配置参数，实施配置
 *********************************************/
void net_conf(const char *cloudinterface, const int encryption, const char *cmdurl, const char *mac, int type,
			  int *resultup)
{
	char url[512] = {0}, buf[BUFSIZE] = {0}, key[256] = {0};
	int flag = 0;
	cJSON *root = NULL, *network = NULL, *wireless = NULL, *tmp = NULL;

	md5key(key, (void *)(time(NULL) / 60));
	sprintf(url, "%s?apmac=%s&key=%s", cmdurl, mac, key);

	log_i("get url: %s", url);
	curl_request(url, GET, NULL, buf);
	if (strlen(buf) == 0)
	{
		return;
	}
	log_i("return: %s", buf);

	FILE *fp = fopen("/tmp/ac/doac.sh", "w");
	if (fp == NULL)
	{
		log_e("fopen error:%d", __LINE__);
		return;
	}
	fputs("#!/bin/sh\n", fp);

	fputs("echo start in $(date +%Y-%m-%d' '%H:%M:%S.%N | cut -b 1-23) > /tmp/ac/doac.log\n", fp);

	root = cJSON_Parse(buf);
	if (root == NULL)
		return;

	network = cJSON_GetObjectItem(root, "network");
	wireless = cJSON_GetObjectItem(root, "wireless");

	tmp = cJSON_GetObjectItem(root, "flag");
	if (tmp)
	{
		if (tmp->type == cJSON_Number)
			flag = tmp->valueint;
		else if (tmp->type == cJSON_String)
			flag = atoi(tmp->valuestring);
	}

	/*when capwap is enable , not allow config network and wireless*/
	if ((network != NULL || wireless != NULL))
	{
		if (1)
		{
			log_d("when mesh mode , not allow config network and wireless !");
		}
		else
		{
			if (network != NULL)
			{
				if (flag)
				{
					netowrk_conf_multi(fp, network);
				}
				else
					network_conf(fp, network);
			}

			if ((wireless != NULL))
			{
				wireless_conf(fp, wireless);
			}
		}
	}

	if ((tmp = cJSON_GetObjectItem(root, "probe")) != NULL)
	{
		probe_conf(fp, tmp);
	}
	if ((tmp = cJSON_GetObjectItem(root, "mesh")) != NULL)
	{
		mesh_conf(fp, tmp);
	}
	if ((tmp = cJSON_GetObjectItem(root, "blue")) != NULL)
	{
		blue_conf(fp, tmp);
	}
	if ((tmp = cJSON_GetObjectItem(root, "433M")) != NULL)
	{
		wireless433_conf(fp, tmp);
	}
	if ((tmp = cJSON_GetObjectItem(root, "rtty")) != NULL)
	{
		rtty_conf(fp, tmp);
	}
	if ((tmp = cJSON_GetObjectItem(root, "uwb")) != NULL)
	{
		uwb_conf(fp, tmp);
	}
	if ((tmp = cJSON_GetObjectItem(root, "alarm")) != NULL)
	{
		alarm_conf(fp, tmp);
	}
	if ((tmp = cJSON_GetObjectItem(root, "blelink")) != NULL)
	{
		blelink_conf(fp, tmp);
	}
	if ((tmp = cJSON_GetObjectItem(root, "uwbcmd")) != NULL)
	{
		uwbcmd_conf(fp, tmp);
		*resultup = 0;
	}

	if ((tmp = cJSON_GetObjectItem(root, "ac")) != NULL)
	{
		ac_conf(fp, tmp);
	}

	fputs("echo **end in $(date +%Y-%m-%d' '%H:%M:%S.%N | cut -b 1-23) >> /tmp/ac/doac.log\n", fp);
	fclose(fp);
	cJSON_Delete(root);

	mychmod("/tmp/ac/doac.sh", 777);
	system_call("/tmp/ac/doac.sh");
	// pox_system("lua /usr/sbin/doac.lua");
	sleep(2);
}

static void do_getinfo(const char *cloudinterface, const int encryption, const char *mac, int type)
{
	char url[BUFSIZE] = {0}, key[256] = {0}, mdata[BUFSIZE] = {0}, buf[BUFSIZE] = {0};
	cJSON *getInfo = init(type);
	char *info = cJSON_PrintUnformatted(getInfo);
	log_i("%s", info);
	sprintf(mdata, "data=%s", info);
	memset(key, 0, sizeof(key));
	md5key(key, (void *)(time(NULL) / 60));
	sprintf(url, "%s/judge?apmac=%s&key=%s&type=info", cloudinterface, mac, key);

	int ret = curl_request(url, POST, mdata, buf);

	if (ret >= 0)
	{
		log_i("getinfo return : %s", buf);
	}

	free(info);
	cJSON_Delete(getInfo);
}

static void do_deny(cJSON *list)
{
	cJSON *tmp = NULL;
	char buf[BUFSIZE] = {0}, cmd[256] = {0};
	int c = cJSON_GetArraySize(list);
	int cw = gainWific();
	int i, j;
	FILE *fp = fopen("/tmp/ac/doac.sh", "w");
	if (fp == NULL)
	{
		log_e("fopen error:%d", __LINE__);
		return;
	}
	fputs("# !/bin/bash\n", fp);
	for (j = 0; j < cw; j++)
	{
		fprintf(fp, "uci -q set wireless.@wifi-iface[%d].macfilter=deny\n", j);
	}
	for (i = 0; i < c; i++)
	{
		tmp = cJSON_GetArrayItem(list, i);
		sprintf(cmd, "uci get wireless.@wifi-iface[%d].maclist", i);
		getGet(buf, cmd, sizeof(buf));
		for (j = 0; j < cw; j++)
		{
			if (strstr(buf, tmp->valuestring) == NULL)
			{
				fprintf(fp, "uci -q add_list wireless.@wifi-iface[%d].maclist=%s\n", j, tmp->valuestring);
			}
		}
	}
	fputs("uci commit\nwifi &\n", fp);
	fclose(fp);
	mychmod("/tmp/ac/doac.sh", 777);
	system("/tmp/ac/doac.sh");
}

static void do_allow(cJSON *list)
{
	cJSON *tmp = NULL;
	char buf[BUFSIZE] = {0}, cmd[256] = {0};
	log_i("\n%s", cJSON_Print(list));
	int c = cJSON_GetArraySize(list);
	int cw = gainWific();
	int i, j;
	FILE *fp = fopen("/tmp/ac/doac.sh", "w");
	if (fp == NULL)
	{
		log_e("fopen error:%d", __LINE__);
		return;
	}
	fputs("# !/bin/bash\n", fp);
	for (j = 0; j < cw; j++)
	{
		fprintf(fp, "uci -q set wireless.@wifi-iface[%d].macfilter=deny\n", j);
	}
	for (i = 0; i < c; i++)
	{
		tmp = cJSON_GetArrayItem(list, i);
		sprintf(cmd, "uci get wireless.@wifi-iface[%d].maclist", i);
		getGet(buf, cmd, sizeof(buf));
		for (j = 0; j < cw; j++)
		{
			if (strstr(buf, tmp->valuestring) != NULL)
			{
				fprintf(fp, "uci -q del_list wireless.@wifi-iface[%d].maclist=%s\n", j, tmp->valuestring);
			}
		}
	}
	fputs("uci commit\nwifi &\n", fp);
	fclose(fp);
	mychmod("/tmp/ac/doac.sh", 777);
	system("/tmp/ac/doac.sh");
}

/********************************************
 *函数名：generate_cmd
 *函数参数：
 *        root 是指向由服务器端返回的一个cJSON对象，
 *函数功能：
 *            该函数执行当cmdtype：generate时，的配置命令cmd
 *********************************************/
void generate_cmd(char *cloudinterface, const int encryption, cJSON *root, char *mac, int type)
{
	char filename[64] = {0};
	char cmd_sh[1024] = {0}, gmd5[256] = {0};
	FILE *fp = NULL;
	strcpy(filename, "/tmp/update.bin");
	cJSON *md5 = cJSON_GetObjectItem(root, "md5");
	cJSON *url = cJSON_GetObjectItem(root, "cmdurl");
	cJSON *cmd = cJSON_GetObjectItem(root, "cmd");
	if (!strcmp(cmd->valuestring, "reboot"))
	{
		log_w("ap will reboot after 15s for other mesh node ap......");
		sleep(15);
		system("reboot");
	}
	else if (!strcmp(cmd->valuestring, "reset"))
	{
		log_w("ap will reset and reboot after 15s for other mesh node ap......");
		sleep(15);
		system("rm -rf /overlay/* && reboot");
	}
	else if (!strcmp(cmd->valuestring, "led"))
	{
		if (url)
		{
			int led = 0;
			if (url->type == cJSON_String && strlen(url->valuestring))
			{
				led = atoi(url->valuestring);
			}
			else if (url->type == cJSON_Number)
			{
				led = url->valueint;
			}
			log_d("led will set %d !", led);
			if (led == 0)
			{
				system("/etc/init.d/airocov_led restart");
			}
			else if (led == 1)
			{
				system("/etc/init.d/airocov_led stop && airocov_led_on");
			}
		}
	}
	else if (!strcmp(cmd->valuestring, "update") || !strcmp(cmd->valuestring, "nonupdate"))
	{
		remove(filename);
		if (url != NULL && strlen(url->valuestring) > 0)
		{
			sprintf(cmd_sh, "/usr/bin/wget --no-check-certificate -c -x -t1 \'%s\' -O %s -o /tmp/ac/wgetbin.log",
					url->valuestring, filename);
			log_i("%s", cmd_sh);
			system(cmd_sh);

			if (md5 != NULL && strlen(md5->valuestring) > 0)
			{
				sprintf(cmd_sh, "md5sum %s | awk '{print $1}' | tr -d '\n'", filename);
				fp = popen(cmd_sh, "r");
				if (fp == NULL)
				{
					log_e("popen error :%d", __LINE__);
					return;
				}
				fgets(gmd5, sizeof(gmd5), fp);
				pclose(fp);
				log_i("file md5:%s", gmd5);
				if (strcmp(md5->valuestring, gmd5) == 0)
				{
					log_w("ap will wait 30s for other mesh node ap......");
					sleep(30);
					log_w("ap will do upgrade, do not poweroff !");

					memset(cmd_sh, 0, sizeof(cmd_sh));
					if (strcmp(cmd->valuestring, "update") == 0)
					{
						sprintf(cmd_sh, "lua /usr/sbin/upgrade.lua 1");
						// sprintf(cmd_sh, "mtd -r write %s firmware", filename);
					}
					else
					{
						sprintf(cmd_sh, "lua /usr/sbin/upgrade.lua 0");
						// sprintf(cmd_sh, "mtd -r write %s firmware", filename);
					}
					log_d("upgrade ......");
					/* not wait fork pid */
					// signal(SIGCHLD,SIG_IGN);
					system(cmd_sh);
				}
				else
				{
					log_e("file md5 is not match !");
				}
			}
			else
			{
				log_e("md5 is null !");
			}
		}
		else
		{
			log_e("cmdurl is null !");
		}
	}
	else if (!strcmp(cmd->valuestring, "ACupgrade"))
	{
		remove("/tmp/softac.ipk");
		if (url != NULL && strlen(url->valuestring) > 0)
		{
			sprintf(cmd_sh, "/usr/bin/wget --no-check-certificate -c -x -t1 \'%s\' -O %s -o /tmp/ac/wgetacipk.log",
					url->valuestring, "/tmp/softac.ipk");
			log_i("%s", cmd_sh);
			system(cmd_sh);

			if (md5 != NULL && strlen(md5->valuestring) > 0)
			{
				sprintf(cmd_sh, "md5sum %s | awk '{print $1}' | tr -d '\n'", "/tmp/softac.ipk");
				fp = popen(cmd_sh, "r");
				if (fp == NULL)
				{
					log_e("popen error :%d", __LINE__);
					return;
				}
				fgets(gmd5, sizeof(gmd5), fp);
				pclose(fp);
				log_i("file md5:%s", gmd5);
				if (strcmp(md5->valuestring, gmd5) == 0)
				{
					memset(cmd_sh, 0, sizeof(cmd_sh));
					log_d("softac do upgrade, programe will reboot !");

					sprintf(cmd_sh, "lua /usr/sbin/softacupgrade.lua");

					system(cmd_sh);
				}
			}
			else
			{
				log_e("md5 is null !");
			}
		}
		else
		{
			log_e("cmdurl is null !");
		}
	}
	else if (!strcmp(cmd->valuestring, "STM32upgrade"))
	{
		remove("/tmp/ac/stm32.bin");

		if (url != NULL && strlen(url->valuestring) > 0)
		{
			sprintf(cmd_sh,
					"/usr/bin/wget --no-check-certificate -c -x -t0 \'%s\' -O /tmp/ac/stm32.bin -o "
					"/tmp/ac/wgetstm32bin.log",
					url->valuestring);
			system(cmd_sh);
			log_i("%s", cmd_sh);

			if (md5 != NULL && strlen(md5->valuestring) > 0)
			{
				fp = popen("md5sum /tmp/ac/stm32.bin | awk '{print $1}' | tr -d '\n'", "r");
				if (fp == NULL)
				{
					log_e("popen error :%d", __LINE__);
					return;
				}
				fgets(gmd5, sizeof(gmd5), fp);
				pclose(fp);
				if (!strcmp(md5->valuestring, gmd5))
				{
					char ttydev[128] = {0};
					/* get uwb tty port */
					fp = popen("uci get uwbcon.con.tty 2>/dev/null | tr -d '\n'", "r");
					if (fp == NULL)
					{
						log_e("popen error");
						return;
					}
					memset(ttydev, 0, sizeof(ttydev));
					fgets(ttydev, sizeof(ttydev), fp);
					pclose(fp);

					if (strlen(ttydev) < 8)
					{
						log_e("get uwb tty port error !");
						return;
					}
					else
					{
						log_e("uwb tty port is %s !", ttydev);
					}

					log_i("stop uwb");
					system("/etc/init.d/uwb_start stop");
					sleep(2);

					log_d("will upgrade stm32...");
					system("killall stm32upgrade");
					system("killall -9 UWB");
					char resault[1024] = {0};
					memset(cmd_sh, 0, sizeof(cmd_sh));
					sprintf(cmd_sh, "stm32upgrade %s u /tmp/ac/stm32.bin", ttydev);

					log_i("%s", cmd_sh);
					int ret = _popen(cmd_sh, resault, sizeof(resault));
					if (ret < 0)
					{
						log_e("popen stm32upgrade error !");
					}
					else
					{
						if (strlen(resault) > 1)
						{
							log_i("stm32upgrade return %s ", resault);
							if (strstr(resault, "successful") != NULL)
							{
								log_i("stm32upgrade successful !");
							}
							else
							{
								log_e("stm32upgrade fail !");
							}
						}
						else
						{
							log_e("stm32upgrade return fail !");
						}
					}

					log_i("restart uwb");
					system("/etc/init.d/uwb_start restart");
					/* heartup no sleep */
					heartup_sleep = 0;
				}
				else
				{
					log_e("file md5 is not match !");
				}
			}
			else
			{
				log_e("md5 is null !");
			}
		}
		else
		{
			log_e("cmdurl is null !");
		}
	}
	else if (!strcmp(cmd->valuestring, "softupdate"))
	{
		remove("/tmp/ac/tmp.ipk");

		if (url != NULL && strlen(url->valuestring) > 0)
		{
			sprintf(cmd_sh,
					"/usr/bin/wget --no-check-certificate -c -x -t0 \'%s\' -O /tmp/ac/tmp.ipk -o /tmp/ac/wgetipk.log",
					url->valuestring);
			system(cmd_sh);
			log_i("%s", cmd_sh);

			if (md5 != NULL && strlen(md5->valuestring) > 0)
			{
				fp = popen("md5sum /tmp/ac/tmp.ipk | awk '{print $1}' | tr -d '\n'", "r");
				if (fp == NULL)
				{
					log_e("popen error :%d", __LINE__);
					return;
				}
				fgets(gmd5, sizeof(gmd5), fp);
				pclose(fp);
				if (!strcmp(md5->valuestring, gmd5))
				{
					log_i("opkg install /tmp/ac/tmp.ipk");
					system_nowait("opkg install /tmp/ac/tmp.ipk &");
				}
			}
			else
			{
				log_e("md5 is null !");
			}
		}
		else
		{
			log_e("cmdurl is null !");
		}
	}
	else if (!strcmp(cmd->valuestring, "remove"))
	{
		if (url != NULL && strlen(url->valuestring) > 0)
		{
			sprintf(cmd_sh, "opkg remove %s &", url->valuestring);
			system_nowait(cmd_sh);
			log_i("%s", cmd_sh);
		}
		else
		{
			log_e("cmdurl is null !");
		}
	}
	else if (!strcmp(cmd->valuestring, "getinfo"))
	{
		do_getinfo(cloudinterface, encryption, mac, type);
	}
	else if (!strcmp(cmd->valuestring, "passwd"))
	{
		if (url != NULL && strlen(url->valuestring) > 0)
		{
			sprintf(cmd_sh, "echo -e \"%s\\n%s\" | passwd root", url->valuestring, url->valuestring);
			log_i("%s", cmd_sh);
			system(cmd_sh);
		}
		else
		{
			log_e("cmdurl is null !");
		}
	}
	else if (!strcmp(cmd->valuestring, "deny"))
	{
		if (url != NULL && strlen(url->valuestring) > 0)
		{
			log_i("\n%s", cJSON_Print(url));
			do_deny(url);
		}
		else
		{
			log_e("cmdurl is null !");
		}
	}
	else if (!strcmp(cmd->valuestring, "allow"))
	{
		if (url != NULL && strlen(url->valuestring) > 0)
		{
			log_i("\n%s", cJSON_Print(url));
			do_allow(url);
		}
		else
		{
			log_e("cmdurl is null !");
		}
	}
	return;
}

/* gain the current connected client info and add those to a LinkList */
void getclients(LinkList L, void *arg)
{
	char buf[32] = {0};
	char climac[20] = {0};
	int rssi = 0;
	system("acscript cmdclients1");
	FILE *fp = fopen("/tmp/ac/client", "r");
	if (fp == NULL)
	{
		log_w("fopen error, no client info");
		return;
	}
	while (fgets(buf, sizeof(buf), fp) != NULL)
	{
		sscanf(buf, "%s %d", climac, &rssi);
		/* for qsdk wifi rssi */
		rssi = rssi - 95;
		if (locateClient(L, climac) == NULL)
		{
			addClient(L, ((Linearg *)arg)->apmac, climac, rssi);
		}
		else
		{
			updateClient(L, ((Linearg *)arg)->apmac, climac, rssi);
		}

		if (locateClient(((Linearg *)arg)->L, climac) == NULL)
		{
			addClient(((Linearg *)arg)->L, ((Linearg *)arg)->apmac, climac, rssi);
		}
		else
		{
			updateClient(((Linearg *)arg)->L, ((Linearg *)arg)->apmac, climac, rssi);
		}
	}
	fclose(fp);
}

/* check rssi of the client and check the client weather connected or not */
int checkclient(Listnode *node, void *arg)
{
	get_rssi(&(((Linearg *)arg)->rssi));
	int disabled = get_disabled();
	if (locateClient(((Linearg *)arg)->L, node->data.climac) == NULL)
	{
		return 1;
	}
	if ((node->data.avgrssi < ((Linearg *)arg)->rssi) && (disabled == 0))
	{
		preventClient(node);
		return 1;
	}
	return 0;
}

/* to prevert the client connect this ap */
void preventClient(Listnode *node)
{
	char buf[256] = {0}, mbuf[4] = {0};
	int i = 0, ret = 0;

	/*wifi0 wifi1*/
	for (i = 0; i < 2; i++)
	{
		memset(buf, 0, sizeof(buf));
		memset(mbuf, 0, sizeof(mbuf));
		sprintf(buf, "hostapd_cli disassociate %s -p /var/run/hostapd-wifi%d | sed -n '2p' | tr -d \'\\n\'",
				node->data.climac, i); // deauthenticate
		FILE *fp = popen(buf, "r");
		if (fp == NULL)
		{
			log_e("popen error.");
			return;
		}
		fgets(mbuf, sizeof(mbuf), fp);
		pclose(fp);
		if (!strncmp(mbuf, "OK", 2))
		{
			ret++;
		}
	}

	if (ret == 2)
	{
		log_i("prevent %s connect OK.", node->data.climac);
	}
}

/* convert the linklist data to a json array object */
void makecJSON_Array(LinkList L, cJSON *array)
{
	cJSON *client = NULL;
	while ((L = L->next))
	{
		client = cJSON_CreateObject();
		cJSON_AddStringToObject(client, "apmac", L->data.apmac);
		cJSON_AddStringToObject(client, "climac", L->data.climac);
		cJSON_AddNumberToObject(client, "rssi", L->data.avgrssi);
		cJSON_AddItemToArray(array, client);
	}
}

/* send the client info to the server */
void sendClientToserver(const char *cloudinterface, const int encryption, LinkList L, char *mac)
{
	cJSON *array = cJSON_CreateArray();
	makecJSON_Array(L, array);
	devnumbers = cJSON_GetArraySize(array);
	char *clients = cJSON_PrintUnformatted(array);
	int clen = strlen(clients);
	// log_i("%s", clients);
	char url[1024] = {0}, buf[BUFSIZE] = {0};
	char *mdata = alloca(clen + 6);
	sprintf(url, "%s/clients?apmac=%s", cloudinterface, mac);
	sprintf(mdata, "data=%s", clients);
	curl_request(url, POST, mdata, buf);
	/*
	log_i("==============================================");
	log_i("send client info to server  return [%s]", buf);
	log_i("==============================================");
	*/
	free(clients);
	cJSON_Delete(array);
}

void curClient(void *arg, LinkList cL)
{
	if ((arg == NULL) || (cL == NULL))
	{
		return;
	}
	LinkList L = ((Linearg *)arg)->L;
	LinkList p = NULL;

	while (L->next != NULL)
	{
		p = L->next;
		get_rssi(&(((Linearg *)arg)->rssi));
		if (locateClient(cL, p->data.climac) == NULL)
		{
			reduceClient(((Linearg *)arg)->L, p->data.climac);
			continue;
		}
		else if ((p->data.avgrssi < ((Linearg *)arg)->rssi) && (((Linearg *)arg)->disabled == 0))
		{
			preventClient(p);
		}
		L = L->next;
	}
}

void int_handler(int signum)
{
	log_e("%d, ctrl+c", signum);
	exit(1);
}

void term_handler(int signum)
{
	log_e("%d, term killed", signum);
	exit(1);
}

void hup_handler(int signum)
{
	log_e("%d", signum);
	exit(1);
}

void segv_handler(int signum)
{
	log_e("%d, segmentation fault or out of memory", signum);
	_exit(1);
}

void pipe_handler(int signum)
{
	log_e("%d", signum);
	exit(1);
}
