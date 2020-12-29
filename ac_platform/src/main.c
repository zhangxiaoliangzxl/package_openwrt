#include <signal.h>

#include "elog/elog.h"
#include "func.h"
#include "init.h"
#include "tcping.h"

#define LOGFILE_NAME "/tmp/debugAC"

typedef enum
{
	start = 0,
	find_ac,
	check_server,
	find_ac_loop,
	start_ac,
	end
} status;

int ac_status = 0;
int heartup_sleep = 0;

static int autofind = 1;

/*udp socket*/
int sockListen;
int sockClient;
struct sockaddr_in recvAddr;
struct sockaddr_in sendAddr;

int receive_acaddr = 0;

char ac_address_cur[256] = {0};
char ac_address[256] = {0};

char static_ipaddr[32], static_netmask[32], static_gateway[32], static_dns[32];

void *subline(void *arg)
{
	int i;
	((Linearg *)arg)->L = createLinkList();
	LinkList L;

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	while (1)
	{
		if (ac_status)
		{
			if (strcmp(apmac, ((Linearg *)arg)->apmac))
			{
				// get_mac(((Linearg *)arg)->apmac);
				sprintf(((Linearg *)arg)->apmac, "%s", apmac);
			}

			L = createLinkList();

			for (i = 0; i < 3; i++)
			{
				getclients(L, arg);
				sleep(5);
			}

			curClient(arg, L);

			sendClientToserver(((Linearg *)arg)->cloudinterface, ((Linearg *)arg)->encryption, ((Linearg *)arg)->L,
							   ((Linearg *)arg)->apmac);

			deleteLinkList(L);
		}
		else
		{
			sleep(5);
		}
	}
	/* delete the Linklist */
	deleteLinkList(((Linearg *)arg)->L);
}

static int udp_init(void)
{
	int ret = -1;
	int optval = 1;

	/* udp send */
	if ((sockClient = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		log_e("sockClient socket fail");

		return ret;
	}

	setsockopt(sockClient, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(int));
	memset(&sendAddr, 0, sizeof(struct sockaddr_in));
	sendAddr.sin_family = AF_INET;

	return 0;
}

static int udp_uninit(void)
{
	close(sockListen);
	close(sockClient);
	sockListen = -1;
	sockClient = -1;
	return 0;
}

static int send_newip_address(char *ip, char *mac, char *broadcast)
{
	char msg[256] = {0};
	int sendBytes = 0;

	sprintf(msg, "airocovapreq=%s,airocovapmac=%s", ip, mac);
	log_i("send new udp msg [%s]", msg);

	/*fill broadcast address*/
	sendAddr.sin_addr.s_addr = inet_addr(broadcast);
	sendAddr.sin_port = htons(SEND_PORT);

	if ((sendBytes = sendto(sockClient, msg, strlen(msg), 0, (struct sockaddr *)&sendAddr, sizeof(struct sockaddr)))
		== -1)
	{
		log_e("udp sockClient sendto fail");
	}

	return 0;
}

void prase_udp_message(char *recvbuf)
{
	/* get ac addrress */
	memset(ac_address, 0, sizeof(ac_address));
	get_value_by_key(recvbuf, "airocovacrsp", ac_address);

	if (strlen(ac_address) > 6)
	{
		/*  ascii / 47 /0 0 */
		if (ac_address[strlen(ac_address) - 1] == 47)
		{
			ac_address[strlen(ac_address) - 1] = 0;
		}

		log_i("receive ac_address [%s]", ac_address);
		receive_acaddr = 1;
	}

	/* get static ap addr */
	char ipaddr[32] = {0};

	get_value_by_key(recvbuf, "airocov_ipaddr", ipaddr);
	if (strlen(ipaddr) < 1)
	{
		log_w("not find static ip info !");
		goto END;
	}

	char netmask[32] = {0};
	char gateway[32] = {0};
	char dns[32] = {0};
	char cmd[256] = {0};

	get_value_by_key(recvbuf, "airocov_netmask", netmask);
	get_value_by_key(recvbuf, "airocov_gateway", gateway);
	get_value_by_key(recvbuf, "airocov_dns", dns);

	log_d("receive ipaddr [%s]", ipaddr);
	log_d("receive netmask [%s]", netmask);
	log_d("receive gateway [%s]", gateway);
	log_d("receive dns [%s]", dns);

	if (strlen(ipaddr) < 7 || strlen(netmask) < 7 || strlen(gateway) < 7 || strlen(dns) < 7)
	{
		log_e("received static ip info is error !");
		goto END;
	}

	if (strcmp(ipaddr, static_ipaddr) || strcmp(netmask, static_netmask) || strcmp(gateway, static_gateway)
		|| strcmp(dns, static_dns))
	{
		log_i("received new static ip info !");
	}
	else
	{
		log_d("received static ip info not changed!");
		goto END;
	}

	/*set static ip addr*/
	log_d("set static ip and reload network !");

	/*
	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "ifconfig br-lan %s netmask %s", ipaddr, netmask);
	system(cmd);
	*/

	/* backup static ip info */
	memset(static_ipaddr, 0, sizeof(static_ipaddr));
	snprintf(static_ipaddr, sizeof(static_ipaddr), "%s", ipaddr);
	memset(static_netmask, 0, sizeof(static_netmask));
	snprintf(static_netmask, sizeof(static_netmask), "%s", netmask);
	memset(static_dns, 0, sizeof(static_dns));
	snprintf(static_dns, sizeof(static_dns), "%s", dns);
	memset(static_gateway, 0, sizeof(static_gateway));
	snprintf(static_gateway, sizeof(static_gateway), "%s", gateway);

	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "uci set network.lan.proto='static'");
	system(cmd);

	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "uci set network.lan.ipaddr='%s'", ipaddr);
	system(cmd);

	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "uci set network.lan.netmask='%s'", netmask);
	system(cmd);

	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "uci set network.lan.gateway='%s'", gateway);
	system(cmd);

	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "uci set network.lan.dns='%s'", dns);
	system(cmd);

	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "uci commit network");
	system(cmd);

	memset(cmd, 0, sizeof(cmd));
	sprintf(cmd, "/etc/init.d/network reload");
	system(cmd);

	/* update new network info */
	get_lan_ip(lanip);
	get_broadcast_by_ifname("br-lan", lan_broadcast);
	send_newip_address(lanip, apmac, lan_broadcast);

END:
	return;
}

/* thread func: udp listen and read */
void *udplisten_thread_func(void *indata)
{
	int optval = 1;

	int recvbytes = 0;
	char recvbuf[1024] = {0};

	/*udp listen*/
	if ((sockListen = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		log_e("sockListen socket fail");
		return 0;
	}

	setsockopt(sockListen, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));
	/*set recv timeout
	struct timeval timeout = {3,0};
	setsockopt(sockListen, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));
	*/

	memset(&recvAddr, 0, sizeof(struct sockaddr_in));
	recvAddr.sin_family = AF_INET;
	recvAddr.sin_port = htons(LISTEN_PORT);
	recvAddr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sockListen, (struct sockaddr *)&recvAddr, sizeof(struct sockaddr)) == -1)
	{
		log_e("sockListen bind fail");

		return 0;
	}

	/* read udp data */
	int addrLen = sizeof(struct sockaddr_in);
	while (1)
	{
		memset(recvbuf, 0, sizeof(recvbuf));
		recvbytes = recvfrom(sockListen, recvbuf, 1024, 0, (struct sockaddr *)&recvAddr, (socklen_t *)&addrLen);
		if (recvbytes != -1)
		{
			recvbuf[recvbytes] = '\0';
			log_d("------ udplisten_thread ------");
			log_i("receive ac_server messgse:%s", recvbuf);

			if (recvbytes > 0)
			{
				/*prase udp messges*/
				prase_udp_message(recvbuf);
			}
			log_d("------------------------------");
		}
		else
		{
			log_i("no udp msg recv from server");
		}
	}

	return 0;
}

static int find_ac_address(char *ip, char *mac, char *broadcast)
{
	int ret = -1;
	char msg[256] = {0};

	int sendBytes = 0;
	int i = 0;

	sprintf(msg, "airocovapreq=%s,airocovapmac=%s", ip, mac);

	/* init receive_acaddr status */
	receive_acaddr = 0;

	/*fill broadcast address*/
	sendAddr.sin_addr.s_addr = inet_addr(broadcast);
	sendAddr.sin_port = htons(SEND_PORT);

	if ((sendBytes = sendto(sockClient, msg, strlen(msg), 0, (struct sockaddr *)&sendAddr, sizeof(struct sockaddr)))
		== -1)
	{
		log_e("udp sockClient sendto fail");
		// sleep(3);
		// return ret;
	}
	// log_i("udp send msg [%s], msgLen=%d", msg, strlen(msg));

	/*recv*/
	for (i = 0; i < 3; i++)
	{
		sleep(1);
		if (receive_acaddr == 1)
		{
			break;
		}
	}

	if (receive_acaddr == 1)
	{
		ret = 1;
		log_i("find ac addr from server");
	}
	else
	{
		log_i("not find ac addr from server");
	}

	return ret;
}

static int update_ac_address_config(char *ac_address)
{
	char cmd[256] = {0};

	sprintf(cmd, "uci set aconf.normal.cloudinterface=%s;uci commit aconf", ac_address);
	system(cmd);

	return 0;
}

/*ap_heart_up*/
static int ap_heart_up(cJSON *heart, cJSON *initInfo, char *info, int systype)
{
	int error_num = 0;
	int error_code = 0;
	int resultup = 0;

	cJSON *ret = NULL, *cmdtype = NULL, *cmd = NULL, *cmdurl = NULL, *errorcode = NULL, *key = NULL;

	while (1)
	{
		/* 上报心跳 */
		log_d("------------ heart_up ------------");
		heartup_sleep = 1;
		error_code = 0;
		ret = heart_up(marg.cloudinterface, marg.encryption, heart, apmac);
		/* check heart_up succesfull */
		if (ret == NULL)
		{
			log_w("heart_up return is error !");
			error_num++;

			if (error_num > 5)
			{
				// error_num = 0;
				break;
			}

			sleep(10);
			continue;
		}

		if (error_num > 5)
		{
			// error_num = 0;
			break;
		}

		/* 心跳回复判断 */
		errorcode = cJSON_GetObjectItem(ret, ERRORCODE);
		key = cJSON_GetObjectItem(ret, "key");

		if (errorcode == NULL || key == NULL)
		{
			log_e("heart_up return not find code or key !");
			// sleep(10);
			// continue;
			error_num++;
			goto err;
		}

		/* error code */
		if (errorcode->type == cJSON_Number)
		{
			error_code = errorcode->valueint;
		}
		else if (errorcode->type == cJSON_String && strlen(errorcode->valuestring))
		{
			error_code = atoi(errorcode->valuestring);
		}

		if (error_code != 200)
		{
			log_e("heart_up return errorcode error !");
			error_num++;
			goto err;
		}

		/* check key */
		if (key->type == cJSON_String && strlen(key->valuestring))
		{
			if (check_key(key->valuestring))
			{
				/* key验证失败 */
				log_e("heart_up check_key error !");
				// system("acscript cmdtime");
				error_num++;
				goto err;
			}
		}
		else
		{
			log_e("heart_up return key error !");
			error_num++;
			goto err;
		}

		error_num = 0;

		cmdtype = cJSON_GetObjectItem(ret, "cmdtype");
		if (cmdtype != NULL && strlen(cmdtype->valuestring) > 0)
		{
			if (!strcmp("generate", cmdtype->valuestring))
			{
				/* 基础控制命令 */
				cmd = cJSON_GetObjectItem(ret, "cmd");
				if (cmd != NULL && strlen(cmd->valuestring) > 0)
				{
					log_i("generate cmdstr: %s", cmd->valuestring);
					generate_cmd(marg.cloudinterface, marg.encryption, ret, apmac, systype);
				}
			}
			else if (!strcmp("netconf", cmdtype->valuestring))
			{
				resultup = 1;
				/* 配置修改命令 */
				cmdurl = cJSON_GetObjectItem(ret, "cmdurl");
				if (cmdurl != NULL && strlen(cmdurl->valuestring) > 0)
				{
					log_i("netconf cmdurl: %s", cmdurl->valuestring);
					net_conf(marg.cloudinterface, marg.encryption, cmdurl->valuestring, apmac, systype, &resultup);

					if (resultup == 1)
					{
						/*cmd update end, result*/
						initInfo = init(systype);
						info = cJSON_PrintUnformatted(initInfo);
						cJSON_Delete(initInfo);
						result_up(marg.cloudinterface, marg.encryption, info, apmac);
						free(info);
					}
				}
			}
			else
			{
				/* 收到未知命令 */
				log_w("the command type %s is undefined.", cmdtype->valuestring);
			}
		}
	err:
		cJSON_Delete(ret);
		if (heartup_sleep == 1)
		{
			sleep(10);
		}
	}

	return -1;
}

static void config_init(void)
{
	char buf[256] = {0};
	FILE *fp = NULL;

	/*app switch*/
	fp = popen("uci -q get aconf.normal.disabled | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("init config popen error");
		exit(0);
	}
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	pclose(fp);

	if (atoi(buf) == 1)
	{
		log_e("==> program switch disabled,exit <==");
		exit(0);
	}

	/*autofind switch*/
	fp = popen("uci -q get aconf.normal.autofind | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("init config get autofind error");
		exit(0);
	}
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	pclose(fp);

	if (strlen(buf) > 0)
	{
		if (atoi(buf) != 1)
		{
			autofind = 0;
			log_d("==> autofind is disabled <==");
		}
		else
		{
			autofind = 1;
			log_d("==> autofind is enabled <==");
		}
	}
	else
	{
		autofind = 1;
		log_d("==> autofind is enabled <==");
	}

	get_mac(apmac);
	strcpy(marg.apmac, apmac);

	/* get cloudinterface */
	fp = popen("uci -q get aconf.normal.cloudinterface | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("init config popen error");
		exit(0);
	}
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	pclose(fp);

	sprintf(ac_address_cur, "%s", buf);
	marg.cloudinterface = ac_address_cur;

	/* get https */
	fp = popen("uci -q get aconf.normal.encrypton | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("init config popen error");
		exit(0);
	}
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	pclose(fp);

	marg.encryption = atoi(buf);

	/* get client disabled */
	fp = popen("uci -q get aconf.client.disabled | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("init config popen error");
		exit(0);
	}
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	pclose(fp);

	marg.disabled = atoi(buf);

	/* get client rssi */
	fp = popen("uci -q get aconf.client.rssi | tr -d '\n'", "r");
	if (fp == NULL)
	{
		log_e("init config popen error");
		exit(0);
	}
	memset(buf, 0, sizeof(buf));
	fgets(buf, sizeof(buf), fp);
	pclose(fp);

	marg.rssi = atoi(buf);

	return;
}

static void logger_init(void)
{
	/* elog sys time init */
	elog_time_init();

	/* close printf buffer */
	setbuf(stdout, NULL);
	/* initialize EasyLogger */

	ElogFileCfg cfg;
	cfg.name = LOGFILE_NAME;
	cfg.max_size = 1 * 1024 * 1024;
	cfg.max_rotate = 0;

	elog_init(&cfg);

	elog_set_fmt(ELOG_LVL_ASSERT, ELOG_FMT_ALL & ~ELOG_FMT_TAG);
	elog_set_fmt(ELOG_LVL_VERBOSE, ELOG_FMT_ALL & ~ELOG_FMT_TAG);
	elog_set_fmt(ELOG_LVL_ERROR, ELOG_FMT_TIME);
	elog_set_fmt(ELOG_LVL_WARN, ELOG_FMT_TIME);
	elog_set_fmt(ELOG_LVL_INFO, ELOG_FMT_TIME);
	elog_set_fmt(ELOG_LVL_DEBUG, ELOG_FMT_TIME);
#ifdef ELOG_COLOR_ENABLE
	elog_set_text_color_enabled(true);
#endif
	/* start EasyLogger */
	elog_start();

	/* dynamic set enable or disable for output logs (true or false) */
	elog_set_output_enabled(true);
	/* dynamic set enable or disable for output stdout (true or false) */
#ifdef DEBUG_STDOUT
	elog_set_stdout_enabled(true);
#else
	elog_set_stdout_enabled(false);
#endif
	/* dynamic set output logs's level (from ELOG_LVL_ASSERT to ELOG_LVL_VERBOSE) */
	elog_set_filter_lvl(ELOG_LVL_DEBUG);

	/* dynamic set output logs's filter for tag */
	// elog_set_filter_tag("main");
	/* dynamic set output logs's filter for keyword */
	// elog_set_filter_kw("Hello");
}

/* main line */
int main(int argc, char *argv[])
{
	char buf[64] = {0};
	pthread_t thread1;
	pthread_t thread_udplisten;

	int udp_count = 0;
	// int udp_sleep = 0;
	int ret;
	int loop_num = 0;

	/* for url */
	char url_abspath[128] = {0};
	char url_host[128] = {0};
	char server_port[16] = {0};
	unsigned int url_port = 0;

	/* logger init */
	logger_init();

	/* libcurl init */
	my_curl_init();

	/*系统信号抓取*/
	signal(SIGINT, int_handler);
	signal(SIGTERM, term_handler);
	signal(SIGHUP, hup_handler);
	signal(SIGSEGV, segv_handler);
	// signal(SIGPIPE, pipe_handler);

	log_d("==> init <==");

	ac_is_running();

	/*config init*/
	memset(&marg, 0, sizeof(Linearg));
	config_init();

	memset(static_ipaddr, 0, sizeof(static_ipaddr));
	memset(static_netmask, 0, sizeof(static_netmask));
	memset(static_gateway, 0, sizeof(static_gateway));
	memset(static_dns, 0, sizeof(static_dns));

	cJSON *heart;
	int systype = 0;
	char serverip[LITTLEBUF], uptime[512];

	/*run after ap get ip*/
	do
	{
		if (1 == get_ap_ip())
		{
			memset(buf, 0, sizeof(buf));
			sprintf(buf, "echo 2 > %s/network", STATUS_PATH);
			system(buf);
			break;
		}

		memset(buf, 0, sizeof(buf));
		sprintf(buf, "echo 1 > %s/network", STATUS_PATH);
		system(buf);

		log_w("ap ip is null, wait ap get ip!");
		sleep(10);

	} while (1);

	/*get network broadcast*/
	get_broadcast_by_ifname("br-lan", lan_broadcast);

	/* run status */
	status run_status;
	run_status = start;

	while (1)
	{
		switch (run_status)
		{
			case start:
				log_d("------run_status is start------");
				/* app init */
				{
					data_init(systype);

					/* get the current system type */
					systype = getsystype(systemtype);

#if 0
	                /* create client thread */
	                r = pthread_create(&thread1, NULL, subline, &marg);
	                if (r != 0)
	                {
	                    log_e("pthread_create failed.");
	                }
	                pthread_detach(thread1);
#endif
					if (1 == autofind)
					{
						udp_init();

						/* udp listen thread */
						ret = pthread_create(&thread_udplisten, NULL, udplisten_thread_func, NULL);
						if (ret != 0)
						{
							log_e("udplisten thread create failed!");
						}
						pthread_detach(thread_udplisten);

						/*next status is find ac*/
						run_status = find_ac;
					}
					else
					{
						/*next status is check_server*/
						run_status = check_server;
					}
				}

				break;
			case find_ac:
				log_d("------run_status is find_ac------");
				{
					// sprintf(broadcast, "192.168.23.255");
					memset(ac_address, 0, sizeof(ac_address));
					if (find_ac_address(lanip, apmac, lan_broadcast) != 1)
					{
						udp_count++;
						if (udp_count >= 3)
						{
							udp_count = 0;
							if (strlen(ac_address_cur) > 0)
							{
								log_i("have old ac server address, use old ac address");
								run_status = check_server;
							}
							else
							{
								sleep(60 - 3);
								run_status = find_ac_loop;
							}
						}
						else
						{
							sleep(5 - 3);
						}
					}
					else
					{
						// log_i("find ac server address !");
						/*update config for ac address*/
						if (strcmp(ac_address_cur, ac_address) != 0)
						{
							log_d("update config && apply new ac address !");
							update_ac_address_config(ac_address);
							memset(ac_address_cur, 0, sizeof(ac_address_cur));
							sprintf(ac_address_cur, "%s", ac_address);
							marg.cloudinterface = ac_address_cur;
						}
						run_status = check_server;
					}
				}

				break;
			case check_server:
				log_d("------run_status is check_server------");
				{
					ac_status = 0;
					// get_server_ip(serverip);
					if (strlen(marg.cloudinterface) < 6)
					{
						log_e("ac server address is null, will exit");
						run_status = end;
						break;
					}

					/* get url host */
					{
						memset(url_host, 0, sizeof(url_host));
						memset(url_abspath, 0, sizeof(url_abspath));
						memset(server_port, 0, sizeof(server_port));

						ret = parse_url(ac_address_cur, "http:", url_host, &url_port, url_abspath);
						if (ret < 0)
						{
							memset(url_host, 0, sizeof(url_host));
							memset(url_abspath, 0, sizeof(url_abspath));
							memset(server_port, 0, sizeof(server_port));

							ret = parse_url(ac_address_cur, "https:", url_host, &url_port, url_abspath);
						}

						if (ret < 0)
						{
							log_e("server url %s is error !", ac_address_cur);
						}
						else
						{
							log_d("addr:%s port:%d path:%s", url_host, url_port, url_abspath);

							snprintf(server_port, sizeof(server_port), "%d", url_port);
							strncpy(serverip, url_host, sizeof(serverip));
							log_d("server addr:%s", serverip);
						}
					}

					// if (!env_check(serverip))
					if (tcping(serverip, server_port, 1, 1, 2, 0))
					{
						memset(buf, 0, sizeof(buf));
						sprintf(buf, "echo 1 > %s/network", STATUS_PATH);
						system(buf);

						if (1 == autofind)
						{
							log_w("ac server %s:%s is unreachable, find the new ac server", serverip, server_port);
							run_status = find_ac_loop;
						}
						else
						{
							log_w("ac server %s:%s is unreachable, will check server again after some time", serverip,
								  server_port);
							run_status = check_server;
						}

						sleep(60);
						break;
					}

					/* 检测通信 */
					if (server_check(marg.cloudinterface, marg.encryption, apmac, systype) < 0)
					{
						memset(buf, 0, sizeof(buf));
						sprintf(buf, "echo 2 > %s/network", STATUS_PATH);
						system(buf);

						if (1 == autofind)
						{
							log_w("check ac server is not work, find the new ac server");
							run_status = find_ac_loop;
						}
						else
						{
							log_w("check ac server is not work, will check server again after some time");
							run_status = check_server;
						}

						sleep(60);
					}
					else
					{
						sprintf(uptime, "/usr/sbin/ntpclient -c 1 -i 1 -s -h %s", serverip);
						system(uptime);
						ac_status = 1;
						run_status = start_ac;
					}
				}

				/* for test */
				// run_status = start_ac;
				break;
			case find_ac_loop:
				log_d("------run_status is find_ac_loop------");
				{
					/* update new network info */
					get_lan_ip(lanip);
					get_broadcast_by_ifname("br-lan", lan_broadcast);

					memset(ac_address, 0, sizeof(ac_address));
					if (find_ac_address(lanip, apmac, lan_broadcast) != 1)
					{
						loop_num++;
						/*
						udp_count++;

						if (udp_count >= 6 ) {
							udp_count = 6;
						}

						udp_sleep = udp_count * 10;
						sleep(udp_sleep-3);
						*/
						sleep(60 - 3);

						/* check ac server is recovery ? */
						if (loop_num > 2)
						{
							loop_num = 0;
							if (strlen(ac_address_cur) > 0)
							{
								run_status = check_server;
								log_d("******check ac server is recovery ?******");
							}
						}
					}
					else
					{
						// log_i("find ac server address !");
						/*update config for ac address*/
						if (strcmp(ac_address_cur, ac_address) != 0)
						{
							log_d("update config && apply new ac address !");
							update_ac_address_config(ac_address);
							memset(ac_address_cur, 0, sizeof(ac_address_cur));
							sprintf(ac_address_cur, "%s", ac_address);
							marg.cloudinterface = ac_address_cur;
						}
						run_status = check_server;
					}
				}

				break;
			case start_ac:
				log_d("------run_status is start_ac------");
				{
					memset(buf, 0, sizeof(buf));
					sprintf(buf, "echo 0 > %s/network", STATUS_PATH);
					system(buf);

					/* result_up config */
					cJSON *initInfo = init(systype);
					char *info = cJSON_PrintUnformatted(initInfo);

					/*
					char * str = cJSON_Print(initInfo);
					log_i("init info :\n%s", str);
					free(str);
					*/

					log_d("------------ result_up ------------");
					int ret_result_up = result_up(marg.cloudinterface, marg.encryption, info, apmac);
					free(info);
					cJSON_Delete(initInfo);

					/* check result_up */
					if (ret_result_up < 0)
					{
						run_status = check_server;
						break;
					}

					/* heart_up && recv cmd */

					/* 初始化心跳 */
					heart = heart_init(systype);

					if (ap_heart_up(heart, initInfo, info, systype) < 0)
					{
						log_w("******ap heart_up long time error, check ac server******");
						run_status = check_server;
					}

					cJSON_Delete(heart);
				}

				// run_status = end;
				break;
			case end:
			default:
				printf("run_status is end or error, program exit!\n");
				goto END;
		}

		// sleep(1);
	}

END:
#if 0
    ret = -1;
    do {
        ret = pthread_cancel(thread1);
    } while (ret != 0) ;
#endif

	if (1 == autofind)
	{
		udp_uninit();

		ret = -1;
		do
		{
			ret = pthread_cancel(thread_udplisten);
		} while (ret != 0);
	}

	my_curl_uninit();

	return 0;
}
