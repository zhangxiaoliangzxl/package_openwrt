#include "init.h"
#include "util.h"

int init(config *con) /* 初始化配置 */
{
	FILE *file = NULL;
	int len = 0;
	char ip[20], port[20], mac[20], tty[20];
	char cmd_resault[128] = {0};

	memset(ip, 0, sizeof(ip));
	memset(port, 0, sizeof(port));
	memset(mac, 0, sizeof(mac));

	file = popen(IP, "r"); /* 获取TCP服务器的IP地址 */
	if (file)
	{
		fgets(ip, 20, file);
	}
	pclose(file);

	file = popen(PORT, "r"); /* 获取TCP服务器的端口地址 */
	if (file)
	{
		fgets(port, 20, file);
	}
	pclose(file);

	file = popen(TTY, "r"); /* 获取串口设备号 */
	if (file)
	{
		fgets(tty, 20, file);
	}
	pclose(file);

	file = popen(MAC, "r"); /* 获取主AP的MAC地址 */
	if (file)
	{
		fgets(mac, 20, file);
	}
	pclose(file);

	len = strlen(ip); /* 数据有效性判断 */
	if (len < 2)
	{
		LOG_LOG("%s", "get ip error");
		return -1;
	}

	len = strlen(port);
	if (len < 2)
	{
		LOG_LOG("%s", "get prot error");
		return -1;
	}

	len = strlen(tty);
	if (len < 12)
	{
		LOG_LOG("%s", "get tty error");
		return -1;
	}

	/*print_enable*/
	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(PRINT_ENABLE, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			if (strlen(cmd_resault) > 0)
			{
				con->print_enable = atoi(cmd_resault);
			}
		}
		else
		{
			con->print_enable = 0;
		}
	}
	pclose(file);

	/*tcp_nagle*/
	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(TCP_NAGLE, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			if (strlen(cmd_resault) > 0)
			{
				con->tcp_nagle = atoi(cmd_resault);
			}
		}
		else
		{
			con->tcp_nagle = 0;
		}
	}
	pclose(file);

	/*debug server*/
	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(DEBUG_ENABLE, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			if (strlen(cmd_resault) > 0)
			{
				con->debug_enable = atoi(cmd_resault);
			}
		}
		else
		{
			con->debug_enable = 0;
		}
	}
	pclose(file);

	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(DEBUG_SERVERPORT, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			if (strlen(cmd_resault) > 0)
			{
				con->debug_serverport = atoi(cmd_resault);
			}
		}
		else
		{
			con->debug_serverport = 0;
		}
	}
	pclose(file);

	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(DEBUG_SERVERIP, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			if (strlen(cmd_resault) > 0)
			{
				strcpy(con->debug_server, cmd_resault);
			}
		}
	}
	pclose(file);

	/*
	if (1 == con->debug_enable) {
		if (con->debug_serverport < 1) {
			LOG_LOG("debug_serverport is error");
			return -1;
		}

		if (strlen(con->debug_server) < 7) {
			LOG_LOG("debug_serverip is error");
			return -1;
		}

	}
	*/

	strcpy(con->ip, ip); /* 保存配置到当前的目标配置结构体 */
	strcpy(con->mac, mac);
	/*machex*/
	memset(con->mac16, 0, sizeof(con->mac16));
	mac2hex(mac, con->mac16);

	strcpy(con->tty, tty);
	con->port = atoi(port);

	memset(&con->uwb_cfg, 0, sizeof(UWB_CFG));

	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(UWB_PANID, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			strcpy(con->uwb_cfg.panid, cmd_resault);
		}
	}
	pclose(file);

	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(UWB_CH, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			strcpy(con->uwb_cfg.ch, cmd_resault);
		}
	}
	pclose(file);

	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(UWB_PCODE, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			strcpy(con->uwb_cfg.pcode, cmd_resault);
		}
	}
	pclose(file);

	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(UWB_MATID, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			strcpy(con->uwb_cfg.matid, cmd_resault);
		}
	}
	pclose(file);

	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(UWB_LOCALID, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			strcpy(con->uwb_cfg.localid, cmd_resault);
		}
	}
	pclose(file);

	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(UWB_MODE, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			strcpy(con->uwb_cfg.mode, cmd_resault);
		}
	}
	pclose(file);

	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(UWB_PALNA, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			strcpy(con->uwb_cfg.palna, cmd_resault);
		}
	}
	pclose(file);

	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(UWB_COARSEGAIN, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			strcpy(con->uwb_cfg.coarsegain, cmd_resault);
		}
	}
	pclose(file);

	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(UWB_FINEGAIN, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			strcpy(con->uwb_cfg.finegain, cmd_resault);
		}
	}
	pclose(file);

	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(UWB_ROLE, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			strcpy(con->uwb_cfg.role, cmd_resault);
		}
	}
	pclose(file);

	LOG_LOG("################config info#################");
	LOG_LOG("\t serveraddr    : %s:%d", ip, atoi(port));
	LOG_LOG("\t syncframe     : %d", con->debug_enable);
	// LOG_LOG ("\t debug_server  : %s:%d", con->debug_server, con->debug_serverport);
	LOG_LOG("\t tty           : %s", tty);
	LOG_LOG("\t apmac         : %s", mac);
	LOG_LOG("\t tcp_nagle     : %d", con->tcp_nagle);
	LOG_LOG("############################################");
	LOG_LOG("\t uwb.panid     : %s", con->uwb_cfg.panid);
	LOG_LOG("\t uwb.ch        : %s", con->uwb_cfg.ch);
	LOG_LOG("\t uwb.pcode     : %s", con->uwb_cfg.pcode);
	LOG_LOG("\t uwb.matid     : %s", con->uwb_cfg.matid);
	LOG_LOG("\t uwb.localid   : %s", con->uwb_cfg.localid);
	LOG_LOG("\t uwb.mode      : %s", con->uwb_cfg.mode);
	LOG_LOG("\t uwb.role      : %s", con->uwb_cfg.role);
	LOG_LOG("\t uwb.palna     : %s", con->uwb_cfg.palna);
	LOG_LOG("\t uwb.coarsegain: %s", con->uwb_cfg.coarsegain);
	LOG_LOG("\t uwb.finegain  : %s", con->uwb_cfg.finegain);
	LOG_LOG("############################################");

	return 0;
}

int save_uwb_config(config *con)
{
	char cmd[128];

	memset(cmd, 0, 128);
	snprintf(cmd, 128, "uci set uwbcon.uwb.matid='%s'", con->uwb_cfg.matid);
	system(cmd);

	memset(cmd, 0, 128);
	snprintf(cmd, 128, "uci set uwbcon.uwb.localid='%s'", con->uwb_cfg.localid);
	system(cmd);

	memset(cmd, 0, 128);
	snprintf(cmd, 128, "uci set uwbcon.uwb.panid='%s'", con->uwb_cfg.panid);
	system(cmd);

	memset(cmd, 0, 128);
	snprintf(cmd, 128, "uci set uwbcon.uwb.ch='%s'", con->uwb_cfg.ch);
	system(cmd);

	memset(cmd, 0, 128);
	snprintf(cmd, 128, "uci set uwbcon.uwb.pcode='%s'", con->uwb_cfg.pcode);
	system(cmd);

	memset(cmd, 0, 128);
	snprintf(cmd, 128, "uci set uwbcon.uwb.palna='%s'", con->uwb_cfg.palna);
	system(cmd);

	memset(cmd, 0, 128);
	snprintf(cmd, 128, "uci set uwbcon.uwb.coarsegain='%s'", con->uwb_cfg.coarsegain);
	system(cmd);

	memset(cmd, 0, 128);
	snprintf(cmd, 128, "uci set uwbcon.uwb.finegain='%s'", con->uwb_cfg.finegain);
	system(cmd);

	memset(cmd, 0, 128);
	snprintf(cmd, 128, "uci commit uwbcon");
	system(cmd);

	return 0;
}

