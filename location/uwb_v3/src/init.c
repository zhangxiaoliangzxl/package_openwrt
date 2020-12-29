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
		log_e("%s", "get ip error");
		return -1;
	}

	len = strlen(port);
	if (len < 2)
	{
		log_e("%s", "get prot error");
		return -1;
	}

	len = strlen(tty);
	if (len < 5)
	{
		log_e("%s", "get tty error");
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

	/*stmhexdebug*/
	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(STM32HEXDEBUG, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			if (strlen(cmd_resault) > 0)
			{
				con->stm32hexdebug = atoi(cmd_resault);
			}
		}
		else
		{
			con->stm32hexdebug = 0;
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

	/*socktype*/
	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(SOCKTYPE, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			if (strlen(cmd_resault) > 0)
			{
				if (0 == strcmp(cmd_resault, "udp"))
				{
					con->socktype = SOCK_UDP;
				}
				else
				{
					con->socktype = SOCK_TCP;
				}
			}
		}
		else
		{
			con->socktype = SOCK_TCP;
		}
	}
	pclose(file);

	/*udp2can*/
	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(UDP2CAN, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			if (strlen(cmd_resault) > 0)
			{
				con->udp2can = atoi(cmd_resault);
			}
		}
		else
		{
			con->udp2can = 0;
		}
	}
	pclose(file);

	/* backup */
	memset(cmd_resault, 0, sizeof(cmd_resault));
	file = popen(BACKUP, "r");
	if (file)
	{
		if (NULL != fgets(cmd_resault, 20, file))
		{
			if (strlen(cmd_resault) > 0)
			{
				con->backup = atoi(cmd_resault);
			}
		}
		else
		{
			con->backup = 0;
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
			log_e("debug_serverport is error");
			return -1;
		}

		if (strlen(con->debug_server) < 7) {
			log_e("debug_serverip is error");
			return -1;
		}

	}
	*/

	strcpy(con->ip, ip);
	strcpy(con->mac, mac);
	/*machex*/
	memset(con->mac16, 0, sizeof(con->mac16));
	if (!mac2hex(MAC_FORMAT_ANY, mac, con->mac16))
	{
		log_e("mac2hex failed !");
		return -1;
	}

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

	log_i("################config info#################");
	log_i("\t serveraddr    : %s:%d", ip, atoi(port));
	// log_i("\t syncframe     : %d", con->debug_enable);
	// log_i ("\t debug_server  : %s:%d", con->debug_server, con->debug_serverport);
	log_i("\t tty           : %s", tty);
	log_i("\t apmac         : %s", mac);
	if (con->socktype == SOCK_UDP)
	{
		log_i("\t socktype      : udp");
		log_i("\t udp2can       : %d", con->udp2can);
	}
	else
	{
		log_i("\t socktype      : tcp");
		log_i("\t tcp_nagle     : %d", con->tcp_nagle);
	}

	log_i("\t backup        : %d", con->backup);
	log_i("############################################");
	/*
	log_i("\t uwb.panid     : %s", con->uwb_cfg.panid);
	log_i("\t uwb.ch        : %s", con->uwb_cfg.ch);
	log_i("\t uwb.pcode     : %s", con->uwb_cfg.pcode);
	log_i("\t uwb.matid     : %s", con->uwb_cfg.matid);
	log_i("\t uwb.localid   : %s", con->uwb_cfg.localid);
	log_i("\t uwb.mode      : %s", con->uwb_cfg.mode);
	log_i("\t uwb.role      : %s", con->uwb_cfg.role);
	log_i("\t uwb.palna     : %s", con->uwb_cfg.palna);
	log_i("\t uwb.coarsegain: %s", con->uwb_cfg.coarsegain);
	log_i("\t uwb.finegain  : %s", con->uwb_cfg.finegain);
	log_i("############################################");
	*/
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
