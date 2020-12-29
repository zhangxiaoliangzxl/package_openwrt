#include "init.h"
#include "elog.h"
#include "util.h"

int init(config *con)
{
	FILE *file = NULL;
	int len = 0;
	char host[20], port[20], mac[20], tty[20];
	char cmd_resault[128] = {0};

	memset(host, 0, sizeof(host));
	memset(port, 0, sizeof(port));
	memset(mac, 0, sizeof(mac));

	file = popen(IP, "r");
	if (file)
	{
		fgets(host, 20, file);
	}
	pclose(file);

	file = popen(PORT, "r");
	if (file)
	{
		fgets(port, 20, file);
	}
	pclose(file);

	file = popen(TTY, "r");
	if (file)
	{
		fgets(tty, 20, file);
	}
	pclose(file);

	file = popen(MAC, "r");
	if (file)
	{
		fgets(mac, 20, file);
	}
	pclose(file);

	len = strlen(host);
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

	strcpy(con->serverhost, host);
	con->serverport = atoi(port);
	strcpy(con->tty, tty);
	strcpy(con->mac, mac);

	/*machex*/
	memset(con->mac16, 0, sizeof(con->mac16));
	if (!mac2hex(MAC_FORMAT_ANY, mac, con->mac16))
	{
		log_e("mac2hex failed !");
		return -1;
	}

	log_i("################config info#################");
	log_i("\t serveraddr    : %s:%d", host, atoi(port));
	log_i("\t tty           : %s", tty);
	log_i("\t apmac         : %s", mac);
	log_i("############################################");

	return 0;
}

