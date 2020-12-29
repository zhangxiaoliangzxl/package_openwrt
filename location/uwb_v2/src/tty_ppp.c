/*************************************************************************
>  File Name: tty_ppp.c
>  Author: zxl
>  Mail:
>  Created Time: Wed 20 Mar 2019 02:33:03 PM CST
*************************************************************************/
#include <assert.h>
#include <errno.h>
#include <sys/epoll.h>

#include "init.h"
#include "log.h"
#include "tty_ppp.h"
#include "uwb.h"

extern FILE *fp_jiffies;
extern config *uwbconfig;

static int ppp_encode(unsigned char *in, int in_len, unsigned char *out, int *out_len)
{
	unsigned char *pi, *po;
	int i, tmp_len;

	pi = in;
	po = out;
	tmp_len = in_len;

	for (i = 0; i < in_len; i++)
	{
		if (*pi == PPP_FRAME_FLAG || *pi == PPP_FRAME_ESC || *pi < PPP_FRAME_ENC)
		{
			*po = PPP_FRAME_ESC;
			po++;
			tmp_len++;
			*po = *pi ^ PPP_FRAME_ENC;
		}
		else
		{
			*po = *pi;
		}

		pi++;
		po++;
	}
	*out_len = tmp_len;

	return 0;
}

static int ppp_decode(unsigned char *in, int in_len, unsigned char *out, int *out_len)
{
	unsigned char *pi, *po;
	int i, tmp_len;

	pi = in;
	po = out;
	tmp_len = in_len;

	for (i = 0; i < in_len; i++)
	{
		if (*pi == PPP_FRAME_ESC)
		{
			pi++;
			tmp_len--;
			*po = *pi ^ PPP_FRAME_ENC;

			i++;
		}
		else
		{
			*po = *pi;
		}

		pi++;
		po++;
	}
	*out_len = tmp_len;

	return 0;
}

static void hex_data(unsigned char *hex, int n, char *out)
{
	int i = 0;
	if (n < 1 || out == NULL)
	{
		return;
	}

	for (i = 0; i < n; i++)
	{
		sprintf(&out[i * 2], "%02x", (unsigned char)hex[i]);
	}
}

#if 1
void printf_hex(char *title, unsigned char *hex, int n)
{
	int i;
	if (n < 1)
	{
		return;
	}
	printf("%s , %d bytes\n", title, n);
	printf("-----------------------------------------------------------\n");
	for (i = 0; i < n; i++)
	{
		if (i % 16 == 0 && i != 0)
			printf("\r\n");
		printf("%02x ", (unsigned char)hex[i]);
	}
	printf("\r\n");
	printf("------------------------------------------------------------\n");
}
#else
void printf_hex(char *title, unsigned char *hex, int n)
{
	size_t size = n;
	const uint8_t *c = hex;
	assert(hex);
	if (size < 1)
	{
		return;
	}

	printf("%s , %d bytes\n", title, n);
	printf("----------------------------------------------------------------\n");

	while (size > 0)
	{
		unsigned i;
		for (i = 0; i < 16; i++)
		{
			if (i < size)
				printf("%02x ", c[i]);
			else
				printf("   ");
		}
		for (i = 0; i < 16; i++)
		{
			if (i < size)
				printf("%c", c[i] >= 32 && c[i] < 127 ? c[i] : '.');
			else
				printf(" ");
		}

		printf("\n");
		c += 16;
		if (size <= 16)
			break;
		size -= 16;
	}
	printf("----------------------------------------------------------------\n");
}

#endif

char datatype_need_ack(char datatype)
{
	return 0x80 | datatype;
}

int recevice_from_tty(int fd, Thread_data *ttyread_buffer)
{
	int ret = 0;
	char readbuff[READSIZE + 1] = {0};
	int epid;
	int recv_len;

	ttyread_data *read_data = NULL;
	read_data = (ttyread_data *)malloc(sizeof(ttyread_data));

	/* epoll init */
	epid = epoll_create(1);
	struct epoll_event event_tty;
	event_tty.events = EPOLLIN | EPOLLET; // ET mode
	event_tty.data.fd = fd;
	ret = epoll_ctl(epid, EPOLL_CTL_ADD, fd, &event_tty);
	if (ret != 0)
	{
		LOG_LOG("set epoll error!");
	}

	memset(readbuff, 0, READSIZE + 1);

	while (TRUE)
	{
		/* wait epoll event */
		ret = epoll_wait(epid, &event_tty, 1, 100);
		if (ret > 0)
		{
			if (event_tty.events & EPOLLIN)
			{
				/* read until buffer is empty */
				while (TRUE)
				{
					memset(readbuff, 0, READSIZE);
					recv_len = read(event_tty.data.fd, readbuff, READSIZE);

					if (recv_len > 0)
					{
						readbuff[recv_len] = '\0';
						/* add to read_buffer */
						memset(read_data, 0, sizeof(ttyread_data));
						memcpy(read_data->data, readbuff, recv_len);
						read_data->len = recv_len;

						pthread_mutex_lock(&ttyread_buffer->mutex);
						if (0 == Rbuf_AddOne(ttyread_buffer->ring_buffer, read_data))
						{
							LOG_LOG("ttyread ring buffer is full");
						}
						pthread_cond_signal(&ttyread_buffer->cond);
						pthread_mutex_unlock(&ttyread_buffer->mutex);
						/* add to string_buffer end */

						if (recv_len < READSIZE)
						{
							/* buffer is empty, should break while */
							break;
						}
					}
					else if (recv_len == 0)
					{
						/* buffer is empty, should break while */
						// printf("no data read from tty, errorid %d %s !\n", errno, strerror(errno));

						if (errno == EINVAL)
						{
							// printf("read from tty error, maybe tty is error !\n");
							LOG_LOG("read from tty error, errorid %d %s !\n", errno, strerror(errno));
							close(epid);
							free(read_data);
							return -2;
						}
						else
						{
							break;
						}
					}
					else if (recv_len < 0)
					{
						/* read from tty error , maybe need return */
						if (errno == EAGAIN)
						{
							// printf("tty buffer is empty, errorid %d %s !\n", errno, strerror(errno));
							break;
						}
						else
						{
							// printf("read from tty error, errorid %d %s !\n", errno, strerror(errno));
							LOG_LOG("read from tty error, errorid %d %s !", errno, strerror(errno));
							close(epid);
							free(read_data);
							return -2;
						}
					}
				}
			}
			else if (event_tty.events & EPOLLERR || event_tty.events & EPOLLHUP || (!event_tty.events & EPOLLIN))
			{
				LOG_LOG("epoll_wait return error event , maybe tty is error!\n");
				/* close epoll id */
				close(epid);
				free(read_data);
				return -2;
			}
		}
		else if (ret <= 0)
		{
			/* */
		}
	}

	close(epid);
	free(read_data);
	return 0;
}

static void parse_uwb_heart(ppp_uwb_data *uwb_data)
{
	if (uwb_data->length != sizeof(syshrt_type))
	{
		LOG_LOG("data length is not match syshrt_type");
		return;
	}

	if (uwb_data->type == DATATYPE_REPORT && uwb_data->port == REPORT_SYSHRT)
	{
		char cmd[128];

		syshrt_type *pdata = (syshrt_type *)(uwb_data->data);

		LOG_LOG("(uwbheart)localid %d, runtime %u, payload %u", pdata->aid, pdata->runtime, pdata->payload);

		/* recode heart time for ac */
		memset(cmd, 0, sizeof(cmd));
		JSONDATA_TIME(&uwb_data->frame_time, cmd);
		write_jiffies(fp_jiffies, cmd);

		memset(cmd, 0, 128);
		snprintf(cmd, 128, "echo %u > /tmp/uwb_runtime", pdata->runtime);
		system(cmd);

		memset(cmd, 0, 128);
		snprintf(cmd, 128, "echo %u > /tmp/uwb_payload", pdata->payload);
		system(cmd);
	}
	return;
}

extern config *uwbconfig;

static void parse_uwb_cfgack(ppp_uwb_data *uwb_data)
{
	LOG_LOG("receive a uwb cfg ack !");
	if (uwb_data->length != sizeof(uwb_vercfg_type))
	{
		LOG_LOG("data length is not match uwb_vercfg_type !");
		return;
	}

	uwb_vercfg_type *vercfg = (uwb_vercfg_type *)(uwb_data->data);
	uwbcfg_ctrlbit_type *cfg_ctrlbit = (uwbcfg_ctrlbit_type *)(&vercfg->ctrlbit);

	LOG_LOG("(uwbcfg)-----------------------------");
	LOG_LOG("(uwbcfg)  matid %u", vercfg->mid);
	LOG_LOG("(uwbcfg)  localid %u", vercfg->aid);
	LOG_LOG("(uwbcfg)  panid %u", vercfg->panid);
	LOG_LOG("(uwbcfg)  channel %u", vercfg->channel);
	LOG_LOG("(uwbcfg)  coarsegain %u", vercfg->coarsegain);
	LOG_LOG("(uwbcfg)  finegain %.1f", ((float)vercfg->finegain * 1.0) / 10);
	LOG_LOG("(uwbcfg)  pcode %u", vercfg->preamble);
	LOG_LOG("(uwbcfg)  pa %d", cfg_ctrlbit->pa);
	LOG_LOG("(uwbcfg)  pwr %d", cfg_ctrlbit->pwr);
	LOG_LOG("(uwbcfg)  uwbversion %u", vercfg->version);
	LOG_LOG("(uwbcfg)-----------------------------");

	if (NULL != uwbconfig)
	{
		memset(uwbconfig->uwb_cfg.matid, 0, sizeof(uwbconfig->uwb_cfg.matid));
		snprintf(uwbconfig->uwb_cfg.matid, sizeof(uwbconfig->uwb_cfg.matid), "%u", vercfg->mid);

		memset(uwbconfig->uwb_cfg.localid, 0, sizeof(uwbconfig->uwb_cfg.localid));
		snprintf(uwbconfig->uwb_cfg.localid, sizeof(uwbconfig->uwb_cfg.localid), "%u", vercfg->aid);

		memset(uwbconfig->uwb_cfg.panid, 0, sizeof(uwbconfig->uwb_cfg.panid));
		snprintf(uwbconfig->uwb_cfg.panid, sizeof(uwbconfig->uwb_cfg.panid), "%u", vercfg->panid);

		memset(uwbconfig->uwb_cfg.ch, 0, sizeof(uwbconfig->uwb_cfg.ch));
		snprintf(uwbconfig->uwb_cfg.ch, sizeof(uwbconfig->uwb_cfg.ch), "%u", vercfg->channel);

		memset(uwbconfig->uwb_cfg.coarsegain, 0, sizeof(uwbconfig->uwb_cfg.coarsegain));
		snprintf(uwbconfig->uwb_cfg.coarsegain, sizeof(uwbconfig->uwb_cfg.coarsegain), "%u", vercfg->coarsegain);

		memset(uwbconfig->uwb_cfg.finegain, 0, sizeof(uwbconfig->uwb_cfg.finegain));
		snprintf(uwbconfig->uwb_cfg.finegain, sizeof(uwbconfig->uwb_cfg.finegain), "%.1f",
				 ((float)vercfg->finegain * 1.0) / 10);

		memset(uwbconfig->uwb_cfg.pcode, 0, sizeof(uwbconfig->uwb_cfg.pcode));
		snprintf(uwbconfig->uwb_cfg.pcode, sizeof(uwbconfig->uwb_cfg.pcode), "%u", vercfg->preamble);

		memset(uwbconfig->uwb_cfg.palna, 0, sizeof(uwbconfig->uwb_cfg.palna));
		snprintf(uwbconfig->uwb_cfg.palna, sizeof(uwbconfig->uwb_cfg.palna), "%u", cfg_ctrlbit->pa);

		save_uwb_config(uwbconfig);
	}

	/* do other thing */
	char cmd[128];

	memset(cmd, 0, 128);
	snprintf(cmd, 128, "echo %u > /tmp/uwb_matid", vercfg->mid);
	system(cmd);

	memset(cmd, 0, 128);
	snprintf(cmd, 128, "echo %u > /tmp/uwb_localid", vercfg->aid);
	system(cmd);

	memset(cmd, 0, 128);
	snprintf(cmd, 128, "echo 1 > /tmp/uwb_upgrade");
	system(cmd);

	memset(cmd, 0, 128);
	snprintf(cmd, 128, "echo %u > /tmp/uwb_version", vercfg->version);
	system(cmd);

	/* recode heart time for ac */
	memset(cmd, 0, sizeof(cmd));
	JSONDATA_TIME(&uwb_data->frame_time, cmd);
	write_jiffies(fp_jiffies, cmd);

	return;
}

static void parse_uwb_roleack(ppp_uwb_data *uwb_data)
{
	LOG_LOG("receive a uwb getrole ack !");
	if (uwb_data->length != sizeof(uwb_role_type))
	{
		LOG_LOG("data length is not match uwb_role_type !");
		return;
	}

	uwb_role_type *rolecfg = (uwb_role_type *)(uwb_data->data);

	char *role_type = NULL;

	switch (rolecfg->role)
	{
		case ROLE_TYPE_M:
			role_type = "M";
			break;
		case ROLE_TYPE_S:
			role_type = "S";
			break;
		default:
			LOG_LOG("unknown role type, %04x", rolecfg->role);
			break;
	}

	if (NULL == role_type)
	{
		return;
	}

	LOG_LOG("(uwbcfg)-----------------------------");
	LOG_LOG("(uwbcfg)  role %s", role_type);
	LOG_LOG("(uwbcfg)-----------------------------");

	if (NULL != uwbconfig)
	{
		char cmd[128];

		memset(uwbconfig->uwb_cfg.role, 0, sizeof(uwbconfig->uwb_cfg.role));
		snprintf(uwbconfig->uwb_cfg.role, sizeof(uwbconfig->uwb_cfg.role), "%s", role_type);

		memset(cmd, 0, 128);
		snprintf(cmd, 128, "uci set uwbcon.uwb.role='%s'", uwbconfig->uwb_cfg.role);
		system(cmd);

		memset(cmd, 0, 128);
		snprintf(cmd, 128, "uci commit uwbcon");
		system(cmd);
	}

	return;
}

static void parse_normal_ack(ack_type *uwback)
{
	switch (uwback->ack_datatype)
	{
		case DATATYPE_CMD:
			if (uwback->ack_dataport == CMD_reset)
			{
				LOG_LOG("(ack) receive uwb_cmd reset ack !");
			}
			else if (uwback->ack_dataport == CMD_getgain)
			{
				LOG_LOG("(ack) receive uwb_cmd getgain ack !");
			}
			else if (uwback->ack_dataport == CMD_getcomm)
			{
				LOG_LOG("(ack) receive uwb_cmd getcomm ack !");
			}
			break;
		case DATATYPE_CMD1:
			if (uwback->ack_dataport == CMD1_matid)
			{
				LOG_LOG("(ack) receive uwb_cmd matid ack !");
			}
			else if (uwback->ack_dataport == CMD1_localid)
			{
				LOG_LOG("(ack) receive uwb_cmd localid ack !");
			}
			else if (uwback->ack_dataport == CMD1_panid)
			{
				LOG_LOG("(ack) receive uwb_cmd panid ack !");
			}
			else if (uwback->ack_dataport == CMD1_pcode)
			{
				LOG_LOG("(ack) receive uwb_cmd pcode ack !");
			}
			else if (uwback->ack_dataport == CMD1_ch)
			{
				LOG_LOG("(ack) receive uwb_cmd channel ack !");
			}
			else if (uwback->ack_dataport == CMD1_mode)
			{
				LOG_LOG("(ack) receive uwb_cmd mode ack !");
			}
			else if (uwback->ack_dataport == CMD1_enpalna)
			{
				LOG_LOG("(ack) receive uwb_cmd enpalna ack !");
			}
			else if (uwback->ack_dataport == CMD1_sync)
			{
				LOG_LOG("(ack) receive uwb_cmd sync ack !");
			}
			else if (uwback->ack_dataport == CMD1_lpf)
			{
				LOG_LOG("(ack) receive uwb_cmd lpf ack !");
			}
			else if (uwback->ack_dataport == CMD1_coarsegain)
			{
				LOG_LOG("(ack) receive uwb_cmd coarsegain ack !");
			}
			else if (uwback->ack_dataport == CMD1_finegain)
			{
				LOG_LOG("(ack) receive uwb_cmd finegain ack !");
			}
			else if (uwback->ack_dataport == CMD1_syshrt)
			{
				LOG_LOG("(ack) receive uwb_cmd syshrt ack !");
			}
			else if (uwback->ack_dataport == CMD1_extpapower)
			{
				LOG_LOG("(ack) receive uwb_cmd extpapower ack !");
			}
			break;
		case DATATYPE_CMD2:
			if (uwback->ack_dataport == CMD2_mrang)
			{
				LOG_LOG("(ack) receive uwb_cmd mrang ack !");
			}
			break;
		case ZIGBEE_SET:
			if (uwback->ack_dataport == ZIGBEE_SET_net)
			{
				LOG_LOG("(ack) receive zigbee_cmd net ack !");
			}
			else if (uwback->ack_dataport == ZIGBEE_SET_pow)
			{
				LOG_LOG("(ack) receive zigbee_cmd pow ack !");
			}
			else if (uwback->ack_dataport == ZIGBEE_SET_tagfreq)
			{
				LOG_LOG("(ack) receive zigbee_cmd tagfreq ack !");
			}
			break;
		case DATATYPE_ACK:
			if (uwback->ack_dataport == ACK_GETROLE)
			{
				LOG_LOG("(ack) receive uwb_cmd setrole ack !");
			}
			break;
		default:
			LOG_LOG("unknown type %02x", uwback->ack_datatype);
			break;
	}
}

static void parse_uwb_normalack(ppp_uwb_data *uwb_data)
{
	if (uwb_data->length != sizeof(ack_type))
	{
		LOG_LOG("data length is not match ack_type !");
		return;
	}

	ack_type *uwback = (ack_type *)(uwb_data->data);
	// LOG_LOG("receive a uwb normal ack, seq %u type %02x port %02x !", uwback->ack_sequence, uwback->ack_datatype,
	// uwback->ack_dataport);

	parse_normal_ack(uwback);

	return;
}

static void parse_uwb_ack(ppp_uwb_data *uwb_data)
{
	switch (uwb_data->port)
	{
		case ACK_NORMAL:
			parse_uwb_normalack(uwb_data);
			break;
		case ACK_VERCFG:
			parse_uwb_cfgack(uwb_data);
			break;
		case ACK_GETROLE:
			parse_uwb_roleack(uwb_data);
			break;
		default:
			LOG_LOG("unknown data, type %02x port %02x", uwb_data->type, uwb_data->port);
			break;
	}
}

static void parse_uwb_report(ppp_uwb_data *uwb_data)
{
	/*need json and report to server*/
	switch (uwb_data->port)
	{
		case REPORT_TDOA:
			uwb_data->uwbtype = Position;
			uwb_data->needsend = 1;

			break;
		case REPORT_SYNC:
			uwb_data->uwbtype = Sync;
			uwb_data->needsend = 1;

			break;
		case REPORT_SYNC_STA:
			uwb_data->uwbtype = Syncsta;
			uwb_data->needsend = 1;

			break;
		case REPORT_TOF:
			uwb_data->uwbtype = Tof;
			uwb_data->needsend = 1;

			break;
		case REPORT_SYSHRT:
			parse_uwb_heart(uwb_data);

			break;
		case REPORT_TDOAG:
			uwb_data->uwbtype = Tdoag;
			uwb_data->needsend = 1;

			break;
		case REPORT_BAROMETER:
			uwb_data->uwbtype = Barometer;
			uwb_data->needsend = 1;

			break;
		case REPORT_TDOASENSOR:
			uwb_data->uwbtype = Tdoasensor;
			uwb_data->needsend = 1;

			break;
		case REPORT_TDOAINFO:
			uwb_data->uwbtype = Tdoainfo;
			uwb_data->needsend = 1;

			break;
		case REPORT_TDOAWARN:
			uwb_data->uwbtype = Tdoawarn;
			uwb_data->needsend = 1;

			break;
		default:
			LOG_LOG("unknown data, type %02x port %02x", uwb_data->type, uwb_data->port);
			break;
	}
}

static void strdump_zigbee_strout(ppp_uwb_data *uwb_data)
{
	if (uwb_data->length > MAXLENGTH_HEX_UWB)
	{
		LOG_LOG("data length over MAXLENGTH_HEX_UWB!");
		uwb_data->length = MAXLENGTH_HEX_UWB;
	}
	char *string_buf = malloc(uwb_data->length + 1);
	memset(string_buf, 0, uwb_data->length + 1);
	memcpy(string_buf, uwb_data->data, uwb_data->length);
	string_buf[uwb_data->length] = '\0';
	LOG_LOG("(###zigbee###)%s", string_buf);
	free(string_buf);
	return;
}

static void parse_zigbee_data(ppp_uwb_data *uwb_data)
{
	switch (uwb_data->port)
	{
		case ZIGBEE_REPORT:
			uwb_data->uwbtype = Status;
			uwb_data->needsend = 1;
			break;
		case ZIGBEE_REPORT_V2:
			uwb_data->uwbtype = Zigbee;
			uwb_data->needsend = 1;
			break;
		case ZIGBEE_NORMAL:
			/* do something */
			strdump_zigbee_strout(uwb_data);
			break;
		default:
			LOG_LOG("unknown data, type %02x port %02x", uwb_data->type, uwb_data->port);
			break;
	}
}

static void strdump_uwb_strout(ppp_uwb_data *uwb_data)
{
	if (uwb_data->length > MAXLENGTH_HEX_UWB)
	{
		LOG_LOG("data length over MAXLENGTH_HEX_UWB!");
		uwb_data->length = MAXLENGTH_HEX_UWB;
	}
	char *string_buf = malloc(uwb_data->length + 1);
	memset(string_buf, 0, uwb_data->length + 1);
	memcpy(string_buf, uwb_data->data, uwb_data->length);
	char *End = strrchr(string_buf, '\r');
	if (End != NULL)
	{
		End[0] = '\0';
	}

	LOG_LOG("(###uwbinfo###)%s", string_buf);
	free(string_buf);
	return;
}

static void parse_uwbdata_type(ppp_uwb_data *uwb_data)
{
	switch (uwb_data->type)
	{
		case DATATYPE_REPORT:
			parse_uwb_report(uwb_data);
			break;
		case DATATYPE_ACK:
			parse_uwb_ack(uwb_data);
			break;
		case DATATYPE_FORWARD:

			break;
		case DATATYPE_STROUT:
			strdump_uwb_strout(uwb_data);
			break;
		case DATATYPE_ZIGBEE:
			parse_zigbee_data(uwb_data);
			break;
		default:
			LOG_LOG("unknown type %02x", uwb_data->type);
			break;
	}
	return;
}

/* build tlv data */
#ifdef TLV_SEND

static int align_uwbdata(ppp_uwb_data *uwb_data, char *out, unsigned int *out_len)
{
	switch (uwb_data->uwbtype)
	{
		case Position:
		{
			if (uwb_data->length != sizeof(tdoa_type))
			{
				LOG_LOG("data length %d not equal length of tdoa_type %d, drop data", uwb_data->length,
						sizeof(tdoa_type));
				goto ERR;
			}

			tdoa_type *ptdoa_data = (tdoa_type *)(uwb_data->data);
			align_tdoa_type align_tdoa;

			align_tdoa.aid = ptdoa_data->aid;
			align_tdoa.tid = ptdoa_data->tid;
			align_tdoa.seq = ptdoa_data->seq;
			align_tdoa.arrival = ptdoa_data->arrival;
			align_tdoa.sn = ptdoa_data->sn;
			align_tdoa.sn_1 = ptdoa_data->sn_1;
			align_tdoa.dindex = ptdoa_data->dindex;
			align_tdoa.ms_sta = ptdoa_data->ms_sta;
			align_tdoa.bp = ptdoa_data->bp;
			align_tdoa.lueq = ptdoa_data->lueq;
			align_tdoa.mc = ptdoa_data->mc;
			align_tdoa.rssi_fp = ptdoa_data->rssi_fp;
			align_tdoa.rssi_all = ptdoa_data->rssi_all;

			*out_len = sizeof(align_tdoa);
			memcpy(out, &align_tdoa, *out_len);
		}
		break;
		case Sync:
		{
			if (uwb_data->length != sizeof(sync_type))
			{
				LOG_LOG("data length %d not equal length of sync_data %d , drop data", uwb_data->length,
						sizeof(sync_type));
				goto ERR;
			}

			sync_type *pSyncdata = (sync_type *)(uwb_data->data);
			align_sync_type align_sync;

			align_sync.syncmid = pSyncdata->syncmid;
			align_sync.syncadd = pSyncdata->syncadd;
			align_sync.syncseq = pSyncdata->syncseq;
			align_sync.synctxtim = pSyncdata->synctxtim;
			align_sync.syncdk = pSyncdata->syncdk;

			*out_len = sizeof(align_sync);
			memcpy(out, &align_sync, *out_len);
		}
		break;
		case Syncsta:
		{
			if (uwb_data->length != sizeof(sync_sta_type))
			{
				LOG_LOG("data length %d not equal length of sync_data %d , drop data", uwb_data->length,
						sizeof(sync_sta_type));
				goto ERR;
			}

			sync_sta_type *pSyncsatdata = (sync_sta_type *)(uwb_data->data);
			align_sync_sta_type align_sync_sta;

			align_sync_sta.syncmid = pSyncsatdata->syncmid;
			align_sync_sta.syncadd = pSyncsatdata->syncadd;
			align_sync_sta.syncsucc = pSyncsatdata->syncsucc;
			align_sync_sta.syncdk = pSyncsatdata->syncdk;

			*out_len = sizeof(align_sync_sta);
			memcpy(out, &align_sync_sta, *out_len);
		}
		break;
		case Status:
		{
			if (uwb_data->length != sizeof(zigbee_report_type))
			{
				LOG_LOG("data length not equal length of zigbee_report_type, drop data");
				goto ERR;
			}
			zigbee_report_type *pZigbeedata = (zigbee_report_type *)(uwb_data->data);
			align_zigbee_report_type align_zigbee_report;

			align_zigbee_report.tid = pZigbeedata->tid;
			align_zigbee_report.zigbeeid = pZigbeedata->zigbeeid;
			align_zigbee_report.freq = pZigbeedata->freq;
			align_zigbee_report.battery = pZigbeedata->battery;
			align_zigbee_report.mstate = pZigbeedata->mstate;

			*out_len = sizeof(align_zigbee_report);
			memcpy(out, &align_zigbee_report, *out_len);
		}
		break;
		case Zigbee:
		{
			if (uwb_data->length != sizeof(zigbee_report_type))
			{
				LOG_LOG("data length not equal length of zigbee_report_type, drop data");
				goto ERR;
			}
			zigbee_report_type *pZigbeedata = (zigbee_report_type *)(uwb_data->data);
			align_zigbee_report_type align_zigbee_report;

			align_zigbee_report.tid = pZigbeedata->tid;
			align_zigbee_report.zigbeeid = pZigbeedata->zigbeeid;
			align_zigbee_report.freq = pZigbeedata->freq;
			align_zigbee_report.battery = pZigbeedata->battery;
			align_zigbee_report.mstate = pZigbeedata->mstate;

			*out_len = sizeof(align_zigbee_report);
			memcpy(out, &align_zigbee_report, *out_len);
		}
		break;
		case Tof:
		{
			if (uwb_data->length != sizeof(tof_type))
			{
				LOG_LOG("data length %d not equal length of tof_type %d, drop data", uwb_data->length,
						sizeof(tof_type));
				goto ERR;
			}

			tof_type *pTofdata = (tof_type *)(uwb_data->data);
			align_tof_type align_tof;

			align_tof.mid = pTofdata->mid;
			align_tof.uid = pTofdata->uid;
			align_tof.dis = pTofdata->dis;
			align_tof.rssi = pTofdata->rssi;

			*out_len = sizeof(align_tof);
			memcpy(out, &align_tof, *out_len);
		}
		break;
		case Tdoag:
		{
			if (uwb_data->length != sizeof(tdoag_type))
			{
				LOG_LOG("data length %d not equal length of tdoag_type %d, drop data", uwb_data->length,
						sizeof(tdoag_type));
				goto ERR;
			}

			tdoag_type *ptdoag_data = (tdoag_type *)(uwb_data->data);
			align_tdoag_type align_tdoag;

			align_tdoag.tdoa.aid = ptdoag_data->tdoa.aid;
			align_tdoag.tdoa.tid = ptdoag_data->tdoa.tid;
			align_tdoag.tdoa.seq = ptdoag_data->tdoa.seq;
			align_tdoag.tdoa.arrival = ptdoag_data->tdoa.arrival;
			align_tdoag.tdoa.sn = ptdoag_data->tdoa.sn;
			align_tdoag.tdoa.sn_1 = ptdoag_data->tdoa.sn_1;
			align_tdoag.tdoa.dindex = ptdoag_data->tdoa.dindex;
			align_tdoag.tdoa.ms_sta = ptdoag_data->tdoa.ms_sta;
			align_tdoag.tdoa.bp = ptdoag_data->tdoa.bp;
			align_tdoag.tdoa.lueq = ptdoag_data->tdoa.lueq;
			align_tdoag.tdoa.mc = ptdoag_data->tdoa.mc;
			align_tdoag.tdoa.rssi_fp = ptdoag_data->tdoa.rssi_fp;
			align_tdoag.tdoa.rssi_all = ptdoag_data->tdoa.rssi_all;

			align_tdoag.axis_x = ptdoag_data->axis_x;
			align_tdoag.axis_y = ptdoag_data->axis_y;
			align_tdoag.axis_z = ptdoag_data->axis_z;

			*out_len = sizeof(align_tdoag);
			memcpy(out, &align_tdoag, *out_len);
		}
		break;
		case Tdoainfo:
		{
			if (uwb_data->length != sizeof(tdoainfo_type))
			{
				LOG_LOG("data length %d not equal length of tdoainfo_type %d, drop data", uwb_data->length,
						sizeof(tdoainfo_type));
				goto ERR;
			}

			tdoainfo_type *ptdoainfo_data = (tdoainfo_type *)(uwb_data->data);
			align_tdoainfo_type align_tdoainfo;

			align_tdoainfo.tdoa.aid = ptdoainfo_data->tdoa.aid;
			align_tdoainfo.tdoa.tid = ptdoainfo_data->tdoa.tid;
			align_tdoainfo.tdoa.seq = ptdoainfo_data->tdoa.seq;
			align_tdoainfo.tdoa.arrival = ptdoainfo_data->tdoa.arrival;
			align_tdoainfo.tdoa.sn = ptdoainfo_data->tdoa.sn;
			align_tdoainfo.tdoa.sn_1 = ptdoainfo_data->tdoa.sn_1;
			align_tdoainfo.tdoa.dindex = ptdoainfo_data->tdoa.dindex;
			align_tdoainfo.tdoa.ms_sta = ptdoainfo_data->tdoa.ms_sta;
			align_tdoainfo.tdoa.bp = ptdoainfo_data->tdoa.bp;
			align_tdoainfo.tdoa.lueq = ptdoainfo_data->tdoa.lueq;
			align_tdoainfo.tdoa.mc = ptdoainfo_data->tdoa.mc;
			align_tdoainfo.tdoa.rssi_fp = ptdoainfo_data->tdoa.rssi_fp;
			align_tdoainfo.tdoa.rssi_all = ptdoainfo_data->tdoa.rssi_all;

			align_tdoainfo.temp = ptdoainfo_data->temp;
			align_tdoainfo.hrs = ptdoainfo_data->hrs;
			align_tdoainfo.mmhgh = ptdoainfo_data->mmhgh;
			align_tdoainfo.mmhgl = ptdoainfo_data->mmhgl;
			align_tdoainfo.b_baro = ptdoainfo_data->b_baro;
			align_tdoainfo.t_baro = ptdoainfo_data->t_baro;

			*out_len = sizeof(align_tdoainfo);
			memcpy(out, &align_tdoainfo, *out_len);
		}
		break;
		case Tdoawarn:
		{
			if (uwb_data->length != sizeof(tdoawarn_type))
			{
				LOG_LOG("data length %d not equal length of tdoawarn_type %d, drop data", uwb_data->length,
						sizeof(tdoawarn_type));
				goto ERR;
			}

			tdoawarn_type *ptdoawarn_data = (tdoawarn_type *)(uwb_data->data);
			align_tdoawarn_type align_tdoawarn;

			align_tdoawarn.tdoa.aid = ptdoawarn_data->tdoa.aid;
			align_tdoawarn.tdoa.tid = ptdoawarn_data->tdoa.tid;
			align_tdoawarn.tdoa.seq = ptdoawarn_data->tdoa.seq;
			align_tdoawarn.tdoa.arrival = ptdoawarn_data->tdoa.arrival;
			align_tdoawarn.tdoa.sn = ptdoawarn_data->tdoa.sn;
			align_tdoawarn.tdoa.sn_1 = ptdoawarn_data->tdoa.sn_1;
			align_tdoawarn.tdoa.dindex = ptdoawarn_data->tdoa.dindex;
			align_tdoawarn.tdoa.ms_sta = ptdoawarn_data->tdoa.ms_sta;
			align_tdoawarn.tdoa.bp = ptdoawarn_data->tdoa.bp;
			align_tdoawarn.tdoa.lueq = ptdoawarn_data->tdoa.lueq;
			align_tdoawarn.tdoa.mc = ptdoawarn_data->tdoa.mc;
			align_tdoawarn.tdoa.rssi_fp = ptdoawarn_data->tdoa.rssi_fp;
			align_tdoawarn.tdoa.rssi_all = ptdoawarn_data->tdoa.rssi_all;

			align_tdoawarn.warnflag = ptdoawarn_data->warnflag;
			align_tdoawarn.warntype = ptdoawarn_data->warntype;

			*out_len = sizeof(align_tdoawarn);
			memcpy(out, &align_tdoawarn, *out_len);
		}
		break;
		case Barometer:
		{
			if (uwb_data->length != sizeof(barometer_type))
			{
				LOG_LOG("data length %d not equal length of barometer_type %d, drop data", uwb_data->length,
						sizeof(barometer_type));
				goto ERR;
			}

			barometer_type *pbarometer_data = (barometer_type *)(uwb_data->data);
			align_barometer_type align_barometer;

			align_barometer.aid = pbarometer_data->aid;
			align_barometer.baro_height = pbarometer_data->baro_height;
			align_barometer.temperature = pbarometer_data->temperature;
			align_barometer.presure = pbarometer_data->presure;

			*out_len = sizeof(align_barometer);
			memcpy(out, &align_barometer, *out_len);
		}
		break;
		case Tdoasensor:
		{
			if (uwb_data->length != sizeof(tdoasensor_type))
			{
				LOG_LOG("data length %d not equal length of tdoasensor_type %d, drop data", uwb_data->length,
						sizeof(tdoasensor_type));
				goto ERR;
			}

			tdoasensor_type *ptdoasensor_data = (tdoasensor_type *)(uwb_data->data);
			align_tdoasensor_type align_tdoasensor;

			align_tdoasensor.tdoag.tdoa.aid = ptdoasensor_data->tdoag.tdoa.aid;
			align_tdoasensor.tdoag.tdoa.tid = ptdoasensor_data->tdoag.tdoa.tid;
			align_tdoasensor.tdoag.tdoa.seq = ptdoasensor_data->tdoag.tdoa.seq;
			align_tdoasensor.tdoag.tdoa.arrival = ptdoasensor_data->tdoag.tdoa.arrival;
			align_tdoasensor.tdoag.tdoa.sn = ptdoasensor_data->tdoag.tdoa.sn;
			align_tdoasensor.tdoag.tdoa.sn_1 = ptdoasensor_data->tdoag.tdoa.sn_1;
			align_tdoasensor.tdoag.tdoa.dindex = ptdoasensor_data->tdoag.tdoa.dindex;
			align_tdoasensor.tdoag.tdoa.lueq = ptdoasensor_data->tdoag.tdoa.lueq;
			align_tdoasensor.tdoag.tdoa.mc = ptdoasensor_data->tdoag.tdoa.mc;
			align_tdoasensor.tdoag.tdoa.rssi_fp = ptdoasensor_data->tdoag.tdoa.rssi_fp;
			align_tdoasensor.tdoag.tdoa.rssi_all = ptdoasensor_data->tdoag.tdoa.rssi_all;
			align_tdoasensor.tdoag.tdoa.ms_sta = ptdoasensor_data->tdoag.tdoa.ms_sta;
			align_tdoasensor.tdoag.tdoa.bp = ptdoasensor_data->tdoag.tdoa.bp;

			align_tdoasensor.tdoag.axis_x = ptdoasensor_data->tdoag.axis_x;
			align_tdoasensor.tdoag.axis_y = ptdoasensor_data->tdoag.axis_y;
			align_tdoasensor.tdoag.axis_z = ptdoasensor_data->tdoag.axis_z;

			align_tdoasensor.gyro_x = ptdoasensor_data->gyro_x;
			align_tdoasensor.gyro_y = ptdoasensor_data->gyro_y;
			align_tdoasensor.gyro_z = ptdoasensor_data->gyro_z;
			align_tdoasensor.mag_x = ptdoasensor_data->mag_x;
			align_tdoasensor.mag_y = ptdoasensor_data->mag_y;
			align_tdoasensor.mag_z = ptdoasensor_data->mag_z;
			align_tdoasensor.b_baro = ptdoasensor_data->b_baro;
			align_tdoasensor.t_baro = ptdoasensor_data->t_baro;

			*out_len = sizeof(align_tdoasensor);
			memcpy(out, &align_tdoasensor, *out_len);
		}
		break;
		default:
			break;
	}

ERR:
	return 0;
}

/*******************************************************************************
每一帧都以标识字符0x7E开始和结束；
由于标识字符的值是0x7E，因此当该字符出现在信息字段中时，需要对它进行转义。
转义字符定义为：0x7D
字节填充规定如下：
1. 把信息字段中出现的每一个0x7E字符转变成字节序列（0x7D,0x5E）
2. 若信息字段中出现一个0x7D的字节（即出现了与转义字符相同的比特组合），
则把0x7D转义成两个字节序列（0x7D,0x5D）
3. 若信息字段中出现ASCII码的控制字符（即数值小于0x20的字符），
则该字符与0x20异或，将该字符的编码加以改变
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    heade    |   timestamp  |    mac   |   datalength          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  datatype   |  dataport    |             data                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            crc16           |             end                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
heade 1byte
timestamp 8byte
mac 6byte
datalength 4byte
datatype 1byte
dataport 1byte
data	nbyte
crc16 2byte
end 1byte
*******************************************************************************/

static int tlv_encode(ppp_uwb_data *uwb_data, config *conf, char *out, unsigned int *out_len)
{
	static char tlv_buf[1024];
	static char align_data_tmp[512];
	unsigned int align_datalen = 0;

	uint64_t time = 0;
	uint32_t datalen = 0;
	uint16_t crc = 0;

	memset(tlv_buf, 0, sizeof(tlv_buf));

	/* timestamp 8 byte */
	time = uwb_data->frame_time.tv_sec * 1000000 + uwb_data->frame_time.tv_usec; // us
	memcpy(&tlv_buf[0], &time, sizeof(time));

	/* mac 6 byte */
	memcpy(&tlv_buf[8], conf->mac16, 6);

	/* data length 4 byte , do after align_uwbdata */

	/* data type && port */
	memcpy(&tlv_buf[8 + 6 + 4], &(uwb_data->type), sizeof(uwb_data->type));
	memcpy(&tlv_buf[8 + 6 + 4 + 1], &(uwb_data->port), sizeof(uwb_data->port));

	/* analyze data and format to 4byte align */
	memset(align_data_tmp, 0, 512);
	align_datalen = 0;

	align_uwbdata(uwb_data, align_data_tmp, &align_datalen);
	memcpy(&tlv_buf[8 + 6 + 4 + 1 + 1], align_data_tmp, align_datalen);

	/* data length 4 byte */
	datalen = sizeof(uwb_data->type) + sizeof(uwb_data->port) + align_datalen;
	memcpy(&tlv_buf[8 + 6], &datalen, sizeof(datalen));

	/* crc16, 2 byte , timestamp + machex + datalength + data(type + port + aligndata) */
	crc = crc16_ccitt(&tlv_buf[0], 8 + 6 + 4 + datalen);
	memcpy(&tlv_buf[8 + 6 + 4 + datalen], &crc, sizeof(crc));

	/* ppp encode */
	out[0] = 0x7E;
	ppp_encode(&tlv_buf[0], 8 + 6 + 4 + datalen + 2, &out[1], out_len);
	out[1 + *out_len] = 0x7E;
	*out_len = *out_len + 2; // add heade and end flag

	return 0;
}

static int tlv_uwbdata(ppp_uwb_data *uwb_data, config *conf, TLV_data *tlv_data)
{
	/* build tlv data from uwb_data */
	memset(tlv_data->data, 0, sizeof(tlv_data->data));
	tlv_data->length = 0;
	tlv_encode(uwb_data, conf, tlv_data->data, &(tlv_data->length));

	/* for test
	printf_hex("tlv encode", tlv_data->data, tlv_data->length);
	*/
	if (conf->print_enable == 1)
	{
		memset(conf->print_buff, 0, PRINT_BUFF_SIZE);
		hex_data(tlv_data->data, tlv_data->length, conf->print_buff);
		printdata(conf->print_buff);
	}

	return tlv_data->length;
}

#else

static char *json_uwbdata(ppp_uwb_data *uwb_data, config *conf)
{
	cJSON *root, *img[10], *arry;
	char *out = NULL;
	char *mac = conf->mac;
	char sys_time[20] = {0};

	char buf[64];

	JSONDATA_TIME(&(uwb_data->frame_time), sys_time);

	switch (uwb_data->uwbtype)
	{
		case Position:
		{
			if (uwb_data->length != sizeof(tdoa_type))
			{
				LOG_LOG("data length %d not equal length of tdoa_type %d, drop data", uwb_data->length,
						sizeof(tdoa_type));
				goto ERR;
			}

			tdoa_type *ptdoa_data = (tdoa_type *)(uwb_data->data);
			root = cJSON_CreateObject();
			cJSON_AddStringToObject(root, "time", sys_time);
			cJSON_AddStringToObject(root, "devID", mac);
			cJSON_AddStringToObject(root, "datatype", uwb_type_to_string(uwb_data->uwbtype));
			cJSON_AddNumberToObject(root, "AID", ptdoa_data->aid);
			cJSON_AddNumberToObject(root, "TID", ptdoa_data->tid);
			cJSON_AddNumberToObject(root, "seq", ptdoa_data->seq);
			cJSON_AddNumberToObject(root, "ArrivalTime", ptdoa_data->arrival);
			cJSON_AddNumberToObject(root, "Sn", ptdoa_data->sn);
			cJSON_AddNumberToObject(root, "Sn_1", ptdoa_data->sn_1);
			cJSON_AddNumberToObject(root, "dix", ptdoa_data->dindex);
			cJSON_AddNumberToObject(root, "Motion", ptdoa_data->ms_sta);
			cJSON_AddNumberToObject(root, "Bat", ptdoa_data->bp);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoa_data->lueq);
			cJSON_AddStringToObject(root, "Lueq", buf);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoa_data->mc);
			cJSON_AddStringToObject(root, "Mc", buf);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoa_data->rssi_fp);
			cJSON_AddStringToObject(root, "rssi", buf);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoa_data->rssi_all);
			cJSON_AddStringToObject(root, "Ra", buf);

			out = cJSON_PrintUnformatted(root);

			if (1 == conf->print_enable)
			{
				printdata(out);
			}

			cJSON_Delete(root);
		}
		break;
		case Sync:
		{
			if (uwb_data->length != sizeof(sync_type))
			{
				LOG_LOG("data length %d not equal length of sync_data %d , drop data", uwb_data->length,
						sizeof(sync_type));
				goto ERR;
			}

			sync_type *pSyncdata = (sync_type *)(uwb_data->data);
			root = cJSON_CreateObject();
			cJSON_AddStringToObject(root, "time", sys_time);
			cJSON_AddStringToObject(root, "devID", mac);
			cJSON_AddStringToObject(root, "datatype", uwb_type_to_string(uwb_data->uwbtype));
			cJSON_AddNumberToObject(root, "SyncMID", pSyncdata->syncmid);
			cJSON_AddNumberToObject(root, "SyncADD", pSyncdata->syncadd);
			cJSON_AddNumberToObject(root, "SyncSeq", pSyncdata->syncseq);
			cJSON_AddNumberToObject(root, "SyncTxTime", pSyncdata->synctxtim);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.13lf", pSyncdata->syncdk);
			cJSON_AddStringToObject(root, "SyncDk", buf);

			out = cJSON_PrintUnformatted(root);

			if (1 == conf->print_enable)
			{
				syncLOG(out);
			}

			cJSON_Delete(root);
		}
		break;
		case Syncsta:
		{
			if (uwb_data->length != sizeof(sync_sta_type))
			{
				LOG_LOG("data length %d not equal length of sync_data %d , drop data", uwb_data->length,
						sizeof(sync_sta_type));
				goto ERR;
			}

			sync_sta_type *pSyncsatdata = (sync_sta_type *)(uwb_data->data);
			root = cJSON_CreateObject();
			cJSON_AddStringToObject(root, "time", sys_time);
			cJSON_AddStringToObject(root, "devID", mac);
			cJSON_AddStringToObject(root, "datatype", uwb_type_to_string(uwb_data->uwbtype));
			cJSON_AddNumberToObject(root, "SyncMID", pSyncsatdata->syncmid);
			cJSON_AddNumberToObject(root, "SyncADD", pSyncsatdata->syncadd);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", pSyncsatdata->syncsucc);
			cJSON_AddStringToObject(root, "SyncSucc", buf);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.13lf", pSyncsatdata->syncdk);
			cJSON_AddStringToObject(root, "SyncDk", buf);

			out = cJSON_PrintUnformatted(root);

			if (1 == conf->print_enable)
			{
				printdata(out);
			}

			cJSON_Delete(root);
		}
		break;
		case Status:
		{
			if (uwb_data->length != sizeof(zigbee_report_type))
			{
				LOG_LOG("data length not equal length of zigbee_report_type, drop data");
				goto ERR;
			}
			zigbee_report_type *pZigbeedata = (zigbee_report_type *)(uwb_data->data);
			root = cJSON_CreateObject();
			cJSON_AddStringToObject(root, "time", sys_time);
			cJSON_AddStringToObject(root, "devID", mac);
			cJSON_AddStringToObject(root, "datatype", uwb_type_to_string(uwb_data->uwbtype));
			cJSON_AddNumberToObject(root, "TID", pZigbeedata->tid);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%016llx", pZigbeedata->zigbeeid);
			cJSON_AddStringToObject(root, "ZID", buf);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.1f", ((float)pZigbeedata->freq * 1.0) / 10);
			cJSON_AddStringToObject(root, "Freq", buf);

			cJSON_AddNumberToObject(root, "Bat", pZigbeedata->battery);
			cJSON_AddNumberToObject(root, "Ms", pZigbeedata->mstate);

			out = cJSON_PrintUnformatted(root);

			if (1 == conf->print_enable)
			{
				printdata(out);
			}

			cJSON_Delete(root);
		}
		break;
		case Zigbee:
		{
			if (uwb_data->length != sizeof(zigbee_report_type))
			{
				LOG_LOG("data length not equal length of zigbee_report_type, drop data");
				goto ERR;
			}
			zigbee_report_type *pZigbeedata = (zigbee_report_type *)(uwb_data->data);
			root = cJSON_CreateObject();
			cJSON_AddStringToObject(root, "time", sys_time);
			cJSON_AddStringToObject(root, "devID", mac);
			cJSON_AddStringToObject(root, "datatype", uwb_type_to_string(uwb_data->uwbtype));
			cJSON_AddNumberToObject(root, "TID", pZigbeedata->tid);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%016llx", pZigbeedata->zigbeeid);
			cJSON_AddStringToObject(root, "ZID", buf);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.1f", ((float)pZigbeedata->freq * 1.0) / 10);
			cJSON_AddStringToObject(root, "Freq", buf);

			cJSON_AddNumberToObject(root, "Bat", pZigbeedata->battery);
			cJSON_AddNumberToObject(root, "Cfgver", pZigbeedata->mstate);

			out = cJSON_PrintUnformatted(root);

			if (1 == conf->print_enable)
			{
				printdata(out);
			}

			cJSON_Delete(root);
		}
		break;
		case Tof:
		{
			if (uwb_data->length != sizeof(tof_type))
			{
				LOG_LOG("data length %d not equal length of tof_type %d, drop data", uwb_data->length,
						sizeof(tof_type));
				goto ERR;
			}

			tof_type *pTofdata = (tof_type *)(uwb_data->data);
			root = cJSON_CreateObject();
			cJSON_AddStringToObject(root, "time", sys_time);
			cJSON_AddStringToObject(root, "devID", mac);
			cJSON_AddStringToObject(root, "datatype", uwb_type_to_string(uwb_data->uwbtype));
			cJSON_AddNumberToObject(root, "MID", pTofdata->mid);
			cJSON_AddNumberToObject(root, "AID", pTofdata->uid);
			cJSON_AddNumberToObject(root, "Dis", pTofdata->dis);

			char buf[10] = {0};
			sprintf(buf, "%.2f", pTofdata->rssi);
			cJSON_AddStringToObject(root, "Rssi", buf);

			out = cJSON_PrintUnformatted(root);

			if (1 == conf->print_enable)
			{
				printdata(out);
			}

			cJSON_Delete(root);
		}
		break;
		case Tdoag:
		{
			if (uwb_data->length != sizeof(tdoag_type))
			{
				LOG_LOG("data length %d not equal length of tdoag_type %d, drop data", uwb_data->length,
						sizeof(tdoag_type));
				goto ERR;
			}

			tdoag_type *ptdoag_data = (tdoag_type *)(uwb_data->data);
			root = cJSON_CreateObject();
			cJSON_AddStringToObject(root, "time", sys_time);
			cJSON_AddStringToObject(root, "devID", mac);
			cJSON_AddStringToObject(root, "datatype", uwb_type_to_string(uwb_data->uwbtype));
			cJSON_AddNumberToObject(root, "AID", ptdoag_data->tdoa.aid);
			cJSON_AddNumberToObject(root, "TID", ptdoag_data->tdoa.tid);
			cJSON_AddNumberToObject(root, "seq", ptdoag_data->tdoa.seq);
			cJSON_AddNumberToObject(root, "ArrivalTime", ptdoag_data->tdoa.arrival);
			cJSON_AddNumberToObject(root, "Sn", ptdoag_data->tdoa.sn);
			cJSON_AddNumberToObject(root, "Sn_1", ptdoag_data->tdoa.sn_1);
			cJSON_AddNumberToObject(root, "dix", ptdoag_data->tdoa.dindex);
			cJSON_AddNumberToObject(root, "Motion", ptdoag_data->tdoa.ms_sta);
			cJSON_AddNumberToObject(root, "Bat", ptdoag_data->tdoa.bp);
			cJSON_AddNumberToObject(root, "AXIS_X", ptdoag_data->axis_x);
			cJSON_AddNumberToObject(root, "AXIS_Y", ptdoag_data->axis_y);
			cJSON_AddNumberToObject(root, "AXIS_Z", ptdoag_data->axis_z);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoag_data->tdoa.lueq);
			cJSON_AddStringToObject(root, "Lueq", buf);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoag_data->tdoa.mc);
			cJSON_AddStringToObject(root, "Mc", buf);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoag_data->tdoa.rssi_fp);
			cJSON_AddStringToObject(root, "rssi", buf);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoag_data->tdoa.rssi_all);
			cJSON_AddStringToObject(root, "Ra", buf);

			out = cJSON_PrintUnformatted(root);

			if (1 == conf->print_enable)
			{
				printdata(out);
			}

			cJSON_Delete(root);
		}
		break;
		case Tdoainfo:
		{
			if (uwb_data->length != sizeof(tdoainfo_type))
			{
				LOG_LOG("data length %d not equal length of tdoainfo_type %d, drop data", uwb_data->length,
						sizeof(tdoainfo_type));
				goto ERR;
			}

			tdoainfo_type *ptdoainfo_data = (tdoainfo_type *)(uwb_data->data);
			root = cJSON_CreateObject();
			cJSON_AddStringToObject(root, "time", sys_time);
			cJSON_AddStringToObject(root, "devID", mac);
			cJSON_AddStringToObject(root, "datatype", uwb_type_to_string(uwb_data->uwbtype));
			cJSON_AddNumberToObject(root, "AID", ptdoainfo_data->tdoa.aid);
			cJSON_AddNumberToObject(root, "TID", ptdoainfo_data->tdoa.tid);
			cJSON_AddNumberToObject(root, "seq", ptdoainfo_data->tdoa.seq);
			cJSON_AddNumberToObject(root, "ArrivalTime", ptdoainfo_data->tdoa.arrival);
			cJSON_AddNumberToObject(root, "Sn", ptdoainfo_data->tdoa.sn);
			cJSON_AddNumberToObject(root, "Sn_1", ptdoainfo_data->tdoa.sn_1);
			cJSON_AddNumberToObject(root, "dix", ptdoainfo_data->tdoa.dindex);
			cJSON_AddNumberToObject(root, "Motion", ptdoainfo_data->tdoa.ms_sta);
			cJSON_AddNumberToObject(root, "Bat", ptdoainfo_data->tdoa.bp);

			cJSON_AddNumberToObject(root, "TEMP", ptdoainfo_data->temp);
			cJSON_AddNumberToObject(root, "HRS", ptdoainfo_data->hrs);
			cJSON_AddNumberToObject(root, "mmHgH", ptdoainfo_data->mmhgh);
			cJSON_AddNumberToObject(root, "mmHgL", ptdoainfo_data->mmhgl);
			cJSON_AddNumberToObject(root, "B_Baro", ptdoainfo_data->b_baro);
			cJSON_AddNumberToObject(root, "T_Baro", ptdoainfo_data->t_baro);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoainfo_data->tdoa.lueq);
			cJSON_AddStringToObject(root, "Lueq", buf);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoainfo_data->tdoa.mc);
			cJSON_AddStringToObject(root, "Mc", buf);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoainfo_data->tdoa.rssi_fp);
			cJSON_AddStringToObject(root, "rssi", buf);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoainfo_data->tdoa.rssi_all);
			cJSON_AddStringToObject(root, "Ra", buf);

			out = cJSON_PrintUnformatted(root);

			if (1 == conf->print_enable)
			{
				printdata(out);
			}

			cJSON_Delete(root);
		}
		break;
		case Tdoawarn:
		{
			if (uwb_data->length != sizeof(tdoawarn_type))
			{
				LOG_LOG("data length %d not equal length of tdoawarn_type %d, drop data", uwb_data->length,
						sizeof(tdoawarn_type));
				goto ERR;
			}

			tdoawarn_type *ptdoawarn_data = (tdoawarn_type *)(uwb_data->data);
			root = cJSON_CreateObject();
			cJSON_AddStringToObject(root, "time", sys_time);
			cJSON_AddStringToObject(root, "devID", mac);
			cJSON_AddStringToObject(root, "datatype", uwb_type_to_string(uwb_data->uwbtype));
			cJSON_AddNumberToObject(root, "AID", ptdoawarn_data->tdoa.aid);
			cJSON_AddNumberToObject(root, "TID", ptdoawarn_data->tdoa.tid);
			cJSON_AddNumberToObject(root, "seq", ptdoawarn_data->tdoa.seq);
			cJSON_AddNumberToObject(root, "ArrivalTime", ptdoawarn_data->tdoa.arrival);
			cJSON_AddNumberToObject(root, "Sn", ptdoawarn_data->tdoa.sn);
			cJSON_AddNumberToObject(root, "Sn_1", ptdoawarn_data->tdoa.sn_1);
			cJSON_AddNumberToObject(root, "dix", ptdoawarn_data->tdoa.dindex);
			cJSON_AddNumberToObject(root, "Motion", ptdoawarn_data->tdoa.ms_sta);
			cJSON_AddNumberToObject(root, "Bat", ptdoawarn_data->tdoa.bp);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoawarn_data->tdoa.lueq);
			cJSON_AddStringToObject(root, "Lueq", buf);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoawarn_data->tdoa.mc);
			cJSON_AddStringToObject(root, "Mc", buf);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoawarn_data->tdoa.rssi_fp);
			cJSON_AddStringToObject(root, "rssi", buf);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoawarn_data->tdoa.rssi_all);
			cJSON_AddStringToObject(root, "Ra", buf);

			cJSON_AddNumberToObject(root, "Warn", ptdoawarn_data->warnflag);
			cJSON_AddNumberToObject(root, "Value", ptdoawarn_data->warntype);

			out = cJSON_PrintUnformatted(root);

			if (1 == conf->print_enable)
			{
				printdata(out);
			}

			cJSON_Delete(root);
		}
		break;
		case Barometer:
		{
			if (uwb_data->length != sizeof(barometer_type))
			{
				LOG_LOG("data length %d not equal length of barometer_type %d, drop data", uwb_data->length,
						sizeof(barometer_type));
				goto ERR;
			}

			barometer_type *pbarometer_data = (barometer_type *)(uwb_data->data);
			root = cJSON_CreateObject();
			cJSON_AddStringToObject(root, "time", sys_time);
			cJSON_AddStringToObject(root, "devID", mac);
			cJSON_AddStringToObject(root, "datatype", uwb_type_to_string(uwb_data->uwbtype));
			cJSON_AddNumberToObject(root, "AID", pbarometer_data->aid);
			cJSON_AddNumberToObject(root, "baroheight", pbarometer_data->baro_height);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.1f", pbarometer_data->temperature);
			cJSON_AddStringToObject(root, "temperature", buf);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.1f", pbarometer_data->presure);
			cJSON_AddStringToObject(root, "presure", buf);

			out = cJSON_PrintUnformatted(root);

			if (1 == conf->print_enable)
			{
				printdata(out);
			}

			cJSON_Delete(root);
		}
		break;
		case Tdoasensor:
		{
			if (uwb_data->length != sizeof(tdoasensor_type))
			{
				LOG_LOG("data length %d not equal length of tdoasensor_type %d, drop data", uwb_data->length,
						sizeof(tdoasensor_type));
				goto ERR;
			}

			tdoasensor_type *ptdoasensor_data = (tdoasensor_type *)(uwb_data->data);
			root = cJSON_CreateObject();
			cJSON_AddStringToObject(root, "time", sys_time);
			cJSON_AddStringToObject(root, "devID", mac);
			cJSON_AddStringToObject(root, "datatype", uwb_type_to_string(uwb_data->uwbtype));

			cJSON_AddNumberToObject(root, "AID", ptdoasensor_data->tdoag.tdoa.aid);
			cJSON_AddNumberToObject(root, "TID", ptdoasensor_data->tdoag.tdoa.tid);
			cJSON_AddNumberToObject(root, "seq", ptdoasensor_data->tdoag.tdoa.seq);
			cJSON_AddNumberToObject(root, "ArrivalTime", ptdoasensor_data->tdoag.tdoa.arrival);
			cJSON_AddNumberToObject(root, "Sn", ptdoasensor_data->tdoag.tdoa.sn);
			cJSON_AddNumberToObject(root, "Sn_1", ptdoasensor_data->tdoag.tdoa.sn_1);
			cJSON_AddNumberToObject(root, "dix", ptdoasensor_data->tdoag.tdoa.dindex);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoasensor_data->tdoag.tdoa.lueq);
			cJSON_AddStringToObject(root, "Lueq", buf);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoasensor_data->tdoag.tdoa.mc);
			cJSON_AddStringToObject(root, "Mc", buf);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoasensor_data->tdoag.tdoa.rssi_fp);
			cJSON_AddStringToObject(root, "rssi", buf);

			memset(buf, 0, sizeof(buf));
			sprintf(buf, "%.2f", ptdoasensor_data->tdoag.tdoa.rssi_all);
			cJSON_AddStringToObject(root, "Ra", buf);

			cJSON_AddNumberToObject(root, "Motion", ptdoasensor_data->tdoag.tdoa.ms_sta);
			cJSON_AddNumberToObject(root, "Bat", ptdoasensor_data->tdoag.tdoa.bp);

			cJSON_AddNumberToObject(root, "AXIS_X", ptdoasensor_data->tdoag.axis_x);
			cJSON_AddNumberToObject(root, "AXIS_Y", ptdoasensor_data->tdoag.axis_y);
			cJSON_AddNumberToObject(root, "AXIS_Z", ptdoasensor_data->tdoag.axis_z);

			cJSON_AddNumberToObject(root, "gyro_x", ptdoasensor_data->gyro_x);
			cJSON_AddNumberToObject(root, "gyro_y", ptdoasensor_data->gyro_y);
			cJSON_AddNumberToObject(root, "gyro_z", ptdoasensor_data->gyro_z);
			cJSON_AddNumberToObject(root, "mag_x", ptdoasensor_data->mag_x);
			cJSON_AddNumberToObject(root, "mag_y", ptdoasensor_data->mag_y);
			cJSON_AddNumberToObject(root, "mag_z", ptdoasensor_data->mag_z);
			cJSON_AddNumberToObject(root, "b_baro", ptdoasensor_data->b_baro);
			cJSON_AddNumberToObject(root, "t_baro", ptdoasensor_data->t_baro);

			out = cJSON_PrintUnformatted(root);

			if (1 == conf->print_enable)
			{
				printdata(out);
			}

			cJSON_Delete(root);
		}
		break;
		default:
			break;
	}

ERR:
	return out;
}
#endif

/* ppp_frame_thread func: parse buffer data to ppp frame and send to parse thread */
void *ppp_frame_thread_func(void *indata)
{
	int ret = 0, n = 0;
	char readbuff[READSIZE] = {0};
	char tempbuff[READSIZE * 2] = {0};
	char *pdata = NULL;

	char last_buff[PPP_FRAME_LENGTH * 2] = {0};
	int last_len = 0;

	int datalen = 0;
	int data_len = 0;

	char *p = NULL;
	char *pStart = NULL, *pEnd = NULL;

	struct timeval cur_time;

	Frame_data *data = (Frame_data *)indata;

	ttyread_data *tmp_data = (ttyread_data *)malloc(sizeof(ttyread_data));
	ppp_frame_data *frame_data = (ppp_frame_data *)malloc(sizeof(ppp_frame_data));

	PPP_STATUS ppp_status = pppstatus_defalut;
	/* read data from tty read buffer */
	while (TRUE)
	{
		/* wait */
		pthread_mutex_lock(&(data->ttyread_buffer->mutex));

		memset(tmp_data, 0, sizeof(ttyread_data));
		ret = Rbuf_GetOne(data->ttyread_buffer->ring_buffer, tmp_data);

		if (ret <= 0)
		{
			/* no data read from string buffer */
			// usleep(5000);
			// continue;
			pthread_cond_wait(&(data->ttyread_buffer->cond), &(data->ttyread_buffer->mutex));
		}
		else
		{
			/* strcat data */

			memset(readbuff, 0, READSIZE);
			memcpy(readbuff, tmp_data->data, tmp_data->len);
			data_len = tmp_data->len;

#ifdef DEBUG
			printf_hex("read data from buffer", readbuff, data_len);
#endif

			/* add last data */
			memset(tempbuff, 0, READSIZE * 2);
			if (last_len > PPP_FRAME_LENGTH)
			{
				LOG_LOG("read datalen over ppp_frame_length, not ppp data , drop");

#ifdef DEBUG
				printf("last datalen over PPP_FRAME_LENGTH , drop\n");
#endif
				memcpy(tempbuff, readbuff, data_len);
				last_len = 0;
			}
			else if (last_len < 1)
			{
				memcpy(tempbuff, readbuff, data_len);
			}
			else
			{
				memcpy(tempbuff, last_buff, last_len);
				memcpy(&tempbuff[last_len], readbuff, data_len);
				data_len = data_len + last_len;

				last_len = 0;
			}

#ifdef DEBUG
			printf_hex("full data", tempbuff, data_len);
#endif

			if (data_len < 8)
			{
				memcpy(last_buff, tempbuff, data_len);
				last_len = data_len;

				pthread_mutex_unlock(&(data->ttyread_buffer->mutex));
				continue;
			}

			/* analyze data to ppp frame */
#ifdef DEBUG
			printf("analyze data to ppp frame\n");
#endif
			pdata = tempbuff;
			datalen = 0;
			while (TRUE)
			{
				/* search start PPP_FRAME_FLAG */
				// ppp_status = pppstatus_defalut;

#ifdef DEBUG
				printf("search start PPP_FRAME_FLAG\n");
#endif

				for (n = 0; n < data_len; n++)
				{
					if (pdata[n] == PPP_FRAME_FLAG)
					{
#ifdef DEBUG
						printf("pdata[%d] == PPP_FRAME_FLAG\n", n);
#endif
						if (n == 0)
						{
							if (pdata[n + 1] == PPP_FRAME_FLAG)
							{
								pStart = &pdata[n + 1];
								datalen = data_len - (n + 1);
							}
							else
							{
								pStart = &pdata[n];
								datalen = data_len - n;
							}
						}
						else if (n == data_len)
						{
#ifdef DEBUG
							printf("no find start PPP_FRAME_FLAG, drop this data!\n");
#endif
							LOG_LOG("no find start PPP_FRAME_FLAG, drop this data!");
							ppp_status = pppstatus_defalut;
							break;
						}
						else
						{
							if (pdata[n + 1] == PPP_FRAME_FLAG)
							{
								pStart = &pdata[n + 1];
								datalen = data_len - (n + 1);
							}
							else
							{
								pStart = &pdata[n];
								datalen = data_len - n;
							}
						}

#ifdef DEBUG
						printf("pStart[%d] %02x datalen %d \n", n, pdata[n], datalen);
#endif
						ppp_status = pppstatus_start;
						break;
					}
				}

				/* search end PPP_FRAME_FLAG */

#ifdef DEBUG
				printf("search end PPP_FRAME_FLAG\n");
#endif
				if (ppp_status == pppstatus_start && pStart != NULL)
				{
#ifdef DEBUG
					printf("find start PPP_FRAME_FLAG\n");
#endif
					for (n = 1; n < datalen; n++) // pStart+1
					{
						if (pStart[n] == PPP_FRAME_FLAG)
						{
							pEnd = &pStart[n];
							int ppp_frame_len = n + 1;

#ifdef DEBUG
							printf("pEnd [%d] %02x ppp_frame_len %d \n", n, pStart[n], ppp_frame_len);
#endif
							/* tail to ppp frame ring_buffer */
							gettimeofday(&cur_time, NULL);

							if (ppp_frame_len >= 8 && ppp_frame_len <= sizeof(ppp_frame_data))
							{
								memset(frame_data, 0, sizeof(ppp_frame_data));
								frame_data->frame_time = cur_time;
								frame_data->ppp_frame_len = ppp_frame_len;
								memcpy(frame_data->ppp_frame, pStart, ppp_frame_len);

								pthread_mutex_lock(&data->pppframe_buffer->mutex);
								if (0 == Rbuf_AddOne(data->pppframe_buffer->ring_buffer, frame_data))
								{
									LOG_LOG("ppp frame ring_buffer is full");
								}
								pthread_cond_signal(&data->pppframe_buffer->cond);
								pthread_mutex_unlock(&data->pppframe_buffer->mutex);

#ifdef DEBUG
								printf("#############################################################\n");
								printf_hex("find a ppp frame", frame_data->ppp_frame, frame_data->ppp_frame_len);
								printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
#endif
							}
							else
							{
								LOG_LOG("frame_len over the buffer length of ppp_frame_data, drop");
							}

							pdata = pEnd + 1;
							data_len = datalen - ppp_frame_len;
							ppp_status = pppstatus_end;
							break;
						}
					}

					if (ppp_status == pppstatus_end && data_len >= 8)
					{
						continue; // continue search while
					}
					else
					{
						/* add to last buff for next search */
						memset(last_buff, 0, PPP_FRAME_LENGTH * 2);
						memcpy(last_buff, pdata, data_len);
						last_len = data_len;

						break; // break analyze data while
					}
				}
				else
				{
					/* add to last buff for next search */
					memset(last_buff, 0, PPP_FRAME_LENGTH * 2);
					memcpy(last_buff, pdata, data_len);
					last_len = data_len;

					break; // break analyze data while
				}
			}
			/*
	#ifdef DEBUG
			printf("analyze data to ppp frame\n");
	#endif*/
		}

		pthread_mutex_unlock(&(data->ttyread_buffer->mutex));
	}

	free(tmp_data);
	free(frame_data);

	return NULL;
}

/* thread func: parse uwbdata from ppp frame buffer and send tcpsend thread */
void *uwb_parse_thread_func(void *indata)
{
	char *pNext = NULL;
	int len = 0;
	int full_num = 0;

	Prase_data *data = (Prase_data *)indata;

	ppp_frame_data *frame_data = (ppp_frame_data *)malloc(sizeof(ppp_frame_data));
	ppp_type_data ppp_data;

	ppp_uwb_data *uwb_data = (ppp_uwb_data *)malloc(sizeof(ppp_uwb_data));

	uint16_t crc = 0;

	char ppp_decode_buff[PPP_FRAME_LENGTH * 2] = {0};
	int ppp_decode_len = 0;

#ifdef TLV_SEND
	TLV_data tlv_data;
#else
	char *pJson_data = NULL;
#endif

#ifdef DEBUG3

	int record_num = 0;
	time_t tm;
	time_t cur_time, last_time;
	cur_time = time(&tm);
	last_time = cur_time;
#endif
	/* read data from data buffer */
	while (TRUE)
	{
#ifdef DEBUG3
		cur_time = time(&tm);
#endif
		pthread_mutex_lock(&(data->pppframe_buffer->mutex));

		memset(frame_data, 0, sizeof(ppp_frame_data));
		len = Rbuf_GetOne(data->pppframe_buffer->ring_buffer, frame_data);

		if (len <= 0)
		{
			/* no data read */
			// usleep(500);
			// continue;
			pthread_cond_wait(&(data->pppframe_buffer->cond), &(data->pppframe_buffer->mutex));
		}
		else
		{
#ifdef DEBUG3
			// printf("time %lu\n", cur_time.tv_sec);
			record_num++;
			if ((cur_time - last_time) >= 1)
			{
				printf("record num %d/s\n", record_num);
				record_num = 0;
				last_time = cur_time;
			}
#endif

#ifdef DEBUG4
			printf_hex("[pppframe]receive a ppp frame", frame_data->ppp_frame, frame_data->ppp_frame_len);
#endif

			/*******************************************************************************
			 每一帧都以标识字符0x7E开始和结束；
			 由于标识字符的值是0x7E，因此当该字符出现在信息字段中时，需要对它进行转义。
			 转义字符定义为：0x7D
			 字节填充规定如下：
			 1. 把信息字段中出现的每一个0x7E字符转变成字节序列（0x7D,0x5E）
			 2. 若信息字段中出现一个0x7D的字节（即出现了与转义字符相同的比特组合），
				则把0x7D转义成两个字节序列（0x7D,0x5D）
			 3. 若信息字段中出现ASCII码的控制字符（即数值小于0x20的字符），
				则该字符与0x20异或，将该字符的编码加以改变
			*******************************************************************************/
			memset(ppp_decode_buff, 0, PPP_FRAME_LENGTH * 2);
			/* del heade and end flag */
			ppp_decode(&(frame_data->ppp_frame)[1], (frame_data->ppp_frame_len - 2), ppp_decode_buff, &ppp_decode_len);

#ifdef DEBUG4
			printf_hex("[pppframe]ppp_decode and del heade && end flag", ppp_decode_buff, ppp_decode_len);
#endif

			/* parse ppp frame and crc data */

			/*******************************************************************************
			0                   1                   2                   3
			 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|    heade      |    reserve    |  sequence      |  datalength  |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|  datatype     |   dataport    |  ......   data
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|     crc16                     |   reserve      |    end       |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

			*******************************************************************************/
			/*reserve0*/
			pNext = &ppp_decode_buff[0];

			memcpy(&(ppp_data.reserve0), pNext, sizeof(uint8_t));
			/*sequence*/

			pNext = pNext + sizeof(uint8_t);
			memcpy(&(ppp_data.sequence), pNext, sizeof(uint8_t));

			/*datalength*/
			pNext = pNext + sizeof(uint8_t);
			memcpy(&(ppp_data.datalength), pNext, sizeof(uint8_t));

			/*data*/
			pNext = pNext + sizeof(uint8_t);
			// memcpy(ppp_data.data, pNext, sizeof(uint8_t));
			ppp_data.data = pNext;

			/*crc*/
			pNext = pNext + ppp_data.datalength;
			memcpy(&(ppp_data.crc), pNext, sizeof(uint16_t));

			/*reserve1*/
			pNext = pNext + sizeof(uint16_t);
			memcpy(&(ppp_data.reserve1), pNext, sizeof(uint8_t));

#ifdef DEBUG1
			printf("[pppframe]receive a ppp frame, seq:%d datalen:%d crc:%04x\n", ppp_data.sequence,
				   ppp_data.datalength, ppp_data.crc);
#endif
			/* crc check */
			crc = CRC_Check(DEF_CRC_INIT, (ppp_data.data - sizeof(uint8_t)), (ppp_data.datalength + sizeof(uint8_t)));
#ifdef DEBUG
			printf("[pppframe]crc start %02x length %d , src_crc %04x our_crc %04x \n",
				   (ppp_data.data - sizeof(uint8_t))[0], (ppp_data.datalength + sizeof(uint8_t)), ppp_data.crc, crc);
#endif

			if (crc != ppp_data.crc)
			{
				LOG_LOG("[pppframe]seq %d frame crc error, src_crc %04x , our_crc %04x ,drop this frame!",
						ppp_data.sequence, ppp_data.crc, crc);
#ifdef DEBUG4
				printf_hex("[pppframe]receive a ppp frame", frame_data->ppp_frame, frame_data->ppp_frame_len);
				printf_hex("[pppframe]ppp_decode and del heade && end flag", ppp_decode_buff, ppp_decode_len);
				printf("[pppframe]seq %d frame crc error, crc start %02x length %d , src_crc %04x our_crc %04x \n",
					   ppp_data.sequence, (ppp_data.data - sizeof(uint8_t))[0], (ppp_data.datalength + sizeof(uint8_t)),
					   ppp_data.crc, crc);
#endif

				pthread_mutex_unlock(&(data->pppframe_buffer->mutex));
				continue;
			}

			/* get uwb data from ppp frame */
			uwb_data->frame_time = frame_data->frame_time;
			uwb_data->type = ppp_data.data[0];
			uwb_data->port = ppp_data.data[1];
			uwb_data->needsend = 0;
			uwb_data->uwbtype = Other;
			uwb_data->length = ppp_data.datalength - 2;
			uwb_data->data = ppp_data.data + 2;

#ifdef DEBUG4
			printf("[pppframe]seq%d frame, type %02x port %02x \n", ppp_data.sequence, uwb_data->type, uwb_data->port);
			printf("###########################################################\n");
#endif

			/* parse uwb data type */
			parse_uwbdata_type(uwb_data);

			/*format data and tail to tcpsend ring_buffer */
			if (uwb_data->needsend == 1)
			{
#ifdef TLV_SEND
				/* format to tlv */
				if (tlv_uwbdata(uwb_data, data->tcpsend_buffer->con, &tlv_data) > 0)
				{
					if (uwb_data->uwbtype != Other)
					{
						if ((uwb_data->uwbtype == Sync) && (0 == data->tcpsend_buffer->con->debug_enable))
						{
							/* do not sednd */
							// LOG_LOG("sync is disabled , don't send");
						}
						else
						{
							pthread_mutex_lock(&(data->tcpsend_buffer->mutex));
							if (0 == Rbuf_AddOne(data->tcpsend_buffer->ring_buffer, &tlv_data))
							{
								full_num++;
							}

							pthread_cond_signal(&(data->tcpsend_buffer->cond));
							pthread_mutex_unlock(&(data->tcpsend_buffer->mutex));
						}
					}
				}
#else
				/* format to json */
				pJson_data = json_uwbdata(uwb_data, data->tcpsend_buffer->con);
				if (NULL != pJson_data)
				{
					if (uwb_data->uwbtype != Other)
					{
						if ((uwb_data->uwbtype == Sync) && (0 == data->tcpsend_buffer->con->debug_enable))
						{
							/* do not sednd */
							// LOG_LOG("sync is disabled , don't send");
						}
						else
						{
							pthread_mutex_lock(&(data->tcpsend_buffer->mutex));
							if (0 == Rbuf_AddOne(data->tcpsend_buffer->ring_buffer, pJson_data))
							{
								full_num++;
							}

							pthread_cond_signal(&(data->tcpsend_buffer->cond));
							pthread_mutex_unlock(&(data->tcpsend_buffer->mutex));
						}
					}
					/* free json root */
					free(pJson_data);
				}
#endif

				if (full_num >= 20)
				{
					full_num = 1;
				}
				if (full_num == 1)
				{
					LOG_LOG("uwb buffer is full");
				}

#ifdef DEBUG
				printf("[pppframe] add one format data to tcpsend buffer\n");
#endif
			}
		}

		pthread_mutex_unlock(&(data->pppframe_buffer->mutex));
	}

	free(frame_data);
	free(uwb_data);

	return NULL;
}

