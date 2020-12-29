#ifndef __FUNC_H__
#define __FUNC_H__

#include "init.h"
#include "maclist.h"
#include "mcurl.h"

typedef struct _uwb_info
{
	char runtime[32];
	char payload[32];
	char matid[16];
	char localid[16];
	char upgrade[4];
	char uwbversion[32];
} UWBINFO;

char apmac[32], wanip[32], lanip[32], hwtype[32], systemversion[32], systemtype[32], lan_broadcast[16];
char ap_type[32], ap_version[32];
char ssid[128];
unsigned long devnumbers, starttime, freetime, cpuruntime, channel, probestat, uwbstat, bluestat, wireless433stat, alarmstate, devdimension;

UWBINFO _uwbinfo;
// char *pUWBinfo = &_uwbinfo;

int get_broadcast_by_ifname(char *ifname, char *broadcast);
void get_value_by_key(char *keyAndValue, char *key, char *outvalue);
int get_hostip_by_url(char *url, char *hostip);
int get_ap_ip(void);
int get_enable_capwap(void);
int _popen(const char *cmd, char *resault, int resault_len);

int getGet(char *dest, char *cmd, int n);

int get_disabled(void);

void get_rssi(int *rssi);

void get_server_ip(char *ip);

void get_mac(char *mac);

void get_lan_ip(char *ip);

void get_wan_ip(char *ip);

void get_devnumbers(unsigned long *num);

void get_ssid(char *ssid);

void get_channel(unsigned long *channel);
void get_dimension(unsigned long *dimension);

void get_info(char *hwtype, char *systemtype, char *systemversion);

void get_time(unsigned long *cpuruntime, unsigned long *freetime);

void md5key(char *key, void *data);

void ac_is_running(void);

cJSON *heart_init(const int systype);

void do_unexpected(void);

int check_key(char *key);

int env_check(char *ip);

int server_check(const char *cloudinterface, const int encryption, const char *mac, int type);

cJSON *heart_up(const char *cloudinterface, const int encryption, cJSON *heart, const char *mac);

void net_conf(const char *cloudinterface, const int encryption, const char *cmdurl, const char *mac, int type, int *resultup);

void generate_cmd(char *cloudinterface, const int encryption, cJSON *root, char *mac, int type);

void sendclientlist(char *mac);

void data_init(int type);

int getsystype(const char *type);

void getclients(LinkList L, void *mac);

int checkclient(Listnode *node, void *arg);

void preventClient(Listnode *node);

void makecJSON_Array(LinkList L, cJSON *array);

void sendClientToserver(const char *cloudinterface, const int encryption, LinkList L, char *mac);

void curClient(void *arg, LinkList cL);

void int_handler(int signum);

void term_handler(int signum);

void hup_handler(int signum);

void segv_handler(int signum);

void pipe_handler(int signum);

void *searchclient(void *arg);

void get_wireless(cJSON *wireless);

void get_txpower(const char *radio, cJSON *item);

void get_radio_channel(const char *radio, cJSON *item);

void get_radio_hwmode(const char *radio, cJSON *item);
void get_radio_htmode(const char *radio, cJSON *item);

int get_radio_ssidnum(const char *radio);

void get_radio_ssidc(const char *radio, cJSON *item);

void get_radio_disabled(const char *radio, cJSON *item);

void get_wireless_heart(const char *radio, cJSON *item);

void get_radio(const char *radio, cJSON *wireless);

int get_radionumber(void);

int result_up(const char *cloudinterface, const int encryption, char *data, const char *mac);

int parse_url(const char *url, const char *protocl, char *host, unsigned int *port, char *abs_path);

#endif
