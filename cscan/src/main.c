/* horst - Highly Optimized Radio Scanning Tool
 *
 * Copyright (C) 2005-2015 Bruno Randolf (br1@einfach.org)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <err.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/wait.h>

#include "main.h"
#include "util.h"
#include "capture.h"
#include "protocol_parser.h"
#include "wlan_util.h"
#include "ieee80211_util.h"
#include "channel.h"
#include "node.h"
#include "conf_options.h"
#include "ifctrl.h"
#include "ipc_unix.h"

struct list_head nodes;
struct node_names_info node_names;

struct config conf;

struct timeval the_time;
struct timeval the_time1;

int mon; /* monitoring socket */
static pid_t pid;

/* 数据 */
static FILE* DF = NULL;
static FILE* DFF = NULL;
static char* realtimef = "/tmp/cscan/outfile1";

/* receive packet buffer
 *
 * due to the way we receive packets the network (TCP connection) we have to
 * expect the reception of partial packet as well as the reception of several
 * packets at one. thus we implement a buffered receive where partially received
 * data stays in the buffer.
 *
 * we need two buffers: one for packet capture or receiving from the server and
 * another one for data the clients sends to the server.
 *
 * not sure if this is also an issue with local packet capture, but it is not
 * implemented there.
 *
 * size: max 80211 frame (2312) + space for prism2 header (144)
 * or radiotap header (usually only 26) + some extra */
static unsigned char buffer[2312 + 200];

/* for select */
static fd_set read_fds;
static fd_set write_fds;
static fd_set excpt_fds;

//static volatile sig_atomic_t is_sigint_caught;

/***********************************************
 *function:获取指定文件的大小
 *@strFileName: 目标文件
 *return:文件大小
 ***********************************************/
int getfilesize(char * strFileName)    
{   
	FILE * fp = fopen(strFileName, "r");   
	fseek(fp, 0L, SEEK_END);   
	int size = ftell(fp);   
	fclose(fp);   
	return size;   
}  

//void __attribute__ ((format (printf, 1, 2)))
void _printlog(const char *fmt, ...)
{
	char buf[512], buf1[28];
	va_list ap;

	FILE* DFL = NULL;
	if(getpid() == pid)
		sprintf(buf, "/tmp/cscan/mlog-%s", "child");
	else
		sprintf(buf, "/tmp/cscan/mlog-%s", "parent");

	DFL = fopen(buf, "r"); 
	if(DFL == NULL)
	{
		DFL = fopen(buf, "w"); 
		if(DFL == NULL)
		{
			fprintf(stderr, "mlog-x open err!\n");
			return;
		}
	}
	fseek(DFL, 0L, SEEK_END);   
	int size = ftell(DFL);   
	fclose(DFL);
	if(size > 10240)
	{
		DFL = fopen(buf, "w"); 
	}
	else
	{
		DFL = fopen(buf, "a+"); 
	}
	va_start(ap, fmt);
	vsnprintf(&buf[1], 510, fmt, ap);
	fprintf(DFL, "[%d]:%s", (int)time(NULL), &buf[1]);
	va_end(ap);
	fclose(DFL);
}

/***********************************************
 *function: write log
 *@opt: selection
 *@p: content
 *return:NULL
 ***********************************************/
void write_to_file_debug(int opt, char* p)
{
	if (conf.dumpfile[0] == '\0' || DF == NULL)
	{
		return;
	}
	if(getfilesize(conf.dumpfile) > 102400)
	{
		rewind(DF);
		fclose(DF);
		DF = fopen(conf.dumpfile, "w");
		fprintf(DF,"%s", "dumpfile erase!\n");
	}

	if(opt)
		fprintf(DF, ">>>%s \n\n", p);
	else
		fprintf(DF, "<<<%s \n\n", p);

	fflush(DF);
}

void write_to_file_debug1(struct packet_info * p)
{

	char data[128];

	sprintf(data, "[ %d, %s, %d, %d ]", (int)time(NULL), ether_sprintf(p->wlan_src), p->wlan_channel, p->phy_signal);

	if (DFF == NULL)
	{
		return;
	}

	if(getfilesize(realtimef) > 102400)
	{
		rewind(DFF);
		fclose(DFF);
		DFF = fopen(realtimef, "w");
		fprintf(DFF, "%s", ">>>>>dumpfile erase<<<<<\n");
	}

	fprintf(DFF, "--->%s \n\n", data);

	fflush(DFF);
}

/* return true if packet is filtered */
static bool filter_packet(struct packet_info* p)
{
	int i;

	if (p->phy_signal > -30 || p->phy_signal < -90)
	{
		return false;
	}

	if(MAC_EMPTY(p->wlan_src))
	{
		return false;
	}

	/* filter MAC adresses */
	/* CULL mode for build the data base */
	if (conf.do_macfilter) {
		for (i = 0; i < MAX_FILTERMAC; i++) {
			//if (MAC_NOT_EMPTY(p->wlan_src) &&
			if(conf.filtermac_enabled[i] &&
					memcmp(p->wlan_src, conf.filtermac[i], MAC_LEN) == 0) {
				return true;
			}
		}
		return false;
	}
	/* location mode just care the filter mode */
	else if (p->wlan_mode & conf.filter_mode){
		return true;
	}
	return false;
}

void fixup_packet_channel(struct packet_info* p)
{
	int i = -1;

	/* get channel index for packet */
	if (p->phy_freq) {
		i = channel_find_index_from_freq(p->phy_freq);
	}

	/* if not found from pkt, best guess from config but it might be
	 * unknown (-1) too */
	if (i < 0)
		p->pkt_chan_idx = conf.channel_idx;
	else
		p->pkt_chan_idx = i;

	/* wlan_channel is only known for beacons and probe response,
	 * otherwise we set it from the physical channel */
	if (p->wlan_channel == 0 && p->pkt_chan_idx >= 0)
		p->wlan_channel = channel_get_chan(p->pkt_chan_idx);

	/* if current channel is unknown (this is a mac80211 bug), guess it from
	 * the packet */
	if (conf.channel_idx < 0 && p->pkt_chan_idx >= 0)
		conf.channel_idx = p->pkt_chan_idx;
}

void handle_packet(struct packet_info* p)
{
	/* filter on server side only */
	if (!filter_packet(p)) {
		return;
	}

	fixup_packet_channel(p);

#if 0
	write_to_file_debug1(p);
#endif

	node_update(p);
}

static void local_receive_packet(int fd, unsigned char* buffer, size_t bufsize)
{
	int len;
	struct packet_info p;

	len = recv_packet(fd, buffer, bufsize);

	memset(&p, 0, sizeof(p));

	if (!parse_packet(buffer, len, &p)) {
		return;
	}

	handle_packet(&p);
}

static void receive_any()
{
	int ret, mfd;
	long usecs;
	struct timespec ts;

	FD_ZERO(&read_fds);
	FD_ZERO(&write_fds);
	FD_ZERO(&excpt_fds);

	FD_SET(mon, &read_fds);

	usecs = max(0, min(channel_get_remaining_dwell_time(), 1000000));
	ts.tv_sec = usecs / 1000000;
	ts.tv_nsec = usecs % 1000000 * 1000;
	mfd = 0;
	mfd = max(mon, mfd);

	ret = pselect(mfd+1, &read_fds, &write_fds, &excpt_fds, &ts, NULL);
	if (ret == -1 && errno == EINTR) /* interrupted */
	{
		exit(-1);
	}
	if (ret == 0) { /* timeout */
		/*ifname was broken*/
		if(!ifctrl_iwget_interface_check(conf.ifname))
		{
			/* ifname was broken */
			exit(-1);
		}
		else
		{
			/* no data */
			return;
		}
	}
	else if (ret < 0) /* error */
		err(1, "select()");

	/* local packet or client */
	if (FD_ISSET(mon, &read_fds)) {
		local_receive_packet(mon, buffer, sizeof(buffer));
	}
}

void free_lists(void)
{
	struct node_info *ni, *mi;

	/* free node list */
	list_for_each_safe(&nodes, ni, mi, list) {
		list_del(&ni->list);
		free(ni);
	}
}

static void exit_handler(void)
{
	free_lists();

	ifctrl_flags(conf.ifname, false, false);

	if (conf.monitor_added)
		ifctrl_iwdel(conf.ifname);

	if (DF != NULL) {
		fclose(DF);
		DF = NULL;
	}

	ifctrl_finish();
}

static void sigint_handler(int sig)
{
	/* Only set an atomic flag here to keep processing in the interrupt
	 * context as minimal as possible (at least all unsafe functions are
	 * prohibited, see signal(7)). The flag is handled in the mainloop. */
	exit_handler();
	printlog("Yes I will exit!!!\n");
	//is_sigint_caught = 1;
	if(sig == SIGCHLD)
	{
		printlog("child get out\n");
		/*I get child gone*/
		wait(NULL);
	}
	exit(EXIT_SUCCESS);
}

static void sigpipe_handler(__attribute__((unused)) int sig)
{
	/* ignore signal here - we will handle it after write failed */
}

const char* mac_name_lookup(const unsigned char* mac, int shorten_mac)
{
	int i;
	if (conf.mac_name_lookup) {
		for (i = 0; i < node_names.count; i++) {
			if (memcmp(node_names.entry[i].mac, mac, MAC_LEN) == 0)
				return node_names.entry[i].name;
		}
	}
	return shorten_mac ? ether_sprintf_short(mac) : ether_sprintf(mac);
}

static void generate_mon_ifname(char *const buf, const size_t buf_size)
{
	unsigned int i;

	for (i=0;; ++i) {
		int len;

		len = snprintf(buf, buf_size, "cscan%d", 0);
		if (len < 0)
			err(1, "failed to generate monitor interface name");
		if ((unsigned int) len >= buf_size)
		{
			errx(1, "failed to generate a sufficiently short "
			     "monitor interface name");
			exit(EXIT_FAILURE);
		}
		if (!if_nametoindex(buf))
			break;  /* interface does not exist yet, done */

		ifctrl_flags(buf, false, false);
		ifctrl_iwdel(buf);

		if (!if_nametoindex(buf))
			break;  /* interface does not exist yet, done */
	}
}

static unsigned int retry = 0;

static void main_loop()
{
	for( ;/*for ever*/; )
	{
		receive_any(NULL);

		/* upload trigger */
		timeout_nodes();

		gettimeofday(&the_time, NULL);

		if(! conf.do_change_channel)
		{
			continue;
		}

		switch(channel_auto_change())
		{
			case 127:
				retry++;
				break;
			case 126:
				conf.do_change_channel = 0;
				break;
			default:
				retry = 0;
				break;
		}
		if(retry > 2)
		{
			printlog("exit for retry:%d\n", retry);
			exit(EXIT_FAILURE);
		}
	}
}

/*just do upload*/
static void upload()
{
	int ipc_fd = ipc_ServerInit();
	int clifd = -1;

	for(; /*for ever*/ ;)
	{
		if ((clifd = ipc_accept(ipc_fd)) <= 0)
		{
			close(ipc_fd);
			ipc_fd = ipc_ServerInit();
			continue;
		}

		ipc_recieve(clifd);
		close(clifd);
	}
}

int main(int argc, char** argv)
{
	struct sigaction sigint_action;
	struct sigaction sigpipe_action;

	list_head_init(&nodes);

	memset(&conf, 0x00, sizeof(conf));

	config_parse_file_and_cmdline(argc, argv);

	sigint_action.sa_handler = sigint_handler;
	sigemptyset(&sigint_action.sa_mask);
	sigint_action.sa_flags = 0;
	sigaction(SIGINT, &sigint_action, NULL);
	sigaction(SIGTERM, &sigint_action, NULL);
	sigaction(SIGHUP, &sigint_action, NULL);
	/*avoid child get into zone*/
	sigaction(SIGCHLD, &sigint_action, NULL);

	sigpipe_action.sa_handler = sigpipe_handler;
	sigaction(SIGPIPE, &sigpipe_action, NULL);

	//atexit(exit_handler);

	gettimeofday(&the_time, NULL);
	gettimeofday(&the_time1, NULL);

	conf.channel_idx = -1;

	ifctrl_init();
	/* just try waiting for phy ready */
	ifctrl_iwget_phy_info(conf.ifname);

	/* if the interface is not already in monitor mode, try to set
	 * it to monitor or create an additional virtual monitor interface */
	if (conf.add_monitor) {
		char mon_ifname[IF_NAMESIZE];
		generate_mon_ifname(mon_ifname, IF_NAMESIZE);
		if (!ifctrl_iwadd_monitor(conf.ifname, mon_ifname))
			err(1, "failed to add virtual monitor interface");

		printlog("INFO: A virtual interface '%s' will be used "
				"instead of '%s'.", mon_ifname, conf.ifname);

		strncpy(conf.ifname, mon_ifname, IF_NAMESIZE);
		conf.monitor_added = 1;
		/* Now we have a new monitor interface, proceed
		 * normally. The interface will be deleted at exit. */
	}

	if (!ifctrl_flags(conf.ifname, true, true))
		err(1, "failed to bring interface '%s' up",
				conf.ifname);

	/* get info again, as chan width is only available on UP interfaces */
	ifctrl_iwget_interface_info(conf.ifname);

	mon = open_packet_socket(conf.ifname, conf.recv_buffer_size);
	if (mon <= 0)
		err(1, "Couldn't open packet socket");
	conf.arphrd = device_get_hwinfo(mon, conf.ifname,
			conf.my_mac_addr);

	if (conf.arphrd != ARPHRD_IEEE80211_PRISM &&
			conf.arphrd != ARPHRD_IEEE80211_RADIOTAP)
		err(1, "interface '%s' is not in monitor mode",
				conf.ifname);

	if (!channel_init())
		err(1, "failed to change the initial channel number");

	printlog("Max PHY rate: %d Mbps\n", conf.max_phy_rate/10);

	/* process for upload */
	if ((pid = fork()) < 0) 
	{
		perror("fork:");
		exit(-1);
	}
	else if (pid == 0)
	{
		upload();
	}
	else
	{
		printlog("main pid:%d, child pid:%d\n", getpid(), pid);
		main_loop();
	}
	return 0;
}

void dumpfile_open(const char* name)
{
	if (DF != NULL) {
		fclose(DF);
		DF = NULL;
	}

	if (DFF != NULL) {
		fclose(DFF);
		DFF = NULL;
	}


	if (name == NULL || strlen(name) == 0) {
		printlog("- Not writing outfile");
		conf.dumpfile[0] = '\0';
		return;
	}

	strncpy(conf.dumpfile, name, MAX_CONF_VALUE_STRLEN);
	conf.dumpfile[MAX_CONF_VALUE_STRLEN] = '\0';
	DF = fopen(conf.dumpfile, "w");
	if (DF == NULL)
		err(1, "Couldn't open dump file");

	printlog("- Writing to outfile %s", conf.dumpfile);

	DFF = fopen("/tmp/cscan/outfile1", "w");
	if (DFF == NULL)
		err(1, "Couldn't open dump file1");
}
