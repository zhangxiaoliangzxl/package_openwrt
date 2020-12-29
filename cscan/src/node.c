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

#include "main.h"
#include "util.h"
#include "wlan80211.h"
#include "node.h"
#include "ipc_unix.h"

#include <unistd.h>
#include <string.h>
#include <time.h>

static struct timeval last_nodetimeout;

static inline void copy_nodeinfo(struct node_info* n, struct packet_info* p)
{
	if (p->ip_src)
		n->ip_src = p->ip_src;
	if (p->wlan_mode)
		n->wlan_mode = p->wlan_mode;
//	if (p->wlan_ht40plus)
//		n->wlan_ht40plus = 1;
//	if (p->wlan_tx_streams)
//		n->wlan_tx_streams = p->wlan_tx_streams;
//	if (p->wlan_rx_streams)
//		n->wlan_rx_streams = p->wlan_rx_streams;

	// otherwise only override if channel was unknown
	n->wlan_channel = p->wlan_channel;

	//ewma_add(&n->phy_sig_avg, -p->phy_signal);
	n->phy_sig_sum += -p->phy_signal;
	n->phy_sig_count ++;

	memcpy(n->wlan_src, p->wlan_src, MAC_LEN);

	//if (p->wlan_chan_width > n->wlan_chan_width)
	//	n->wlan_chan_width = p->wlan_chan_width;
}

struct node_info* node_update(struct packet_info* p)
{
	struct node_info* n;

	if (p->phy_flags & PHY_FLAG_BADFCS)
		return NULL;

	/* find node by wlan source address */
	list_for_each(&nodes, n, list) {
		if (memcmp(p->wlan_src, n->wlan_src, MAC_LEN) == 0) {
			break;
		}
	}

	/* not found */
	if (&n->list == &nodes.n) {
		n = (struct node_info *)malloc(sizeof(struct node_info));
		memset(n, 0, sizeof(struct node_info));
//		ewma_init(&n->phy_sig_avg, 1024, 8);
		list_add_tail(&nodes, &n->list);
	}

	copy_nodeinfo(n, p);

	return n;
}

/************************************************
 * function: generate json string of clients
 * @data: json string of clients
 * @return: length of json string
 ***********************************************/
static int json_data(char **data, unsigned int *dlen)
{
	char *dat = NULL;
	struct json_object *infor_object = NULL;
	struct json_object *result = NULL;
	struct json_object *array_object = NULL;
	struct json_object *tmp_obj = NULL;

	struct node_info *n, *m;

	unsigned int num= 0;

	*dlen = 0;

	/*json init*/
	infor_object = json_object_new_object();
	if (NULL == infor_object)
	{
		printlog("new json object failed.\n");
		exit(EXIT_FAILURE);
	}
	/*client info*/
	array_object = json_object_new_array();
	if (NULL == array_object)
	{
		printlog("new json object failed.\n");
		json_object_put(infor_object);//free
		exit(EXIT_FAILURE);
	}
	result = json_object_new_object();
	if (NULL == result)
	{
		printlog("new json object failed.\n");
		json_object_put(infor_object);
		json_object_put(array_object);
		exit(EXIT_FAILURE);
	}

	list_for_each_safe(&nodes, n, m, list) {
//		tmp_obj = json_object_new_string(ether_sprintf_com(n->wlan_src));
//		json_object_object_add(infor_object, "mac", tmp_obj);
		json_object_object_add(infor_object, "mac", 
				json_object_new_string(ether_sprintf_com(n->wlan_src)));

//		tmp_obj = json_object_new_int(-((n->phy_sig_sum)/(n->phy_sig_count)));
//		json_object_object_add(infor_object, "rssi", tmp_obj);

		json_object_object_add(infor_object, "rssi", 
				json_object_new_int(-((n->phy_sig_sum)/(n->phy_sig_count))));

//		tmp_obj = json_object_new_int(n->wlan_channel);
//		json_object_object_add(infor_object, "chan", tmp_obj);

		json_object_object_add(infor_object, "chan", 
				json_object_new_int(n->wlan_channel));

		/*需要将对象转成普通字符串后再转化为标准JSON对象*/
		tmp_obj = json_tokener_parse(json_object_to_json_string(infor_object));
		json_object_array_add(array_object, tmp_obj);
		//json_object_array_add(array_object, infor_object);

		/*删除节点*/
		list_del(&n->list);
		if(n)free(n);
		num ++;
	}

	if(num == 0)
		goto out;

	tmp_obj = json_object_new_int((int)time(NULL));
	json_object_object_add(result, "stamp", tmp_obj);
	json_object_object_add(result, conf.apID, array_object);

	dat = (char*)json_object_to_json_string(result);
	if(dat)
	{
		*dlen = strlen(dat);
	}

	/*+6: data=*/
	*data = (char *)calloc(*dlen+7, sizeof(char));
	memcpy(*data, "data=", 5);
	memcpy(*data+5, dat, *dlen);

out:
	/*free*/
//	while((NULL != tmp_obj) && (1 != json_object_put(tmp_obj)));
//	while((NULL != infor_object) && (1 != json_object_put(infor_object)));
//	while((NULL != array_object) && (1 != json_object_put(array_object)));
//	while((NULL != result) && (1 != json_object_put(result)));

	json_object_put(infor_object);
	json_object_put(array_object);
	json_object_put(result);
	return num;
}

void timeout_nodes()
{
	char *data = NULL;
	unsigned int num, len;
	int clifd;
	IPC ipc_send;

	if(the_time.tv_sec - last_nodetimeout.tv_sec >= conf.node_timeout)
	{
		if((num = json_data(&data, &len)) <= 0)
		{
			printlog("json encode err!\n");
			return;
		}
		/*trigger the send process*/
		ipc_send.cmd = IPC_SEND_CLIENTS;
		ipc_send.len = len+5;
		ipc_send.value = (void*)data;
		clifd = ipc_ClientInit();
		if(clifd < 0)
		{
			printlog("ipc_ClientInit error!\n");
			if(data)free(data);
			data = NULL;
			return;
		}
		len = ipc_trigger(ipc_send, clifd);
		/* update the time */
		last_nodetimeout = the_time;
		if(data)free(data);
		data = NULL;
		close(clifd);
	}
}
