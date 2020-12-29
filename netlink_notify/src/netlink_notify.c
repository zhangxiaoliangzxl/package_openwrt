/*************************************************************************
>  File Name: netlink_notify.c
>  Author: zxl
>  Mail:
>  Created Time: 2020-09-18 14:43:55
*************************************************************************/

#include <net/netlink.h>
#include <net/sock.h>
#include <stdarg.h>
#include <linux/inetdevice.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/types.h>

#define NETLINK_NOTIFY 25
#define MAX_LOGSIZE 128
#define MAX_MSGSIZE 16

int notify_netdev_event(struct notifier_block *this, unsigned long event, void *ptr);
int notify_inetaddr_event(struct notifier_block *this, unsigned long event, void *ptr);

int usr_pid = 0;
struct sock *nl_sk = NULL;
struct notifier_block inethandle = {.notifier_call = notify_inetaddr_event};
struct notifier_block devhandle = {.notifier_call = notify_netdev_event};

static int stringlength(char *s)
{
	int slen = 0;
	for (; *s; s++)
	{
		slen++;
	}
	return slen;
}

static void my_printk(char *format, ...)
{
	char buffer[MAX_LOGSIZE] = {0};
	int len = 0;

	va_list arg;
	va_start(arg, format);

	len = sprintf(buffer, "[netlink_notify]->");
	vsnprintf(buffer + len, MAX_LOGSIZE - len, format, arg);
	va_end(arg);

	printk("%s", buffer);
}

static void sendnlmsg(char *message, int pid)
{
	struct sk_buff *skb_buf;
	struct nlmsghdr *nlh;
	int len = NLMSG_SPACE(MAX_MSGSIZE);
	int slen = 0;

	if (!message || !nl_sk || !pid)
	{
		my_printk("usr app not work !\n");
		return;
	}

	my_printk("usr app pid:%d.\n", pid);

	skb_buf = alloc_skb(len, GFP_KERNEL);
	if (!skb_buf)
	{
		my_printk("my_net_link:alloc_skb error !\n");
	}

	slen = stringlength(message);
	nlh = nlmsg_put(skb_buf, 0, 0, 0, MAX_MSGSIZE, 0);
	NETLINK_CB(skb_buf).creds.pid = 0;
	NETLINK_CB(skb_buf).dst_group = 0;
	message[slen] = '\0';
	memcpy(NLMSG_DATA(nlh), message, slen + 1);
	my_printk("send to usr message '%s'.\n", (char *)NLMSG_DATA(nlh));
	netlink_unicast(nl_sk, skb_buf, pid, MSG_DONTWAIT);
}

static void nl_data_ready(struct sk_buff *__skb)
{
	struct sk_buff *skb_buf;
	struct nlmsghdr *nlh;
	char str[MAX_MSGSIZE];

	skb_buf = skb_get(__skb);
	if (skb_buf->len >= NLMSG_SPACE(0))
	{
		nlh = nlmsg_hdr(skb_buf);
		memcpy(str, NLMSG_DATA(nlh), sizeof(str));
		my_printk("received message:(%s).\n", str);

		if (NULL != strstr(str, "netlink_notify"))
		{
			usr_pid = nlh->nlmsg_pid;
		}

		kfree_skb(skb_buf);
	}
}

int notify_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	char sendmsg[128] = {0};

	switch (event)
	{
		case NETDEV_UP:
			if (dev && dev->name)
				my_printk("dev(%s) up.\n", dev->name);
			break;
		case NETDEV_DOWN:
			if (dev && dev->name)
				my_printk("dev(%s) down.\n", dev->name);
			break;
		case NETDEV_CHANGE:
			if (dev && dev->name)
			{
				my_printk("dev(%s) status change.\n", dev->name);
				sprintf(sendmsg, "%s", dev->name);
				sendnlmsg(sendmsg, usr_pid);
			}
			break;
		case NETDEV_REBOOT:
		case NETDEV_CHANGEMTU:
		case NETDEV_CHANGEADDR:
		case NETDEV_CHANGENAME:
		case NETDEV_FEAT_CHANGE:
		case NETDEV_BONDING_FAILOVER:
		case NETDEV_POST_TYPE_CHANGE:
		case NETDEV_NOTIFY_PEERS:
		case NETDEV_CHANGEUPPER:
		case NETDEV_RESEND_IGMP:
		case NETDEV_CHANGEINFODATA:
		case NETDEV_CHANGE_TX_QUEUE_LEN:
			if (dev && dev->name)
				my_printk("dev(%s) 111.\n", dev->name);
			break;
		default:
			break;
	}

	return NOTIFY_DONE;
}

int notify_inetaddr_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct net_device *dev = NULL;

	if (ifa && ifa->ifa_dev)
		dev = ifa->ifa_dev->dev;

	switch (event)
	{
		case NETDEV_UP:
			if (dev && dev->name)
				my_printk("inet(%s) up.\n", dev->name);
			break;
		case NETDEV_DOWN:
			if (dev && dev->name)
				my_printk("inet(%s) down.\n", dev->name);
		default:
			break;
	}

	return NOTIFY_OK;
}

static int netlink_init(void)
{
	struct netlink_kernel_cfg cfg = {
		.input = nl_data_ready,
	};

	nl_sk = netlink_kernel_create(&init_net, NETLINK_NOTIFY, &cfg);
	if (!nl_sk)
	{
		my_printk("netlink_notify -> create netlink fail.\n");
		return 1;
	}
	my_printk("netlink_notify -> create netlink successful.\n");
	return 0;
}

static void netlink_exit(void)
{
	if (nl_sk != NULL)
	{
		sock_release(nl_sk->sk_socket);
	}
	my_printk("netlink_notify -> netlink closed.\n");
}

static int __init notify_init(void)
{
	register_netdevice_notifier(&devhandle);
	register_inetaddr_notifier(&inethandle);

	netlink_init();

	return 0;
}

static void __exit notify_exit(void)
{
	unregister_netdevice_notifier(&devhandle);
	unregister_inetaddr_notifier(&inethandle);

	netlink_exit();

	return;
}

module_init(notify_init);
module_exit(notify_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zxl");
MODULE_DESCRIPTION("notify netlink status");
