#ifndef __MACLIST_H__
#define __MACLIST_H__

/* return value */
#define SUCCESS 0
#define FAIL -1

/* flag value */
#define ONLINE 0
#define OFFLINE 1

struct client
{
	char apmac[20];
	char climac[20];
	int count;
	int rssi;
	int avgrssi;
	int arssi[5];
};

typedef struct node
{
	struct client data;
	struct node *next;
} Listnode, *LinkList;

/* create an empty linklist which have the head node */
extern LinkList createLinkList(void);

/* delete a linklist  */
extern void deleteLinkList(LinkList L);

/* add a node to the linklist */
extern int addClient(LinkList L, char *apmac, char *climac, int rssi);

/* reduce a node from linklist */
extern int reduceClient(LinkList L, char *climac);

/* modify a node info in the linklist */
extern int updateClient(LinkList L, char *apmac, char *climac, int rssi);

/* locate a node from the linklist */
extern Listnode *locateClient(LinkList L, char *climac);

/* List LinkList */
extern void doList(LinkList L);

/* List LinkList and do something for every node */
extern void doLinkList(LinkList L, int (*func)(Listnode *, void *arg), void *arg);

#endif
