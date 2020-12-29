#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elog/elog.h"
#include "init.h"
#include "logs.h"
#include "maclist.h"

static void sort(int *array, int size)
{
	int i, j, temp;
	for (j = 0; j < size - 1; j++)
		for (i = 0; i < size - 1 - j; i++)
		{
			if (array[i] > array[i + 1])
			{
				temp = array[i];
				array[i] = array[i + 1];
				array[i + 1] = temp;
			}
		}
}

static int averageRssi(int *array, int size)
{
	sort(array, size);
	int i, tmp = 0;
	for (i = 1; i < size - 1; i++)
	{
		//	log_i("%d\n", array[i]);
		tmp += array[i];
	}
	i = (tmp / (size - 2));
	// log_i("%d\n", i);
	return i;
}

/* create an empty linklist which have the head node */
LinkList createLinkList(void)
{
	LinkList L = (LinkList)malloc(sizeof(Listnode));
	if (L == NULL)
	{
		log_e("create Linklist failure.");
		return NULL;
	}
	memset(L, 0, sizeof(Listnode));
	return L;
}

/* delete a linklist  */
void deleteLinkList(LinkList L)
{
	LinkList p;
	while (L->next)
	{
		p = L;
		L = L->next;
		free(p);
	}
}

/* add a node to the linklist */
int addClient(LinkList L, char *apmac, char *climac, int rssi)
{
	LinkList p = (LinkList)malloc(sizeof(Listnode));
	if (p == NULL)
	{
		log_e("add node failure.");
		return FAIL;
	}

	memset(p, 0, sizeof(Listnode));
	strcpy(p->data.apmac, apmac);
	strcpy(p->data.climac, climac);
	p->data.rssi = rssi;
	p->data.avgrssi = 0;
	p->data.arssi[0] = rssi;
	p->data.count = 0;

	p->next = L->next;
	L->next = p;

	return SUCCESS;
}

/* reduce a node from linklist */
int reduceClient(LinkList L, char *climac)
{
	LinkList p;
	// doList(L);
	// log_i("%s\n",climac);
	while ((p = L->next))
	{
		// p = L->next;
		// log_i("%s\t%s\t%p%p\n", p->data.climac, climac, p->next, L->next);
		if (!strcmp(p->data.climac, climac))
		{
			L->next = L->next->next;
			free(p);
			//	break;
			return SUCCESS;
		}
		L = L->next;
	}
	// log_i("############\n");
	return FAIL;
}

/* modify a node info in the linklist */
int updateClient(LinkList L, char *apmac, char *climac, int rssi)
{
	L = locateClient(L, climac);
	if (L == NULL)
	{
		return FAIL;
	}
	if (climac != NULL)
	{
		strcpy(L->data.apmac, apmac);
	}
	L->data.count += 1;
	L->data.count %= 5;
	L->data.arssi[L->data.count] = rssi;
	L->data.rssi = rssi;
	// sort(L->data.arssi, sizeof(L->data.arssi)/sizeof(int));
	L->data.avgrssi = averageRssi(L->data.arssi, sizeof(L->data.arssi) / sizeof(int));
	// L->data.avgrssi = 0;
	return SUCCESS;
}

/* locate a node from the linklist */
Listnode *locateClient(LinkList L, char *climac)
{
	while (L->next)
	{
		L = L->next;
		if (!strcmp(L->data.climac, climac))
		{
			return L;
		}
	}
	//	printf("the %s is not found.\n", climac);
	return NULL;
}

/* List LinkList */
void doList(LinkList L)
{
	int i;
	while ((L = L->next) != NULL)
	{
		log_i("apmac:%s climac:%s rssi:%d, avg:%d,", L->data.apmac, L->data.climac, L->data.rssi, L->data.avgrssi);
		for (i = 0; i < 5; i++)
		{
			log_i("%d", (L->data.arssi)[i]);
		}
	}
}

/* List LinkList and do something for every node */
void doLinkList(LinkList L, int (*func)(Listnode *, void *), void *arg)
{
	LinkList Lp = L;
	log_i("**************\n");
	doList(Lp);
	log_i("--------------\n");
	doList(((Linearg *)arg)->L);
	log_i("++++++++++++++\n");
	while (L->next != NULL)
	{
		log_i("xxxxxxxxxxxxxx\n");
		L = L->next;
		log_i("gggggggggggggg\n");
		if (func(L, arg) != 0)
		{
			log_i("%s\n", L->data.climac);
			reduceClient(Lp, L->data.climac);
			log_i("wwwwwwwwwwwwww\n");
		}
		log_i("vvvvvvvvvvvvvv\n");
	}
}

/*
void curClient(void *arg, LinkList *cL)
{
	LinkList L = ((Linearg *)arg)->L;
	log_i("**************\n");
	doList(L);
	log_i("--------------\n");
	doList(cL);
	log_i("++++++++++++++\n");

	while (L->next)
	{
		L = L->next;
	}
}









*/

