#ifndef __INIT_H__
#define __INIT_H__

#include <stdio.h>
#include <string.h>
#include "main.h"
#include "list.h"
#include "log.h"
#include <uci.h>
#include "pthread.h"
#include "main.h"
#include <stdarg.h>
#include "us_list.h"

#define PAKEGE "blconfig"
#define LOG_PATH "/tmp/blutooth"
#define LOG_PATH_HAVE_RO_NO "ls /tmp/* | grep blutoothi | tr -d '\n'"
//#define PATH_STRING(x,y) x##y
#define PINT_CONFIG_C "echo '%s : %s' >>/tmp/blutooth/blconf"
#define PINT_CONFIG_I "echo '%s : %d' >>/tmp/blutooth/blconf"
#define PINT_CONFIG_INIT "echo 'config' >/tmp/blutooth/blconf"

enum echo{
	Y_ECHO,
	N_ECHO
};

int PINT;

int init();
void handle_path(char *);
void echo_config(char *, ...);
int bl_config_uci_get(char *, char *);
extern int set_bl_devid();

#endif
