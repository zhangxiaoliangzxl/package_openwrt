#include "init.h"

#include <uci.h>

#include "elog/elog.h"

int switch_vlan_num = 0;
int wifi_iface_num = 0;
int interface_num = 0;
int delc = 0;

static void readarg(char *args, char *buf, int size)
{
	memset(buf, 0, size);
	FILE *fp = popen(args, "r");
	if (fp == NULL)
	{
		log_e("fopen error: line %d file %s", __LINE__, __FILE__);
		return;
	}
	fgets(buf, size, fp);
	pclose(fp);
}

static cJSON *getWireless(void)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg = NULL;
	struct uci_element *e1 = NULL, *e2 = NULL, *e3 = NULL;
	struct uci_section *s = NULL;
	struct uci_option *o;

	int device_number = 0, iface_number = 0;

	ctx = uci_alloc_context();
	if (!ctx)
		return NULL;

	if (uci_load(ctx, "wireless", &pkg) != UCI_OK)
	{
		uci_free_context(ctx);
		return NULL;
	}

	cJSON *wireless = cJSON_CreateObject();
	cJSON *wifi_device = cJSON_CreateArray();
	cJSON *wifi_iface = cJSON_CreateArray();
	cJSON *tmp = NULL, *tmparray = NULL;
	cJSON_AddItemToObject(wireless, "wifi-device", wifi_device);
	cJSON_AddItemToObject(wireless, "wifi-iface", wifi_iface);

	uci_foreach_element(&pkg->sections, e1)
	{
		s = uci_to_section(e1);
		tmp = cJSON_CreateObject();
		if (!strcmp(s->type, "wifi-device"))
		{
			cJSON_AddItemToArray(wifi_device, tmp);
			cJSON_AddNumberToObject(tmp, "section_number", device_number);
			device_number++;
		}
		else if (!strcmp(s->type, "wifi-iface"))
		{
			cJSON_AddItemToArray(wifi_iface, tmp);
			cJSON_AddNumberToObject(tmp, "section_number", iface_number);
			iface_number++;
		}
		else
		{
			cJSON_Delete(tmp);
			continue;
		}
		if (s->anonymous == false)
			cJSON_AddStringToObject(tmp, "section_name", s->e.name);
		cJSON_AddStringToObject(tmp, "section_type", s->type);
		uci_foreach_element(&s->options, e2)
		{
			o = uci_to_option(e2);
			if (o->type == UCI_TYPE_STRING)
			{
				/* do not upload wifi macaddr */
				if (strcmp(o->e.name, "macaddr") != 0)
				{
					cJSON_AddStringToObject(tmp, o->e.name, o->v.string);
				}
				continue;
			}
			tmparray = cJSON_CreateArray();
			cJSON_AddItemToObject(tmp, o->e.name, tmparray);
			uci_foreach_element(&o->v.list, e3)
			{
				cJSON_AddItemToArray(tmparray, cJSON_CreateString(e3->name));
			}
		}
	}

	uci_unload(ctx, pkg);

	uci_free_context(ctx);

	wifi_iface_num = iface_number;

	return wireless;
}

static cJSON *getNetWork(const int type)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg = NULL;
	struct uci_element *e1 = NULL, *e2 = NULL, *e3 = NULL;
	struct uci_section *s = NULL;
	struct uci_option *o;

	int interface_number = 0, vlan_number = 0;

	ctx = uci_alloc_context();
	if (!ctx)
		return NULL;

	if (uci_load(ctx, "network", &pkg) != UCI_OK)
	{
		uci_free_context(ctx);
		return NULL;
	}

	cJSON *network = cJSON_CreateObject();
	cJSON *interface = cJSON_CreateArray();
	cJSON *switch_vlan = cJSON_CreateArray();
	cJSON *tmp = NULL, *tmparray = NULL;
	cJSON_AddItemToObject(network, "interface", interface);
	cJSON_AddItemToObject(network, "switch_vlan", switch_vlan);

	uci_foreach_element(&pkg->sections, e1)
	{
		s = uci_to_section(e1);
		tmp = cJSON_CreateObject();
		if (!strcmp(s->type, "interface"))
		{
			cJSON_AddItemToArray(interface, tmp);
			cJSON_AddNumberToObject(tmp, "section_number", interface_number);
			interface_number++;
		}
		else if (!strcmp(s->type, "switch_vlan"))
		{
			cJSON_AddItemToArray(switch_vlan, tmp);
			cJSON_AddNumberToObject(tmp, "section_number", vlan_number);
			vlan_number++;
		}
		else
		{
			cJSON_Delete(tmp);
			continue;
		}
		if (s->anonymous == false)
			cJSON_AddStringToObject(tmp, "section_name", s->e.name);
		cJSON_AddStringToObject(tmp, "section_type", s->type);
		uci_foreach_element(&s->options, e2)
		{
			o = uci_to_option(e2);
			if (o->type == UCI_TYPE_STRING)
			{
				cJSON_AddStringToObject(tmp, o->e.name, o->v.string);
				continue;
			}
			tmparray = cJSON_CreateArray();
			cJSON_AddItemToObject(tmp, o->e.name, tmparray);
			uci_foreach_element(&o->v.list, e3)
			{
				cJSON_AddItemToArray(tmparray, cJSON_CreateString(e3->name));
			}
		}
	}

	uci_unload(ctx, pkg);

	uci_free_context(ctx);

	switch_vlan_num = vlan_number;
	interface_num = interface_number;

	return network;
}

static cJSON *config2json(const char *configname)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg = NULL;
	struct uci_element *e1 = NULL, *e2 = NULL, *e3 = NULL;
	struct uci_section *s = NULL;
	struct uci_option *o = NULL;

	ctx = uci_alloc_context();
	if (!ctx)
		return NULL;

	if (uci_load(ctx, configname, &pkg) != UCI_OK)
	{
		uci_free_context(ctx);
		return NULL;
	}

	cJSON *out = cJSON_CreateObject();
	cJSON *tmp = NULL, *tmparray = NULL;

	uci_foreach_element(&pkg->sections, e1)
	{
		s = uci_to_section(e1);

		if (s->anonymous == true)
			continue;
		// cJSON_AddStringToObject(tmp, "section_name", s->e.name);
		tmp = cJSON_CreateObject();

		cJSON_AddItemToObject(out, s->e.name, tmp);
		cJSON_AddStringToObject(tmp, "section_name", s->e.name);
		cJSON_AddStringToObject(tmp, "section_type", s->type);
		uci_foreach_element(&s->options, e2)
		{
			o = uci_to_option(e2);
			if (o->type == UCI_TYPE_STRING)
			{
				cJSON_AddStringToObject(tmp, o->e.name, o->v.string);
				continue;
			}
			tmparray = cJSON_CreateArray();
			cJSON_AddItemToObject(tmp, o->e.name, tmparray);
			uci_foreach_element(&o->v.list, e3)
			{
				cJSON_AddItemToArray(tmparray, cJSON_CreateString(e3->name));
			}
		}
	}

	uci_unload(ctx, pkg);

	uci_free_context(ctx);

	return out;
}

static cJSON *getProbe(void)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg = NULL;
	struct uci_element *e1 = NULL, *e2 = NULL, *e3 = NULL;
	struct uci_section *s = NULL;
	struct uci_option *o;

	int interface_number = 0, interface1_number = 0;

	ctx = uci_alloc_context();
	if (!ctx)
		return NULL;

	if (uci_load(ctx, "cscan", &pkg) != UCI_OK)
	{
		uci_free_context(ctx);
		return NULL;
	}

	cJSON *probe = cJSON_CreateObject();
	cJSON *interface = cJSON_CreateArray();
	cJSON *interface1 = cJSON_CreateArray();
	cJSON *tmp = NULL, *tmparray = NULL;
	cJSON_AddItemToObject(probe, "interface", interface);
	cJSON_AddItemToObject(probe, "interface1", interface1);

	uci_foreach_element(&pkg->sections, e1)
	{
		s = uci_to_section(e1);
		tmp = cJSON_CreateObject();
		if (!strcmp(s->type, "interface1"))
		{
			cJSON_AddItemToArray(interface1, tmp);
			cJSON_AddNumberToObject(tmp, "section_number", interface1_number);
			interface1_number++;
		}
		else if (!strcmp(s->type, "interface"))
		{
			cJSON_AddItemToArray(interface, tmp);
			cJSON_AddNumberToObject(tmp, "section_number", interface_number);
			interface_number++;
		}
		else
		{
			cJSON_Delete(tmp);
			continue;
		}
		if (s->anonymous == false)
			cJSON_AddStringToObject(tmp, "section_name", s->e.name);
		cJSON_AddStringToObject(tmp, "section_type", s->type);
		uci_foreach_element(&s->options, e2)
		{
			o = uci_to_option(e2);
			if (o->type == UCI_TYPE_STRING)
			{
				cJSON_AddStringToObject(tmp, o->e.name, o->v.string);
				continue;
			}
			tmparray = cJSON_CreateArray();
			cJSON_AddItemToObject(tmp, o->e.name, tmparray);
			uci_foreach_element(&o->v.list, e3)
			{
				cJSON_AddItemToArray(tmparray, cJSON_CreateString(e3->name));
			}
		}
	}

	uci_unload(ctx, pkg);

	uci_free_context(ctx);

	return probe;
}

int count(char *cmd)
{
	char buf[BUF];
	readarg(cmd, buf, sizeof(buf));
	return atoi(buf);
}

int gainWific(void)
{
	return count("uci -q show wireless | grep =wifi-iface | wc -l | tr -d \'\\n\'");
}

/* 函数功能：获得AP的开机配置信息并且以json格式的方式存储 */
cJSON *init(int type)
{
	cJSON *coninfo = cJSON_CreateObject();
	// cJSON_AddItemToObject(coninfo, "wireless", getWireless());
	// cJSON_AddItemToObject(coninfo, "network", getNetWork(type));
	// cJSON_AddItemToObject(coninfo, "probe", getProbe());
	cJSON_AddItemToObject(coninfo, "mesh", config2json("mesh"));
	cJSON_AddItemToObject(coninfo, "ac", config2json("aconf"));
	cJSON_AddItemToObject(coninfo, "rtty", config2json("rtty"));
	cJSON_AddItemToObject(coninfo, "uwb", config2json("uwbcon"));
	cJSON_AddItemToObject(coninfo, "alarm", config2json("alarm"));
	cJSON_AddItemToObject(coninfo, "blue", config2json("blconfig"));
	cJSON_AddItemToObject(coninfo, "433M", config2json("433Mcon"));

	cJSON_AddStringToObject(coninfo, "version", "ac_new_v2.0");

	return coninfo;
}
