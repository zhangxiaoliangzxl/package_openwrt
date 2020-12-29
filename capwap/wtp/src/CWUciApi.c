#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "uci.h"

#define UCI_WIRELESS_CONFIG_FILE "/etc/config/wireless"

static struct uci_context * ctx = NULL; //定义一个UCI上下文的静态变量.
/*********************************************
*   载入配置文件,并遍历Section.
*/
unsigned int UCIgetRadioCount()
{
    struct uci_package * pkg = NULL;
    struct uci_element *e;
	unsigned int value = 0;

    ctx = uci_alloc_context(); // 申请一个UCI上下文.

    if (UCI_OK != uci_load(ctx, UCI_WIRELESS_CONFIG_FILE, &pkg))
        goto cleanup; //如果打开UCI文件失败,则跳到末尾 清理 UCI 上下文.

    /*遍历UCI的每一个节*/
    uci_foreach_element(&pkg->sections, e)
    {
        struct uci_section *s = uci_to_section(e);

	    if(!strcmp(s->type, "wifi-device"))
	    {
	    	value ++;
	    }
    }
    uci_unload(ctx, pkg); // 释放 pkg 
cleanup:
    uci_free_context(ctx);
    ctx = NULL;

	return value;
}

