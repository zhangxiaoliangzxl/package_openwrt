#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "uci.h"

#define UCI_WIRELESS_CONFIG_FILE "/etc/config/wireless"

static struct uci_context * ctx = NULL; //����һ��UCI�����ĵľ�̬����.
/*********************************************
*   ���������ļ�,������Section.
*/
unsigned int UCIgetRadioCount()
{
    struct uci_package * pkg = NULL;
    struct uci_element *e;
	unsigned int value = 0;

    ctx = uci_alloc_context(); // ����һ��UCI������.

    if (UCI_OK != uci_load(ctx, UCI_WIRELESS_CONFIG_FILE, &pkg))
        goto cleanup; //�����UCI�ļ�ʧ��,������ĩβ ���� UCI ������.

    /*����UCI��ÿһ����*/
    uci_foreach_element(&pkg->sections, e)
    {
        struct uci_section *s = uci_to_section(e);

	    if(!strcmp(s->type, "wifi-device"))
	    {
	    	value ++;
	    }
    }
    uci_unload(ctx, pkg); // �ͷ� pkg 
cleanup:
    uci_free_context(ctx);
    ctx = NULL;

	return value;
}

