#include "init.h"

int bl_dev_num = 0;

int init()
{
    int ret;    
    char buff[50] = {0};
    char data[10] = {0};
    FILE *file;

    Initialization();
    list_ret();

    memset(buff, 0, sizeof(buff));
    ret = bl_config_uci_get(buff, "disabled");
    if(ret < 0){
        LOG_LOG("get disabled_value error!");
        return -1;    
    }
    con->disabled = atoi(buff);

    memset(buff, 0, sizeof(buff));
    ret = bl_config_uci_get(buff, "port");
    if(ret < 0){
        LOG_LOG("get prot_value error!");
        return -1;    
    }
    con->prot = atoi(buff);

    memset(buff, 0, sizeof(buff));
    ret = bl_config_uci_get(buff, "ip");
    if(ret < 0){
        LOG_LOG("get ip value error!");
        return -1;    
    }
    strcpy(con->ip, buff);

    memset(buff, 0, sizeof(buff));
    ret = bl_config_uci_get(buff, "send_model");
    if(ret < 0){
        LOG_LOG("get send_model_value error!");
        return -1;    
    }
    con->send_model = atoi(buff);

    memset(buff, 0, sizeof(buff));
    ret = bl_config_uci_get(buff, "curl_data");
    if(ret < 0){
        LOG_LOG("get curl_value error!");
        return -1;    
    }
    strcpy(con->curl_data, buff);

    memset(buff, 0, sizeof(buff));
    ret = bl_config_uci_get(buff, "collet_model");
    if(ret < 0){
        LOG_LOG("get collet_model_value error!");
        return -1;    
    }
    con->collet_mod = atoi(buff);

    memset(buff, 0, sizeof(buff));
    ret = bl_config_uci_get(buff, "collet_mac");
    if(ret < 0){
        LOG_LOG("get collet_mac_value error!");
        return -1;    
    }
    strcpy(con->collet_mac, buff);

    memset(buff, 0, sizeof(buff));
    ret = bl_config_uci_get(buff, "show_model");
    if(ret < 0){
        LOG_LOG("get show_model_value error!");
        return -1;    
    }
    con->show_mode = atoi(buff);

    memset(buff, 0, sizeof(buff));
    ret = bl_config_uci_get(buff, "time");
    if(ret < 0){
        LOG_LOG("get time error!");
        return -1;    
    }
    con->send_time = atoi(buff);

    memset(buff, 0, sizeof(buff));
    ret = bl_config_uci_get(buff, "USB_interface");
    if(ret < 0){
        LOG_LOG("get interface error!");
        return -1;    
    }
    strcpy(con->interface, buff);

    memset(buff, 0, sizeof(buff));
    ret = bl_config_uci_get(buff, "getdata_time");
    if(ret < 0){
        LOG_LOG("get getdata_time error!");
        return -1;    
    }
    con->getdata_time = atoi(buff);

    memset(buff, 0, sizeof(buff));
    ret = bl_config_uci_get(buff, "min_rssi");
    if(ret < 0){
        LOG_LOG("get min_ssid error!"); 
        return -1;    
    }
    con->min_rssi = atoi(buff);


    memset(buff, 0, sizeof(buff));
    ret = bl_config_uci_get(buff, "max_rssi");
    if(ret < 0){
        LOG_LOG("get max_ssid error!");
        return -1;    
    }

    con->max_rssi = atoi(buff);
    if(con->show_mode == Y_ECHO)
        PINT =     Y_ECHO;

    getdata_time = con->getdata_time;
    min_rssi = con->min_rssi;
    max_rssi = con->max_rssi;

    system(PINT_CONFIG_INIT);
    echo_config("%s %s", con->ip, "ip");
    echo_config("%d %s", con->prot, "prot");
    echo_config("%d %s", con->send_model, "send_modle");
    echo_config("%s %s", con->curl_data, "curl_data");
    echo_config("%d %s", con->collet_mod, "collet_mod");
    echo_config("%s %s", con->collet_mac, "collet_mac");
    echo_config("%d %s", con->send_time, "time");
    echo_config("%d %s", con->show_mode, "show_modle");
    echo_config("%d %s", con->disabled, "disabled");
    echo_config("%s %s", con->interface, "USB_interface");
    echo_config("%d %s", con->getdata_time, "getdata_time");
    echo_config("%d %s", con->min_rssi, "min_rssi");
    echo_config("%d %s", con->max_rssi, "max_rssi");
    return 0;
}

void echo_config(char *fmt, ...)
{
    char *p = NULL;
    char buff[2][60];
    char data[200];
    int num = 0;
    int i = 0;

    
    memset(buff, 0, sizeof(buff));
    memset(data, 0, sizeof(data));
    
    va_list ap;    
    va_start(ap, fmt);
    while(*fmt) {
        switch(*fmt++)    {
            case 's':
                p = va_arg(ap, char *);
                strcpy(buff[i], p);
                i++;
                break;
            case 'd':
                num = va_arg(ap, int);
                break;
        }
    }

    if(i > 1){
        sprintf(data, PINT_CONFIG_C, buff[1], buff[0]);
    }else{
        sprintf(data, PINT_CONFIG_I, buff[0], num);
    }

    LOG_LOG("%s", data);
    system(data);
}

int bl_config_uci_get(char *data, char *buff)
{
    struct uci_element *e;
    struct uci_context * ctx = uci_alloc_context(); //申请上下文
    struct uci_package *pkg = NULL;
    char *value_option = NULL;
    char option[20] = {0};

    strcpy(option, buff);
    if (UCI_OK != uci_load(ctx, PAKEGE, &pkg)){
        uci_free_context(ctx); //释放
        return -1;
    }

    struct uci_ptr prt = {
        .package = PAKEGE,
        .option = option,
    };

    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (NULL != (value_option = uci_lookup_option_string(ctx, s, option))) {
//            printf("%s : %s\n", option, value_option);
        }
    }

    while(*value_option){
        *data++ = *value_option++;
    }

    uci_commit(ctx, &prt.p, false); //提交保存更改
    uci_unload(ctx,prt.p); //卸载包
    uci_free_context(ctx); //释放
}

