#include "us_list.h"
#include "log.h"
#include "systime.h"

/*初始化
 * */
void Initialization()
{
    INIT_LIST_HEAD(&list1);
    INIT_LIST_HEAD(&list2);
    INIT_LIST_HEAD(&list3);
}

int list_null(int i)
{
    if(i == 1){
        i = list_empty(&list1);
    }else if(i == 2){
        i = list_empty(&list2);
    }else if(i == 3){
        i = list_empty(&list3);
    }

    return i;
}

int list_ret()
{
    int i = list_empty(&list1);
    i = list_empty(&list1);
    if(1 == i){
        i = list_empty(&list2);
        if(1 == i){
            i = list_empty(&list3);
            if(1 == i){
                return 0;
            }else if(0 == i){
                LOG_LOG("init list fail");
                return -1;
            }
        }else if(0 == i){
            LOG_LOG("init list fail");
            return -1;
        }
    }else if(0 == i){
        LOG_LOG("init list fail");
        return -1;
    }
}

void insert_list(BL_DATA *bl, int flag)
{
    if(1 == flag)
        list_add(&(bl->list), &list1);
    if(2 == flag)
        list_add(&(bl->list), &list2);
    if(3 == flag)
        list_add(&(bl->list), &list3);
}

void delet_list(int flag)
{
    struct list_head *pos, *n;
    struct bluetooth_data *tmp;
    int ret = 0;

    if(flag == 1)
        goto DEL_LIST1;
    if(flag == 2)
        goto DEL_LIST2;
    if(flag == 3)
        goto DEL_LIST3;

DEL_LIST1:
    ret = list_null(1);
    if(ret == 1)
        return;
    /*遍历删除*/
    list_for_each_safe(pos, n, &list1) {
        list_del(pos);
        tmp = list_entry(pos, struct bluetooth_data, list);
        free(tmp);
    }
    return;

DEL_LIST2:
    ret = list_null(2);
    if(ret == 1)
        return;
    list_for_each_safe(pos, n, &list2) {
        list_del(pos);
        tmp = list_entry(pos, struct bluetooth_data, list);
        free(tmp);
    }
    return;

DEL_LIST3:
    ret = list_null(3);
    if(ret == 1)
        return;
    list_for_each_safe(pos, n, &list3) {
        list_del(pos);
        tmp = list_entry(pos, struct bluetooth_data, list);
        free(tmp);
    }
    return;
}


int copy_list()
{
    struct bluetooth_data *tmp, *qq;
    struct list_head *post;
    int ret = 0;

    ret = list_null(1); /*判断链表是否为空*/
    if(ret == 1){
        //printf("list 1 empty");
        return 2;
    }

    /*遍历链表*/
    list_for_each(post, &list1) {
        tmp=list_entry(post, struct bluetooth_data, list);
        qq = cp_list_data(tmp);
        insert_list(qq, 2);
    }
}

BL_DATA *cp_list_data(BL_DATA *tmp)
{
    BL_DATA *head;
    head = new_bl();
    
    strcpy(head->id, tmp->id);
    head->rssi = tmp->rssi;
    head->lev = tmp->lev;
    head->num = tmp->num;
    strcpy(head->id, tmp->id);
    return head;
}

void delete_one(char *id)
{
    struct list_head *pos, *n;
    BL_DATA *tmp;

    list_for_each_safe(pos, n, &list2) {
        tmp=list_entry(pos, BL_DATA, list);    
        if(strcmp(tmp->id, id) == 0) {
            list_del(pos);    
            free(tmp);
        }
    }
}

void addlist3()
{    
    struct bluetooth_data *tmp, *new_bl;
    struct list_head *post, *n;
    int flag = 0;

    char id[33] = "0";
    int rssi = 0, num = 0, lev = 0;

    list_for_each_safe(post, n, &list2){
        if(0 == flag){
            tmp = list_entry(post, struct bluetooth_data, list);
            strcpy(id, tmp->id);
            rssi = tmp->rssi;
            lev = tmp->lev;
            num = tmp->num;

            list_del(post);    
            free(tmp);
            flag = 1;
        }else if(1 == flag){
            tmp = list_entry(post, struct bluetooth_data, list);        
            if(strcmp(tmp->id, id) == 0){
                rssi = rssi + tmp->rssi;
                lev = tmp->lev;
                num = num + tmp->num;

                list_del(post);    
                free(tmp);
            }
        }
    }

    new_bl = (BL_DATA *)malloc(sizeof(BL_DATA));
    rssi = rssi/num;
    strcpy(new_bl->id, id);
    new_bl->rssi = rssi;
    new_bl->lev = lev;
    new_bl->num = 1;
    insert_list(new_bl, 3);
}

int json_data(char *buff, int num)
{
    cJSON *root, *img[100],*arry;
    FILE *file;
    char data[READ_LEN] = "0";
    char ap_mac[30] = "0";
    int now_time = 0, i = 0;
    struct bluetooth_data *tmp;
    struct list_head *post;
    char rssi[10] = "0";
    char *out = NULL, *p = NULL;

    memset(ap_mac, 0, sizeof(ap_mac));
    memset(data, 0, sizeof(data));

    file = popen(SET_DEV_ID, "r");
    if(file){
        fgets(ap_mac, sizeof(ap_mac), file);
    }
    pclose(file);

    now_time = get_time_date();    

    root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "stamp",now_time);
    cJSON_AddStringToObject(root, "devID",ap_mac);

    arry = cJSON_CreateArray();
    cJSON_AddItemToObject(root,"beacon", arry);

    list_for_each(post, &list3){
        tmp = list_entry(post, struct bluetooth_data, list);

        memset(rssi, 0, sizeof(rssi));
        sprintf(rssi, "%d", tmp->rssi); 
        img[i] = cJSON_CreateObject();
        cJSON_AddItemToObject(arry,"beacon", img[i]);
        cJSON_AddStringToObject(img[i], "uuid", tmp->id);
        cJSON_AddStringToObject(img[i], "rssi", rssi);
        cJSON_AddNumberToObject(img[i], "lev", tmp->lev);
        i++;
    }

#if 1
        out = cJSON_PrintUnformatted(root);
        char time_date[64] = {0};
        get_now_time_date(time_date);
        snprintf(data, sizeof(data), "[%s] %s", time_date, out);
        send_date_log(data);
        free(out);
#endif
//    if(i == num){
        out = cJSON_Print(root);
        memset(data, 0, sizeof(data));
        sprintf(data, "%s", out);
        p = data;
        while(*p)
            *buff++ = *p++;
        free(out);
//    }
    cJSON_Delete(root);
    return i;
}

void show(int i)
{
    struct bluetooth_data *tmp;
    struct list_head *post;
    int ret = 0;

    if(i == 1){
        ret = list_null(1); 
        if(ret == 1){
            printf("list 1 empty\n");
            return;
        }

        list_for_each(post, &list1) {
            tmp = list_entry(post, struct bluetooth_data, list);
            printf("id: %s\trssi: %d\tlev: %d\n", tmp->id, tmp->rssi, tmp->lev);
        }
    }
    if(i == 2){
        ret = list_null(2);
        if(ret == 1){
            printf("list 2empty\n");
            return;
        }

        list_for_each(post, &list2) {
            tmp = list_entry(post, struct bluetooth_data, list);
            printf("id: %s\trssi: %d\tlev: %d\n", tmp->id, tmp->rssi, tmp->lev);
        }
    }
    if(i == 3){
        ret = list_null(3); 
        if(ret == 1){
            printf("list 3 empty\n");
            return;
        }

        list_for_each(post, &list3) {
            tmp = list_entry(post, struct bluetooth_data, list);
            printf("id: %s\trssi: %d\tlev: %d\n", tmp->id, tmp->rssi, tmp->lev);
        }
    }
}
