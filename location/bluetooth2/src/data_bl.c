#include "data_bl.h"
#include "log.h"

extern bl_dev_num;
int bluetooth_num;

int set_bl_devid()
{
    int fd = 0;
    int ret = 0;
    char buff[15];

    buff[0] = 0x02;
    buff[1] = 0x3F;
    buff[2] = 0x3F;
    buff[3] = 0x31;
    buff[4] = 0x34;
    buff[5] = 0x30;
    buff[6] = 0x35;
    buff[7] = 0x30;
    buff[8] = 0x31;
    buff[9] = DEV_BL_ID_1;
    buff[10] = DEV_BL_ID_2;
    buff[11] = 0X03;

    fd = BL_FILE();
    if(fd < 0){
        close(fd);
        return -1;
    }
    
    ret = write(fd, buff, sizeof(buff));
    if(ret < 0){
        close(fd);
        return -1;
    }
    
    close(fd);
}

void *get_bl_data(void *p)
{
    int fd;    
    int ret = 0;
    char buff[11];
    buff[0] = 0x02;
    buff[1] = DEV_BL_ID_1;
    buff[2] = DEV_BL_ID_2;
    buff[3] = 0x31;
    buff[4] = 0x36;
    buff[5] = 0x30;
    buff[6] = 0x34;
    buff[7] = 0x30;
    buff[8] = 0x31;
    buff[9] = 0x03;

    fd = BL_FILE();
    if(fd < 0)
        return;
    
    while(1){
        ret = write(fd, buff, sizeof(buff));
        if(ret < 0){
            LOG_LOG("write,get bl_data error!");    
        }
    }

    close(fd);
}

int read_data(int fd, char *bl_data)
{
    struct timeval timeout={10, 0};
    fd_set fds;

    char data[READ_LEN] = {0};
    char buff[READ_LEN] = {0};

    int len = 0;
    char cc[5] = {0};
    int ret = 0;
    int i = 0;
    char data_null[10] = {0};
    char *data_have_or_no = NULL;


    memset(data, 0, sizeof(data));
    memset(buff, 0, sizeof(buff));
    memset(cc, 0, sizeof(cc));

    char super[30] = {0};
    char buff111[20] = {0x02,0x30,0x30,0x31,0x36,0x30,0x34,0x30,0x31,0x03}; 
    ret = write(fd, buff111, 20);
    if (ret < 0)
    {
        LOG_LOG("write to bluetooth error !");
        return -1;
    }
    
    msleep(2);

    /* read date form bluetooth */
    while(1) {
        timeout.tv_sec = 3;
        FD_ZERO(&fds);
        FD_SET(fd,&fds);

        ret = select(fd + 1, &fds, NULL, NULL, &timeout);

        if (ret > 0) 
        {
            if(FD_ISSET(fd, &fds)){
                ret = read(fd, &data[i], 1);
                if(ret <0) {
                    LOG_LOG("read bluetooth data error !");
                    return -1;
                }

                sprintf(&buff[i*2],"%.2x",data[i]);
                sprintf(cc,"%.2x",data[i]);

                if( strcmp(cc,"03") == 0){
                    break;
                }

                i++;
            }
            else
            {
                return 2;    
            }
        }
        else 
        {
            return 1; // timeout
        }
    }

    /*data crc */
    //printf("crc data: %s \n", buff);
    int test_len = 0;
    test_len = strlen(buff);
    ret = data_check(data, i);
    if(CHECK_CORRECT == ret){
        /*check data*/
        memset(data, 0, sizeof(data));
        change_data(buff, data);
        memset(buff, 0, sizeof(buff));
        data_have_or_no = data;
        data_have_or_no = data_have_or_no + 13;

        if(HAVE_DATA == *data_have_or_no)
        {
            /*check the data is right*/    
            data_string(data, HAVE_DATA, buff);
            ret  =     len_check(HAVE_DATA, buff);
            if(LEN_CHECK_ERROR == ret){
                //data_error(buff, LEN_CHECK_ERROR);
            }
            else 
            {
                len = strlen(buff);
                if(len >= 20)
                    ret = parsing_data(buff);
            }
        }
        else if(NO_DATA == *data_have_or_no)
        {
            data_string(data, NO_DATA, buff);
            ret  =     len_check(NO_DATA, buff);
            if(LEN_CHECK_ERROR == ret){
                //data_error(buff, LEN_CHECK_ERROR);
            }
        }
    }else if(CHECK_ERROR == ret){
        /********/;        
        //data_error(buff, CHECK_ERROR);
    }

    return 0;
}


int parsing_data(char *bl_data)
{
    char *p = NULL;
    char buff[READ_LEN] = "0";
    char log[20] = "parsing_data : ";
    
    memset(buff, 0, READ_LEN);
    strcpy(buff, bl_data);
        
    bluetooth_num = bluetooth_num > GET_DEV_NUM(get_real_len(buff)) ? bluetooth_num : GET_DEV_NUM(get_real_len(buff));

    p = buff;
    p = p + 10;
    addlist(p, bluetooth_num);
    return 0;
}

int addlist(char *data, int num)
{
    char buff[READ_LEN] = {0};
    int i = 0, j = 0, ret = 0;
    char id[35] = {0};
    char rssi[5] = {0};
    char lev[5] = {0};
    char *p = NULL;
    char *p1 = NULL;

    memset(buff, 0, READ_LEN);
    strcpy(buff, data);

    //printf("beacon数目 : %d\n", num);
    p = buff;
    for(i = 0; i < num; i++){
        memset(id, 0, sizeof(id));
        memset(lev, 0, sizeof(lev));
        memset(rssi, 0, sizeof(rssi));

        j = 0;
        p1 = id;        
        while(j++ < 32)
            *p1++ = *p++;
        
        j = 0;
        p1 = lev;
        while(j++ < 2){
            *p1++ = *p++;
        }

        j = 0;
        p1 = rssi;
        while(j++ < 2){
            *p1++ = *p++;
        }
    
        ret = new_staruct(id, lev, rssi);
        if(ret < 0){
            /*数据错误*/    
        }else if(ret == 2){
            /*** 信号强度不符合****/    
        }
    }
    return 0;
}

int new_staruct(char *id, char *lev, char *rssi)
{
    char buff[40] = "0";
    int len = 0;
    strcpy(buff, id);

    len = strlen(buff);
    if(len != 32)
        return -1;

    if(id == NULL && lev == NULL && rssi == NULL){
        LOG_LOG("data error !\n");
        return -1;
    }

    if(!((data_16(rssi) * -1) > min_rssi && (data_16(rssi) * -1) < max_rssi)){
        //printf("信号强度：%d\n", (data_16(rssi) * -1));
        //printf("min_rssi: %d      max_rssi: %d\n",min_rssi, max_rssi);
        return 2;
    }
    int ret = 0;

    //printf("add list! \n");
    struct bluetooth_data *bl = new_bl();    
    strcpy(bl->id, id);
    bl->lev = data_16(lev);
    bl->rssi = data_16(rssi) * -1;
    bl->num = 1;

    /*add list*/
    insert_list(bl, 1);

    return 0;
}

int data_16(char *buff)
{
    int num;
    char data[10] = "0";

    memset(data, 0, sizeof(data));
    strcpy(data, buff);
    if(data[0] >= 'a')
        num = data[0] - 87; 
    else
        num = data[0] - 48;
    
    num = num * 16;

    if(data[1] >= 'a')
        num = (data[1] - 87) + num;
    else
        num = (data[1] - 48) + num;
    return num;
}

struct bluetooth_data *new_bl()
{
    return (struct bluetooth_data *)malloc(sizeof(struct bluetooth_data));
}

int len_check(int model_flag, char *data)
{
    char buff[READ_LEN]    = "0";
    int len = 0, real_len = 0;

    memset(buff, 0, READ_LEN);
    strcpy(buff, data);
    len = strlen(buff);
    len = len/2;

    if(NO_DATA == model_flag){
        if(LEN_CHECKA_CORRECT == len){
            return LEN_CHECKA_CORRECT;
        }else{
            return LEN_CHECK_ERROR;
        }
    }else if(HAVE_DATA == model_flag){
        real_len = get_real_len(buff);
        if(len == real_len)
            return LEN_CHECKA_CORRECT;
        else
            return LEN_CHECK_ERROR;
    }
}

int get_real_len(char *data)
{
    int i = 0;
    char buff[READ_LEN] = "0";
    char *p = NULL;
    int m = 0;
    int j = 16;

    memset(buff, 0, READ_LEN);
    strcpy(buff,data);
    p = buff;
    p = p + 8;
    for(i = 0; i < 2; i++) {
        if(i == 1)
            j = 1;
        if(*p == 'a'){
            m = 10 * j  + m;
        }else if(*p == 'b'){
            m = 11 * j + m;
        }else if(*p == 'c'){
            m = 12 * j + m;
        }else if(*p == 'd'){
            m = 13 * j + m;
        }else if(*p == 'e'){
            m = 14 * j + m;
        }else if(*p == 'f'){
            m = 15 * j + m;
        }else{
            m = (*p - 48) * j + m;
        }
        p++;
    }

    return REAL_DATA_LEN(m);
}

void data_string(char *p, int model_flag, char *p1)
{
    char buff[READ_LEN] = "0";
    char *data = NULL, *data1 = NULL;
    char i = 0, len = 0;

    memset(buff, 0, READ_LEN);
    strcpy(buff, p);

    if(HAVE_DATA == model_flag )
        goto HAVE_DATA_MODEL;
    else if(NO_DATA == model_flag )
        goto NO_DATA_MODEL;

HAVE_DATA_MODEL:
    data = strstr(buff,"03");
    data = data + 2;
    *data = '\n';

    data = strtok(buff,"\n");
    strcpy(buff,data);
    buff[strlen(buff) - 9] = '\0';
    data = strstr(buff," ");
    strcpy(buff,data);
    len = strlen(buff);
    data = buff;

    while(*data){
        if(*data == ' ') {
            ;
        }else if (*data == '3' && i == 0){
            i = 1;
        }else if(i == 1) {
            *p1 = *data;
            p1++;
            i = 0;
        }
        data++; 
    }
    return;

NO_DATA_MODEL:
    data = strstr(buff,"03");
    data = data + 2;
    *data = '\n';

    data = strtok(buff,"\n");
    strcpy(buff,data);
    buff[strlen(buff) - 2] = '\0';
    data = strstr(buff," ");
    strcpy(buff,data);
    data1 = buff;
    data1 =data1 + 8;

    while(*data1) {
        if(*data == ' ') {
        }else if(*data == '3' && i == 0){
            i = 1;
        }else {
            *p1 = *data;
            p1++;
            i = 0;
        }
        data++;
        data1++;
    }
    return;
}

void change_data(char *p, char *p1)
{
    int i = 0;
    while(*p) {
        if(i == 2) {
            *p1++ = ' ';
            i=0;
        }
        else {
            *p1++ = *p++;
            i++;
        }
    }
}

int data_check(char *check_buff, int len)
{
    char data[READ_LEN/2] = "0";
    char check[10] = "0";
    char check_data;
    int i = len - 1;
    int n = 0;
    int j = 0;

    memset(data, 0, sizeof(data));
    memset(check, 0, sizeof(check));

    strcpy(data, check_buff);
    check[1] = data[i--] & 0x0f;
    check[0] = (data[i] & 0x0f) << 4;
    check[2] = check[0] + check[1];
    check[2] = check[2] & 0xff;
    check[3] = check[2];

    for(j = 1; j < (len - 1); j++) {
        if(n == 2){
            check[3] ^=check_data;
            n = 0;
            check_data &= 0x00;
        }
        if(n == 0){
            check_data = (data[j] & 0x0f) << 4;
        }
        if(n == 1) {
            check_data = check_data + (data[j] & 0x0f);
        }
        n++;
    }

    if(check[3] == 0x00) {
        return  CHECK_CORRECT;
    }
    else
        return CHECK_ERROR;
}

int BL_FILE()
{
    int fd;    
    char error[512] = {0};
    char buff[512] = {0};
    
    memset(buff, 0, sizeof(buff));
    strcpy(buff, con->interface);

    fd = open(buff, O_RDWR | O_NOCTTY | O_NDELAY);
    if(fd < 0){
        LOG_LOG("open the dev %s error !", buff);
        return -1;
    }

    /*设置串口相关信息*/
    struct termios opt;
    tcgetattr(fd, &opt);
    cfsetispeed(&opt, B115200);
    cfsetospeed(&opt, B115200);
    opt.c_cflag &= ~PARENB;        //清除校验位
    opt.c_iflag &= ~INPCK;
    opt.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    opt.c_oflag &= ~OPOST;
    tcflush(fd, TCIOFLUSH);
    if(tcsetattr(fd, TCSANOW, &opt) != 0 ) {
        LOG_LOG("tcsetattr error!");
        return -1;
    }

    return fd;
}

int timeout(int befortime, int sendtime)
{
    int time = 0;
    int ret = 0;

    time = get_time_date();

//  printf("上一次的时间: %d\t 这一次的时间: %d\t发送间隔：%d\n", befortime, time, sendtime);
    if(time - befortime >= sendtime){
        /*
        printf("timeout !\n");
        printf("------------1------------\n");
        show(1);

        printf("[%d]     %s\n", __LINE__, __func__);
        */
        ret = copy_list();
        if(2 == ret){
            return time;
        }

        delet_list(1);
        /*
        printf("------------2------------\n");
        show(2);
        */
        if(list_null(2) == 0){
            /*send data*/
            pool_add_work(json_data_send, (void*)NULL);
        }
        return time;
    }else
        return befortime;
}

void *json_data_send(void *P)
{
    char *buff = NULL;

    /*add the list*/
    while(1){
        if(list_null(2) == 1)
            break;

        addlist3(buff);
    }

    /*select the send mode*/
    //show(3);
    json_send_modle();
    delet_list(3);
}

void json_send_modle()
{
    int ret = 0, len = 0;
    char buff[READ_LEN] = "0";
    
    ret = json_data(buff, bluetooth_num);
    /*if(ret != bluetooth_num){
    printf("the num of analyze lable: %d\n"
           "the num of detect lable: %d\n",
            ret, bluetooth_num);
    }*/
    
    bluetooth_num = 0;
    len = strlen(buff);
    switch(con->send_model){
        case UDP:
            udp_send_data(buff, len);
            break;
        case TCP:
            //tcp_send_data(buff);
            break;
        case HTTP:
            //http_send_data(buff);
            break;
    }
}

void udp_send_data(char *buff, int len)
{
    //printf("udp send -- %s\n",buff);

    int fd, ret;
    struct sockaddr_in addr;
    fd = udp_client(&addr);
    if (fd < 0) {
        return;
    }

    ret = udp_send(fd, &addr, buff, len);
    if (ret < 0) {
        /* retry */
        ret = udp_send(fd, &addr, buff, len);
        if ( ret  < 0 ) 
        {
            LOG_LOG("udp send error, retry is failed !");
            close(fd);
            return;
        }
    }

    close(fd);
    return;
}

int udp_client(struct sockaddr_in *addr)
{
    int sockfd;
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = PF_INET;
    addr->sin_addr.s_addr = inet_addr(con->ip);
    addr->sin_port = htons(con->prot);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        LOG_LOG("udp sock error!");
        return -1;
    }
    return sockfd;
}

int udp_send(int fd, struct sockaddr_in *addr, char *buff, int len)
{
    int ret;
    
    ret = sendto(fd, (void *)buff, len, 0, (struct sockaddr *)addr, sizeof(struct sockaddr));
    if(ret < 0){
        LOG_LOG("udp send data error !");
    }
    return 0;
}

