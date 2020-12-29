/**********************************************************************
function for write mac in qca_art 
**********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <linux/netlink.h>
#include <linux/string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <poll.h>
#include <arpa/inet.h>
#include <regex.h>

#define FAILED -1
#define SUCCESS 0

#define OPT_INFO	1
#define OPT_READ	2
#define OPT_WRITE	3
#define OPT_ERASE	4

//#define ART "/dev/mtd5"
#define ART "/tmp/art.bin"

#define OFFSET_LAN 0x0
#define OFFSET_WAN 0x6
#define OFFSET_WLAN0 0x1002
#define OFFSET_WLAN1 0x5006

int check_mac_format(char *pstr)
{
    int i;
    for(i=0;i<12;i++)
    {
        if((pstr[i]>='a' && pstr[i] <='f') || (pstr[i]>='A' && pstr[i] <='F') || (pstr[i]>='0' && pstr[i] <='9'))
            continue;
        else
        {
            printf("Characters shuold be hex\n");
            return FAILED;
        }
    }

    return SUCCESS;
}

int change_hex(char s[],char bits[]) {
    int i,n = 0;
    for(i = 0; s[i]; i += 2) {
        if(s[i] >= 'A' && s[i] <= 'F')
            bits[n] = s[i] - 'A' + 10;
        else if(s[i] >= 'a' && s[i] <= 'f')
            bits[n] = s[i] - 'a' + 10;
        else bits[n] = s[i] - '0';
        
        if(s[i + 1] >= 'A' && s[i + 1] <= 'F')
            bits[n] = (bits[n] << 4) | (s[i + 1] - 'A' + 10);
        else if(s[i + 1] >= 'a' && s[i + 1] <= 'f')
            bits[n] = (bits[n] << 4) | (s[i + 1] - 'a' + 10);
        else bits[n] = (bits[n] << 4) | (s[i + 1] - '0');
        ++n;
        printf("[%02X %02X]", s[i], s[i + 1]);
    }
    printf("\n");
    return n;
}

int write_mtd_value(int offset, unsigned char *value, int len)
{
    int fd;
    
    if((fd = open(ART, (O_RDWR | O_SYNC))) < 0) {
       perror("can not open art mtd\n");
       return FAILED;
    }  
    
    lseek(fd, offset, SEEK_SET);
    
    if (write(fd, value, len) < 0) {
        perror("write error \n");
        close(fd);
        return FAILED;
    }

    close(fd);
    return SUCCESS;
}

/**************************************************************************

***************************************************************************/
static int setLanMac(char *pstr)
{
    unsigned char mac_addr[6] = {0};
    unsigned int  mac_addr_tmp[6];
    unsigned char mac_tmp[20] = {0}, mac_str[20] = {0};
    char          * byte;
    unsigned int  mac_value = 0;
    int i = 0, len = 0;

    strcpy(mac_tmp, pstr);        
    sscanf(mac_tmp, "%02X%02X%02X%02X%02X%02X", &mac_addr_tmp[0],&mac_addr_tmp[1],&mac_addr_tmp[2],&mac_addr_tmp[3],&mac_addr_tmp[4],&mac_addr_tmp[5]);
    printf("base mac %s\n", mac_tmp);
    while(i < 6)
    {
        mac_addr[i] = (unsigned char)mac_addr_tmp[i];
        i++;
    }

    /* base mac */
    mac_value = ( mac_addr[3] << 16 ) | (mac_addr[4] << 8 ) | mac_addr[5] ;  
    byte = ( char * ) &mac_value;

    /* lan mac */
    mac_addr[3] = byte[1];
    mac_addr[4] = byte[2];
    mac_addr[5] = byte[3];
    
    memset(mac_str, 0 , sizeof(mac_str));
    sprintf(mac_str, "%02X%02X%02X%02X%02X%02X", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
    printf("lan mac %s\n", mac_str);                      
    memset(mac_tmp, 0 , sizeof(mac_tmp));
    len = change_hex(mac_str, mac_tmp);
    write_mtd_value(OFFSET_LAN, mac_tmp, len); /* set lan mac */
    write_mtd_value(OFFSET_WAN, mac_tmp, len); /* set wan mac */

 
#if 0
    /* wan mac */
    mac_value +=1;
    byte = ( char * ) &mac_value; 

    mac_addr[3] = byte[1];
    mac_addr[4] = byte[2];
    mac_addr[5] = byte[3];
    memset(mac_str, 0 , sizeof(mac_str));
    sprintf(mac_str, "%02X%02X%02X%02X%02X%02X", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
    printf("wan mac %s\n", mac_str);                      
    memset(mac_tmp, 0 , sizeof(mac_tmp));
    len = change_hex(mac_str, mac_tmp);
    write_mtd_value(OFFSET_WAN, mac_tmp, len); /* set wan mac */
    
    memset(mac_tmp, 0 , sizeof(mac_tmp));
    len = change_hex(mac_addr_tmp, mac_tmp);
  #endif
    
    /* wlan0 mac */
    mac_value +=1;
    byte = ( char * ) &mac_value; 

    mac_addr[3] = byte[1];
    mac_addr[4] = byte[2];
    mac_addr[5] = byte[3];
    memset(mac_str, 0 , sizeof(mac_str));
    sprintf(mac_str, "%02X%02X%02X%02X%02X%02X", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
    printf("wlan0 mac %s\n", mac_str);                      
    memset(mac_tmp, 0 , sizeof(mac_tmp));
    len = change_hex(mac_str, mac_tmp);
    write_mtd_value(OFFSET_WLAN0, mac_tmp, len); /* set wlan0 mac */

#if 0
    /* wlan1 mac */
    mac_value +=1;
    byte = ( char * ) &mac_value; 

    mac_addr[3] = byte[1];
    mac_addr[4] = byte[2];
    mac_addr[5] = byte[3];
    memset(mac_str, 0 , sizeof(mac_str));
    sprintf(mac_str, "%02X%02X%02X%02X%02X%02X", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
    printf("wlan1 mac %s\n", mac_str);                      
    memset(mac_tmp, 0 , sizeof(mac_tmp));
    len = change_hex(mac_str, mac_tmp);
    write_mtd_value(OFFSET_WLAN1, mac_tmp, len); /* set wlan1 mac */
#endif   
    
    return SUCCESS;
}

/**************************************************************************

***************************************************************************/

int main(int argc,char **argv)
{
    char *pargv4, *pargv5; 
    int iRet = 0;
    char setName[32] = {0};
    char szBuf[128] = {0};

    /*protest --mac -w 001122334455 */
    if(!strcmp(argv[1],"--mac"))        
    {
        if(argc == 4 && 0 == strcmp(argv[2],"-w"))
        {
            pargv4 = argv[3];
            if(!pargv4)
            {
                printf("MAC Can't empty\n");
                return FAILED;
            }
            if(check_mac_format(pargv4)<0)
            {
                printf("MAC format should be XXXXXXXXXXAB (hex)\n");
                return FAILED;
            }

            if(strlen(pargv4) != 12)
            {
                printf("MAC len should be 12\n");
                return FAILED;
            }        
            setLanMac(pargv4);            
        }
        else
        {
            printf("error : illegal parament\n");
            return FAILED;        
        }
    }
    else 
    {
        printf("help:\r\n");
        printf("protest --mac -w 001122334455\n");
        return FAILED;
    }
   
    return SUCCESS;
}
