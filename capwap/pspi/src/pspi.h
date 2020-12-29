#ifndef __PSPI_H
#define __PSPI_h

typedef unsigned char uchar;
typedef unsigned int uint;

#define ERMSG_LEN	512

/*block dev*/
#define mtdev "/dev/mtdblock6"
/*char dev*/
//#define mtdev "/dev/mtd6"

#define START 0xfe0000
#define LEN	0x10000

#define MAC_LEN		48
#define	TYPE_LEN	48
#define SN_LEN		48
#define SVER_LEN	48
#define HVER_LEN	48
#define LKEY_LEN	48

#define SVER	"AIROCOV_V2.3.0"
#define HVER	"DTT_QCA9558ED2"
#define PVER	"AR6260 AP(D)"
#define SNUM	"V334R126A16000000001"
#define LKEY	"abcdabcdabcdabcdabcdabcdabcdabcd"


struct cfg_info {
	uchar mac[MAC_LEN];
	uchar type[TYPE_LEN];
	uchar snum[SN_LEN];
	uchar sver[SVER_LEN];
	uchar hver[HVER_LEN];
	uchar lkey[LKEY_LEN];
	uchar pack[16];
};

#endif
