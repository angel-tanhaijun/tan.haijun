#pragma once

#include "offline.h"

#define CAPTURE_FAIL -1
#define CAPTURE_OK    1
#define CAPTURE_EOF   2
#define CAPTURE_DATA_SHORT 3

#define SNIFFER_HELPER_GRP_NUM 10    


enum{
    capture_ret_ok = 0,
    capture_ret_error,
	capture_ret_too_many_helper,
};

typedef struct                                                                                                                                                          
{
	unsigned char version:4;
	unsigned char headerlen:4;
	unsigned char tos;
	unsigned short totallen;
	unsigned short ident;
	unsigned int flags:3;
	unsigned int offset:13;
	unsigned char ttl;
	unsigned char proto;
	unsigned short checksum;
	unsigned char sip[4];
	unsigned char dip[4];   
}ip_header_t;       //IP层数据包格式，总长度20字节
typedef struct{
    char position[6];
    char line[10];
    uint32_t subchannel;
    char Freq[6];
    uint64_t jiffies;
}note_vendor_t;
//用于保存扫描 的文件的后缀名类型
typedef struct
{
	char type_name[32];
}type_info_t;


typedef struct
{
	uint64_t packg_ok;
	uint64_t packg_bad;
	uint64_t bytes_ok;
	uint64_t bytes_bad;
	uint64_t option_num_bad;

	void *handle;
	int modify_flag;    //标志目录下的文件，大小事件戳等属性是否变化，0：不变；1：改变
	int quit;
	mini_hash_t *psthashtable;
	char path[255];
	char ip[32];
	int port;
	int interval;
	int capture_moudle;
	uint8_t  line_num[20];  //通信格式：大端
	int type_num;
	type_info_t *file_type;
	int connectfd;
	uint64_t reconnect_count;
	int (*create_oneconnect)(void *ptcpclient);
}tcpclient_t;



typedef void capture_pcap_data(void *this_p, char *data, int data_len);

typedef struct
{
	capture_pcap_data* pcap_data;
}capture_helper_t;


void* capture_init(char *filename, uint8_t decode_switch, void **dst);
int capture_destroy(void *handle);
/*
   -1: fail 1:ok 2:eof
 */
int capture_get_pkt(void *handle, uint8_t **ip, uint16_t *ip_len);
int capture_helper_register(capture_helper_t *capture_helper);
int capture_get_pkt_from_file(void *handle, char *path_name);
void capture_proc_init(void);


