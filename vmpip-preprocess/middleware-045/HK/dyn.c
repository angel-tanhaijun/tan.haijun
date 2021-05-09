/*************************************************************************
	> File Name: dyn.c
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月20日 星期六 18时26分04秒
 ************************************************************************/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <dirent.h>
#include <assert.h>
#include "utils.h"
#include "dyn.h"
#include "mddw.h"
#include "tcpserver.h"
#include "rbque.h"
#include "udpserver.h"

#define     ONLINE_MAGIC_IP     0x3c3f03f0  //ip数据
#define     ONLINE_MAGIC_M      0xf3c303f0  //mi数据
#define     ONLINE_MAGIC_Y      0xc3f3c3f3  //元数据

#define     DYN_MAX_USER_NUM        4

#define datatype_ip             0x01
#define datatype_eth            0x08
#define datatype_not_ip         0x20
#define pcapName "/home/tan.haijun/workbench/nca/pcap/sip/sip/sdp.pcap"
static char *libinfo __attribute__((unused))  = "\n@VERSION@:hk, 1.0.0, "VERSION"\n" ;
#pragma pack (1)
typedef struct{
	uint32_t magic;
	uint8_t  timeway;
	uint8_t  stanum;
	uint8_t  spotbeam;
	uint8_t  channel;
	uint16_t lenflag;
	uint8_t  timeflag[10];
}time_log_t;

typedef struct{
	time_log_t timelog;
	uint16_t   id;
	uint8_t    network[3];
}hk_header_t;


#pragma pack (0)
char y_data_1[100] = {0xC3, 0xF3, 0xC3 , 0xF3 , 0x20 , 0x0B , 0x20 , 0x0B , 0x20 , 0x00 , 0x20 , 0x00 , 0x20 , 0x00 , 0x20 , 0x13 , 0x01 , 0x01 , 0x16 , 0x23 , 0x16 , 0x00 , 0x0C , 0x75 , 0x4D , 0x20 , 0x01 , 0x20 , 0x54 , 0xB9 , 0x20 , 0x01 , 0x00 , 0x00 , 0x00 , 0x20 , 0xD4 , 0x00 , 0x00 , 0x00 , 0x20 , 0xAE , 0x02 , 0x12 , 0x92 , 0x12 , 0x92 , 0x12 , 0x92 , 0x3A , 0x12 , 0xAE , 0x02 , 0xAE , 0x03 , 0x59 , 0x13 , 0x5B , 0xA2 , 0x12 , 0x93 , 0x5B , 0xA3 , 0x3A , 0x12 , 0x3A , 0x12 , 0x3A , 0x12 , 0x3A , 0x12 , 0x3A , 0x12, 0x3B};

char y_data_2[100] = {0xC3, 0xF3, 0xC3 , 0xF3 , 0x20 , 0x0B , 0x20 , 0x0A , 0x20 , 0x00 , 0x20 , 0x00 , 0x20 , 0x00 , 0x20 , 0x13 , 0x01 , 0x01 , 0x16 , 0x23 , 0x16 , 0x00 , 0x0C , 0x75 , 0x4D , 0x20 , 0x02 , 0x20 , 0xF9 , 0xBE , 0x20 , 0x7F , 0x19 , 0x20 , 0x70 , 0x60 , 0x7E , 0x60 , 0x7F , 0x60 , 0x3B };

char y_data_3[100] = {0xC3, 0xF3 , 0xC3 , 0xF3 , 0x20 , 0x0B , 0x20 , 0x0D , 0x20 , 0x00 , 0x20 , 0x00 , 0x20 , 0x00 , 0x20 , 0x13 , 0x01 , 0x01 , 0x16 , 0x25 , 0x30 , 0x00 , 0x04 , 0xE6 , 0x4F , 0x20 , 0x03 , 0x20 , 0xE0 , 0xBD , 0x20 , 0x01 , 0x00 , 0x00 , 0x00 , 0x20 , 0x4A , 0xC1 , 0xC5 , 0x01 , 0x20 , 0xF0 , 0xB3 , 0x1A , 0x00 , 0x20 , 0x01 , 0x00 , 0x00 , 0x00 , 0x20 , 0x34 , 0x3B};


char y_data_4[100] = {0xC3, 0xF3 , 0xC3 , 0xF3 , 0x20 , 0x08 , 0x20 , 0x0A , 0x20 , 0x00 , 0x20 , 0x00 , 0x20 , 0x00 , 0x20 , 0x13 , 0x01 , 0x01 , 0x16 , 0x25 , 0x30 , 0x00 , 0x04 , 0xE6 , 0x4F , 0x20 , 0x01 , 0x20 , 0x17 , 0xC3 , 0x20 , 0xD1 , 0xDC , 0x00 , 0x14 , 0x20 , 0x01 , 0x3B};

//用户提供的接口声明
typedef int hk_proc_helper(unsigned char *BBdatabuf, int len, unsigned char *databuf, int *datalen, unsigned char *cBuf, int *cLen, int thr_id);
/*
 * BBdatabuf: udp接收到的数据
 * len： udp接收到的数据长度
 * databuf ： 返回的ip数据或者mi数据
 * datalen：返回的ip数据或者mi数据长度
 * cBuf：元消息数据
 * cLen：元消息数据长度
 * */

static hk_proc_helper *hk_proc = NULL;

void *udpserver_rbq_handle = NULL;
static mddw_gsc_info_t m_mddw_gsc;
static online_helper_t g_online_helper[DYN_MAX_USER_NUM];
static int g_online_helper_num = 0;

int online_register(online_helper_t *online_helper)
{
	if(online_helper == NULL)
		return -1;
	if(g_online_helper_num > DYN_MAX_USER_NUM - 1) 
		return -1;
	memcpy(&(g_online_helper[g_online_helper_num]), online_helper, sizeof(online_helper_t));

	g_online_helper_num++;
	return 0;
}

typedef struct{
	int use_id;
	int thr_id;
}online_rbq_init_t;

static int do_onlinelb_helper(online_fb_t *fb, uint8_t *ip, uint32_t ip_len, uint32_t channel, int thr_id)
{
	return g_online_helper[0].onlineip_entry(NULL, fb, ip, ip_len, datatype_ip, channel, thr_id, NULL);
}
static void online_data_write(char *filename, char *data, uint32_t dataLen, int thr_id)
{
	char path[215] = {0};
	snprintf(path, sizeof(path), "%s_%d", filename, thr_id);
	FILE *fp = fopen(path, "ab+");
	if(fp != NULL)
	{
		fwrite(data, dataLen, 1, fp);
		fclose(fp);
	}
	return;
}
#if 1

static online_fb_t gonline_fb[64];
static void online_data_ip_put(uint8_t *data, uint32_t len, int thr_id)
{
	//printf("online_data_ip_put begin\n");
	//online_data_write("./DealGS_Dat/ip.dat", data, len, thr_id);
	hk_header_t hk_header;
	if(len <= sizeof(hk_header_t))
		return;
	memcpy(&hk_header, data, sizeof(hk_header_t));
	if(ntohl(hk_header.timelog.magic) != ONLINE_MAGIC_IP)
	{
		printf("ip header magic is not %x\n", ONLINE_MAGIC_IP);
		return;
	}
	//memset(&gonline_fb[thr_id], 0, sizeof(online_fb_t));
	snprintf(gonline_fb[thr_id].sessId, sizeof(gonline_fb[thr_id].sessId), "%s%d", "ott", hk_header.timelog.channel);
	gonline_fb[thr_id].sessIdLen = strlen(gonline_fb[thr_id].sessId);
	gonline_fb[thr_id].capTimeStamp = jiffies;
	gonline_fb[thr_id].analysisTimeStamp = jiffies;
	gonline_fb[thr_id].IPOffset = 0;

	uint32_t total_len = 0, copy_len = 0; 
	total_len += 8 + sizeof(hk_header.timelog);
	total_len += 8 + sizeof(hk_header.id);
	total_len += 8 + sizeof(hk_header.network);
	uint32_t body_type = 0x100050af;
	body_type = ntohl(body_type);
	uint32_t body_len = sizeof(hk_header.timelog);
	body_len = ntohl(body_len);
	memcpy(gonline_fb[thr_id].userInfo + copy_len, &body_type, sizeof(uint32_t));
	copy_len += sizeof(uint32_t);
	memcpy(gonline_fb[thr_id].userInfo + copy_len, &body_len, sizeof(uint32_t));
	copy_len += sizeof(uint32_t);
	memcpy(gonline_fb[thr_id].userInfo + copy_len, &hk_header.timelog, sizeof(time_log_t));
	copy_len += sizeof(time_log_t);

	body_type = 0x100050b0;
	body_type = ntohl(body_type);
	body_len = sizeof(hk_header.id);
	body_len = ntohl(body_len);
	memcpy(gonline_fb[thr_id].userInfo + copy_len, &body_type, sizeof(uint32_t));
	copy_len += sizeof(uint32_t);
	memcpy(gonline_fb[thr_id].userInfo + copy_len, &body_len, sizeof(uint32_t));
	copy_len += sizeof(uint32_t);
	memcpy(gonline_fb[thr_id].userInfo + copy_len, &hk_header.id, sizeof(hk_header.id));
	copy_len += sizeof(hk_header.id);

	body_type = 0x100050b1;
	body_type = ntohl(body_type);
	body_len = sizeof(hk_header.network);
	body_len = ntohl(body_len);
	memcpy(gonline_fb[thr_id].userInfo + copy_len, &body_type, sizeof(uint32_t));
	copy_len += sizeof(uint32_t);
	memcpy(gonline_fb[thr_id].userInfo + copy_len, &body_len, sizeof(uint32_t));
	copy_len += sizeof(uint32_t);
	memcpy(gonline_fb[thr_id].userInfo + copy_len, hk_header.network, sizeof(hk_header.network));
	copy_len += sizeof(hk_header.network);

	gonline_fb[thr_id].userInfoLen = total_len;
	gonline_fb[thr_id].userInfoType = 0x100050b2;

	do_onlinelb_helper(&gonline_fb[thr_id], data + sizeof(hk_header_t), len - sizeof(hk_header_t), hk_header.timelog.channel, thr_id);
	return;
}

#else if 
static void online_data_ip_put(uint8_t *data, uint32_t len, int thr_id)
{
	//printf("online_data_ip_put begin\n");
	//online_data_write("./DealGS_Dat/ip.dat", data, len, thr_id);
	hk_header_t hk_header;
	if(len <= sizeof(hk_header_t))
		return;
	memcpy(&hk_header, data, sizeof(hk_header_t));
	if(ntohl(hk_header.timelog.magic) != ONLINE_MAGIC_IP)
	{
		printf("ip header magic is not %x\n", ONLINE_MAGIC_IP);
		return;
	}
	online_fb_t online_fb;
	memset(&online_fb, 0, sizeof(online_fb));
	snprintf(online_fb.sessId, sizeof(online_fb.sessId), "%s%d", "ott", hk_header.timelog.channel);
	online_fb.sessIdLen = strlen(online_fb.sessId);
	online_fb.capTimeStamp = jiffies;
	online_fb.analysisTimeStamp = jiffies;
	online_fb.IPOffset = 0;

	uint32_t total_len = 0, copy_len = 0; 
	total_len += 8 + sizeof(hk_header.timelog);
	total_len += 8 + sizeof(hk_header.id);
	total_len += 8 + sizeof(hk_header.network);
	online_fb.userInfo = malloc(total_len);
	uint32_t body_type = 0x100050af;
	body_type = ntohl(body_type);
	uint32_t body_len = sizeof(hk_header.timelog);
	body_len = ntohl(body_len);
	memcpy(online_fb.userInfo + copy_len, &body_type, sizeof(uint32_t));
	copy_len += sizeof(uint32_t);
	memcpy(online_fb.userInfo + copy_len, &body_len, sizeof(uint32_t));
	copy_len += sizeof(uint32_t);
	memcpy(online_fb.userInfo + copy_len, &hk_header.timelog, sizeof(time_log_t));
	copy_len += sizeof(time_log_t);

	body_type = 0x100050b0;
	body_type = ntohl(body_type);
	body_len = sizeof(hk_header.id);
	body_len = ntohl(body_len);
	memcpy(online_fb.userInfo + copy_len, &body_type, sizeof(uint32_t));
	copy_len += sizeof(uint32_t);
	memcpy(online_fb.userInfo + copy_len, &body_len, sizeof(uint32_t));
	copy_len += sizeof(uint32_t);
	memcpy(online_fb.userInfo + copy_len, &hk_header.id, sizeof(hk_header.id));
	copy_len += sizeof(hk_header.id);

	body_type = 0x100050b1;
	body_type = ntohl(body_type);
	body_len = sizeof(hk_header.network);
	body_len = ntohl(body_len);
	memcpy(online_fb.userInfo + copy_len, &body_type, sizeof(uint32_t));
	copy_len += sizeof(uint32_t);
	memcpy(online_fb.userInfo + copy_len, &body_len, sizeof(uint32_t));
	copy_len += sizeof(uint32_t);
	memcpy(online_fb.userInfo + copy_len, hk_header.network, sizeof(hk_header.network));
	copy_len += sizeof(hk_header.network);

	online_fb.userInfoLen = total_len;
	online_fb.userInfoType = 0x100050b2;

	//printf("do onlinelb helper\n");
	do_onlinelb_helper(&online_fb, data + sizeof(hk_header_t), len - sizeof(hk_header_t), hk_header.timelog.channel, thr_id);
	free(online_fb.userInfo);
	//printf("online_data_ip_put end\n");
	return;
}
#endif

static int do_onlineld_helper(online_fd_t *fd, uint8_t *data, uint32_t datalen, uint16_t pro_type, uint32_t channel, int thr_id)
{

	return g_online_helper[0].onlinefh_entry(NULL, fd, data, datalen, pro_type, channel, thr_id, NULL);
}

static int do_onlinepv_helper(online_pv_t *pv, uint8_t *data, uint32_t datalen, uint32_t channel, int thr_id)
{

	return g_online_helper[0].onlinepv_entry(NULL, pv, data, datalen, channel, thr_id, NULL);
}

static void online_data_y_put(uint8_t *data, uint32_t len, int thr_id)
{
	//online_data_write("./DealGS_Dat/yuan.dat", data, len, thr_id);
	uint32_t magic = 0;
	if(len <= sizeof(uint32_t))
		return;
	//memcpy(&magic, data, sizeof(uint32_t));
	magic = *((uint32_t *)data);
	if(ntohl(magic) != ONLINE_MAGIC_Y)
	{
		printf("y header magic is not %x\n", ONLINE_MAGIC_Y);
		return;
	}
	online_pv_t pv;
	memset(&pv, 0, sizeof(pv));
	uint32_t total_len = 0;
	//char *buf = malloc(len + sizeof(uint32_t) * 2);
	char buf[4096];
	uint32_t t = 0x1a1b1c1d;
	t = ntohl(t);
	uint32_t l = len;
	l = ntohl(l);
	//memcpy(buf + total_len, &t, sizeof(uint32_t));
	*(uint32_t *)(buf + total_len) = t;
	total_len += sizeof(uint32_t);
	//memcpy(buf + total_len, &l, sizeof(uint32_t));
	*(uint32_t *)(buf + total_len) = l;
	total_len += sizeof(uint32_t);
	memcpy(buf + total_len, data, len);
	total_len += len;
	assert(total_len<4096);
	do_onlinepv_helper(&pv, buf, total_len, 0, thr_id);
	//free(buf);
	return;
}

static void online_data_m_put(uint8_t *data, uint32_t len, int thr_id)
{
	//online_data_write("./DealGS_Dat/mi.dat", data, len, thr_id);
	hk_header_t hk_header;
	if(len <= sizeof(hk_header_t))
		return;
	memcpy(&hk_header, data, sizeof(hk_header_t));
	if(ntohl(hk_header.timelog.magic) != ONLINE_MAGIC_M)
	{
		printf("mi header magic[%x] is not %x\n", ntohl(hk_header.timelog.magic), ONLINE_MAGIC_M);
		return;
	}
	online_pv_t pv;
	memset(&pv, 0, sizeof(pv));
	uint32_t total_len = 0;
	char buf[4096];
	uint32_t t = 0x2a2b2c2d;
	t = ntohl(t);
	uint32_t l = len;
	l = ntohl(l);
	//memcpy(buf + total_len, &t, sizeof(uint32_t));
	*(uint32_t *)(buf + total_len) = t;
	total_len += sizeof(uint32_t);
	//memcpy(buf + total_len, &l, sizeof(uint32_t));
	*(uint32_t *)(buf + total_len) = l;
	total_len += sizeof(uint32_t);
	memcpy(buf + total_len, data, len);
	total_len += len;
	assert(total_len<4096);
	do_onlinepv_helper(&pv, buf, total_len, 0, thr_id);;
	//free(buf);
	return;
}

static uint64_t online_state_time[64];
static uint32_t check_time = 10 * 1000;
static void online_data_state_put(int thr_id)
{
	if((jiffies - online_state_time[thr_id]) < check_time)
		return;
	online_pv_t pv;
	memset(&pv, 0, sizeof(pv));
	uint32_t flag = 1;
	uint32_t total_len = 0;
	char buf[12];
	uint32_t t = 0x3a3b3c3d;
	t = ntohl(t);
	uint32_t l = sizeof(uint32_t);
	l = ntohl(l);
	//memcpy(buf + total_len, &t, sizeof(uint32_t));
	*(uint32_t *)(buf + total_len) = t;
	total_len += sizeof(uint32_t);
	//memcpy(buf + total_len, &l, sizeof(uint32_t));
	*(uint32_t *)(buf + total_len) = l;
	total_len += sizeof(uint32_t);
	//memcpy(buf + total_len, &flag, sizeof(uint32_t));
	*(uint32_t *)(buf + total_len) = flag;
	total_len += sizeof(uint32_t);
	do_onlinepv_helper(&pv, buf, total_len, 0, thr_id);
	//free(buf);
	online_state_time[thr_id] = jiffies;
	return;
}

#define ONLINE_MAGIC_BQ_BASE_FR       0x3C3F03F0  //接收到的统先数据的头部校验
#define ONLINE_MAGIC_BQ_YUAN          0xC3F3C3F3  //接收到的统先数据的头部校验

static int online_data_check(uint8_t *data, uint32_t datalen, int thr_id)
{
	uint8_t *move_data = data;
	uint32_t move_len = 0; 
	uint32_t magic_len = 0;
	uint32_t  magic = NULL; 
	uint16_t len = 0;
	while(move_len < datalen)
	{
		if((datalen - move_len) <= (sizeof(uint32_t) + sizeof(uint16_t)))
			return -1;
		//memcpy(&len, data + move_len, sizeof(uint16_t));
		len = *((uint16_t *)(data + move_len));
		move_len += sizeof(uint16_t);
		//memcpy(&magic, data + move_len, sizeof(uint32_t));
		magic = *((uint32_t *)(data + move_len));
		magic = ntohl(magic);
		//printf("magic %x len %d\n begin put data", magic, len);

		if(magic == ONLINE_MAGIC_IP)
			online_data_ip_put(data + move_len, len, thr_id);
		else if(magic == ONLINE_MAGIC_M)
			online_data_m_put(data + move_len, len, thr_id);
		else if(magic == ONLINE_MAGIC_Y)
			online_data_y_put(data + move_len, len, thr_id);
		else
		{
			//online_data_write("./DealGS_Dat/BQ_ERR.dat", data, datalen, thr_id);
			printf("the online_data_check magic[0x%x] is err\n", magic);
			return -1;
		}
		//printf("magic %x begin put data ok", magic);
		move_len += len;
	}
	return 0;
}

static void *online_data_proc(uint8_t *ele, char *data, uint32_t dataLen, int thr_id)
{
	uint8_t databuf[1024*12] = {0};
	uint32_t datalen = 0;
	uint32_t magic = 0;
	uint8_t cbuf[1024*12] = {0};
	uint32_t clen = 0;
	int ret = 0;
	//online_data_write("./BQ.dat", data, dataLen, thr_id);
	hk_proc(data, dataLen, databuf, &datalen, cbuf, &clen, thr_id);
	//online_data_write("./BQ_cbuf.dat", cbuf, clen, thr_id); //落包函数用于调试数据
	if(datalen > 0 || clen > 0)
	{
		online_data_state_put(thr_id); 
	}
	if(datalen > sizeof(uint32_t))
		ret = online_data_check(databuf, datalen, thr_id);
	if(clen > sizeof(uint32_t))
		ret = online_data_check(cbuf, clen, thr_id);
	
	return NULL;
}
static void online_data_get(void *ele, uint8_t *data, uint32_t len, int thr_id)
{
	uint8_t *move_data = data;
	uint32_t move_len = 0;
	uint32_t magic_len = 0; 
	uint8_t *magic = NULL;

	while(move_len < len)
	{
		if(ntohl(*(uint32_t *)(move_data + move_len)) == ONLINE_MAGIC_BQ_BASE_FR || ntohl(*(uint32_t *)(move_data + move_len)) == ONLINE_MAGIC_BQ_YUAN)
		{
			if(magic_len > sizeof(uint32_t))
				online_data_proc(ele, magic, magic_len, thr_id);		
			magic = move_data + move_len;
			magic_len = 0;
		}
		magic_len++;
		move_len++;
		if(move_len == len)
		{
			online_data_proc(ele, magic, magic_len, thr_id);
		}
	}

	return;
}

static int online_data_do_p2(char *data, int len, int thr_id)
{
	uint32_t magic = 0;
	memcpy(&magic, data, sizeof(uint32_t));
	magic = ntohl(magic);
	if(magic == ONLINE_MAGIC_IP)
		online_data_ip_put(data, len, thr_id);
	else if(magic == ONLINE_MAGIC_M)
		online_data_m_put(data, len, thr_id);
	else if(magic == ONLINE_MAGIC_Y)
		online_data_y_put(data, len, thr_id);
	return 0;
}

static int online_data_do(uint8_t *data, uint32_t len, int thr_id)
{
	uint8_t *move_data = data;
	uint32_t move_len = 0;
	uint32_t magic_len = 0; 
	uint8_t *magic = NULL;
	uint32_t magicp = 0;

	while(move_len < len)
	{
		memcpy(&magicp, move_data + move_len, sizeof(uint32_t));
		if(ntohl(magicp) == ONLINE_MAGIC_IP || ntohl(magicp) == ONLINE_MAGIC_M || ntohl(magicp) == ONLINE_MAGIC_Y)
		{
			if(magic_len > sizeof(uint32_t))
				online_data_do_p2(magic, magic_len, thr_id);		
			magic = move_data + move_len;
			magic_len = 0;
		}
		magic_len++;
		move_len++;
		if(move_len == len)
		{
			online_data_do_p2(magic, magic_len, thr_id);
		}
	}

}

static uint8_t *readbuf[64];
static uint32_t maxreadbuflen = 10*1024*1024 + 65535;
static uint32_t readbuflen = 10*1024*1024;

static int online_data_read_proc(char *path, int thr_id)
{
	char buf[65535] = {0};
	uint32_t magic = 0;
	char read[1] = {0};
	uint32_t len = 0;
	char ebuff[1024];
	uint32_t flag = 0;
	int ret_len = 0;
	FILE *fp = fopen(path, "r+");
	if(fp != NULL)
	{
#if 0
		while((ret_len = fread(&magic, 1, 4, fp)) >  0)
		{
			if(ntohl(magic) == ONLINE_MAGIC_IP || ntohl(magic) == ONLINE_MAGIC_M || ntohl(magic) == ONLINE_MAGIC_Y)	
			{
				if(len > 0)
				{
					online_data_do_p2(buf, len, thr_id);			
					memset(buf, 0, sizeof(buf));
					len = 0;
				}
				memcpy(buf + len, &magic, sizeof(uint32_t));
				len += sizeof(uint32_t);
			}
			else
			{
				if(len > 0)
				{
					memcpy(buf + len, &magic, sizeof(uint8_t));
					len += sizeof(uint8_t);
				}
				if(ret_len == 4)
					fseek(fp, -3L, SEEK_CUR);
			}
		}
#else 
		while((ret_len = fread(readbuf[thr_id], 1, readbuflen, fp)) > 0)
		{
			if(ret_len == readbuflen)
			{
				len = readbuflen;
				while((ret_len = fread(&magic, 1, sizeof(magic), fp)) == sizeof(magic))
				{
					if(ntohl(magic) == ONLINE_MAGIC_IP || ntohl(magic) == ONLINE_MAGIC_M || ntohl(magic) == ONLINE_MAGIC_Y)
					{
						fseek(fp, -4L, SEEK_CUR);
						online_data_do(readbuf[thr_id], len, thr_id);
						break;
					}
					else 
					{
						memcpy(readbuf[thr_id] + len, &magic, sizeof(uint8_t));
						len += sizeof(uint8_t);
						fseek(fp, -3L, SEEK_CUR);
					}
				}
			}
			else
			{
				online_data_do(readbuf[thr_id], len, thr_id);
			}
		}

#endif
		fclose(fp);
	}
	return 0;
}


static int online_data_read_dir(char *path, int thr_id)
{
	struct stat s_buf;                                                           
	stat(path, &s_buf);                                                          
	if(S_ISDIR(s_buf.st_mode))                                                   
	{                                                                            
		DIR *dp = NULL;                                                          
		dp = opendir(path);                                                      
		struct dirent   *dirt = NULL;                                            
		char pathx[512] = {0};                                                   
		while(dirt = readdir(dp))                                                
		{                                                                        
			if(strcmp(dirt->d_name, ".") != 0 && strcmp(dirt->d_name, "..") != 0)
			{                                                                    
				snprintf(pathx, 512, "%s/%s", path, dirt->d_name);               
				struct stat n_buf;                                               
				stat(pathx, &n_buf);                                             
				if(S_ISDIR(n_buf.st_mode))                                       
					online_data_read_dir(pathx, thr_id);                
				else if(S_ISREG(n_buf.st_mode))                                  
					online_data_read_proc(pathx, thr_id);               
			}                                                                    
		}                                                                        
	}                                                                            
	else if(S_ISREG(s_buf.st_mode))
		online_data_read_proc(path, thr_id);
	return 0;
}
static void *online_rbq_get(void *ele)
{
	online_rbq_init_t *rbq_in = (online_rbq_init_t *)ele;
	rbq_buf_t *rbq_buf = NULL;
	uint32_t total_len = 0, copy_len = 0;
	hk_header_t hk_header;
	total_len += 8 + sizeof(hk_header.timelog);
	total_len += 8 + sizeof(hk_header.id);
	total_len += 8 + sizeof(hk_header.network);
	gonline_fb[rbq_in->use_id].userInfo = malloc(total_len);	
	char thread_name[128] = {0};
	int cpu_id = 0;
	cpu_set_t mask;                                                                             
	CPU_ZERO(&mask);
	cpu_id = rbq_in->use_id + 40;
	CPU_SET(cpu_id, &mask);
	int ret = sched_setaffinity(0, sizeof(cpu_set_t), &mask);
	if(ret == -1)
		printf("%s(%d):hk_proc, cpu_id=%d, cpu bind failed\n", __FILE__, __LINE__, cpu_id);
	else
		printf("%s(%d):hk_proc, cpu_id=%d, cpu bind succeed\n", __FILE__, __LINE__, cpu_id);
	snprintf(thread_name, sizeof(thread_name), "hk_proc_%d", rbq_in->use_id);
	prctl(PR_SET_NAME, thread_name);
	readbuf[rbq_in->use_id] = malloc(maxreadbuflen);	
	while(1)
	{
	
#if 1
		//online_data_read_dir("/home/tan.haijun/3.0/run-front/bin/DealGS_Dat", rbq_in->use_id);
		online_data_read_dir("/yuantek/HK/run/run-front/bin/DealGS_Dat", rbq_in->use_id);
#else 
		rbq_buf = rbq_get_data(udpserver_rbq_handle, rbq_in->thr_id);
		if(rbq_buf == NULL)
		{
			usleep(1);
			continue; 	
		}
	//	online_data_proc(rbq_buf->ext, rbq_buf->buf, rbq_buf->len, rbq_in->use_id);
		online_data_get(rbq_buf->ext, rbq_buf->buf, rbq_buf->len, rbq_in->use_id);
		rbq_put_buf(udpserver_rbq_handle, rbq_buf);
#endif
		
	}

	return NULL;
}
static int online_rbq_init(int thr_id, int use_id)
{
#if 1
	online_rbq_init_t *rbq_in = (online_rbq_init_t *)malloc(sizeof(online_rbq_init_t));
	rbq_in->thr_id = thr_id;
	rbq_in->use_id = use_id;
	pthread_t pthid;
	int ret = pthread_create(&pthid ,NULL, online_rbq_get, (void *)rbq_in);
	if(ret != 0)
	{
		printf("pthread_create fail\n");
		exit(0);
	}
	return 0;
#endif
}
static int udpserver_qlen = 65536, udpserver_qsize = 1024 * 4, udpserver_total_mem = 1024 * 1024 * 500, udpserver_malloc_size = 1024 * 1024 * 20;

static void *udpserver_rbq_init(int moniServerSum)
{
	udpserver_rbq_handle = rbq_malloc(moniServerSum, udpserver_qlen, udpserver_qsize, moniServerSum, moniServerSum, "udpserver_rbq");
	assert(udpserver_rbq_handle != NULL);
	rbq_overcommit(udpserver_rbq_handle, udpserver_total_mem, udpserver_malloc_size);
	return NULL;
}   


static tcpserver_param_t serv_param;
static int check_helper(void *ele, char *data, int dataLen, void **user_data)
{
#if 1
	uint32_t magic = 0;
	if(dataLen <= sizeof(uint32_t))
	{
		printf("recv data len[%d] is err\n", dataLen);
		return UDPSERVER_ERR;
	}
	magic = *(uint32_t *)data;
	if(ntohl(magic) != ONLINE_MAGIC_BQ_BASE_FR && ntohl(magic) != ONLINE_MAGIC_BQ_YUAN)
	{
		printf("TX data magic[0x%x] is err\n", ntohl(magic));
		return UDPSERVER_ERR;
	}
#endif
	return UDPSERVER_OK; 
}
static void *online_hk_init(char *dyn_name)
{

	void *dyn_load_ptr = dlopen(dyn_name, RTLD_LAZY);
	if(!dyn_load_ptr)
	{
		printf("dlopen %s fail [%s-%s-%d]\n", dyn_name, __FILE__, __func__, __LINE__);
		goto leave;
	}
	hk_proc = (hk_proc_helper *)dlsym(dyn_load_ptr, "DealGS1");
	if(!hk_proc)
	{
		printf("dlsym hk_proc fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		goto leave;
	}  
leave:
	return NULL;
}

int online_mddw_init(mddw_dyn_init_t *mddw_dyn_init, mddw_gsc_info_t *mddw_gsc)
{
	memcpy(&m_mddw_gsc, mddw_gsc, sizeof(mddw_gsc_info_t));
	int i = 0;
	online_hk_init("../mddw_dyn/libManageFile.so");
#if 0
	while(hk_proc(NULL, 0, NULL, NULL, NULL, NULL, 0) != 1)
	{
		printf("try DealGS1 check!\n");
		sleep(1);
	}
#endif
	udpserver_rbq_init(mddw_gsc->mddw_sc_num);
	udpserver_init_t udpserver;
	memset(&udpserver, 0, sizeof(udpserver_init_t));
	udpserver.moniServerSum = mddw_gsc->mddw_sc_num;
	for(i = 0; i < mddw_gsc->mddw_sc_num; i++)
		udpserver.cpuId[i] = i + 30;
	udpserver.udpserver_check;	
	udpserver.udpserver_check.bufMaxLen = 1024*10;  
	udpserver.maxPackLen   = 1024 * 1204 * 10; //打包大小
	udpserver.packSwitch   = 1;   //打包开关
	udpserver.packPushTime = 10;  //超时时间
	udpserver.udpserver_helper.check_helper = check_helper;
	void *hand = udpserver_init(udpserver_rbq_handle, &udpserver);
	for(i = 0; i < mddw_gsc->mddw_sc_num; i++)  //mddw_xml_conf.xml内配置的端口
		udpserver_add_socket(hand, mddw_gsc->mddw_sc[i].port);
	udpserver_recv_start(hand);
	for(i = 0; i < mddw_gsc->mddw_sc_num; i ++)
		online_rbq_init(i, mddw_dyn_init->thr_id[i]);
	return 0;
}

int online_mddw_push(mddw_dyn_push_t *mddw_dyn_push)
{
	mddw_dyn_push->thrnum = 4;
	return 0;
}
