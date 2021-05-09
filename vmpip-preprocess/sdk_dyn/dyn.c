/*************************************************************************
	> File Name: dyn.c
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月20日 星期六 18时26分04秒
 ************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <netinet/in.h>
#include <assert.h>
#include <dlfcn.h>
#include "utils.h"
#include "dyn.h"
#include "xmlcfg.h"
#include "vmp_demod.h"

#define     DYN_MAX_USER_NUM        4
#define     TCPSERVER_HEADER_TYPE 0x435A5223
#define datatype_ip             0x01
#define datatype_eth            0x08
#define datatype_not_ip         0x20

static char *libinfo __attribute__((unused))  = "\n@VERSION@:sdk_dyn, 1.0.0, "VERSION"\n" ;

static online_helper_t g_online_helper[DYN_MAX_USER_NUM];
static int g_online_helper_num = 0;
static int fixthr_id[DYN_MAX_USER_NUM];
static uint32_t  fixchannel[DYN_MAX_USER_NUM];
static int g_online_num = 0;



#pragma pack (1)
typedef struct{
	char     dynname[512]; 
	uint16_t port; 
	uint32_t ip;
}online_sdk_recv_t;

typedef void* ol_vmp_demod_open(uint32_t ip, uint16_t port, vmp_demod_type_t type, int *retcode);
typedef void ol_vmp_demod_close(void *handle, int *retcode);
typedef int ol_vmp_demod_get_data(void *handle, vmp_demod_data_info_t *info, void *buf, uint32_t buf_len, int *retcode);
typedef void ol_vmp_demod_get_stats(void *handle, vmp_demod_stats_t *stats, int *retcode);
typedef void ol_vmp_demod_reset_stats(void *handle, int *retcode);


typedef struct{
	ol_vmp_demod_open         *vmp_demod_open;
	ol_vmp_demod_close        *vmp_demod_close;
	ol_vmp_demod_get_data     *vmp_demod_get_data;	
	ol_vmp_demod_get_stats    *vmp_demod_get_stats;
	ol_vmp_demod_reset_stats  *vmp_demod_reset_stats;
}online_sdk_dyn_t;


typedef struct{
	uint32_t assign_id;
	uint32_t serial_num;
	uint64_t mac;
	uint8_t right;
	uint8_t group_id;
	uint8_t priority;
}online_sdk_ip_header_t;

#pragma pack (0)         


static online_sdk_dyn_t sdk_dyn;

static uint64_t ntoh64(uint64_t buff)
{
	uint64_t value = 0;
	uint8_t *pos1 = (uint8_t *)&value;
	uint8_t *pos2 = (uint8_t *)&buff;

	pos1[0] = pos2[7];
	pos1[1] = pos2[6];
	pos1[2] = pos2[5];
	pos1[3] = pos2[4];
	pos1[4] = pos2[3];
	pos1[5] = pos2[2];
	pos1[6] = pos2[1];
	pos1[7] = pos2[0];

	return value;
}

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

static int do_onlineld_helper(online_fc_t *fc, uint8_t *data, uint32_t datalen)                      
{   
	int no = 0;     
	int iret = -1; 
	if(fc == NULL || data == NULL || datalen <= 0)
		goto exit;
	iret = g_online_helper[no].onlineld_entry(NULL, fc, data, datalen, fixchannel[no], fixthr_id[no], NULL); 
exit:    
	return iret;
}
static int do_onlineip_helper(online_fb_t *fb, uint8_t *data, uint32_t datalen)
{

	int no = 0;     
	int iret = -1; 
	if(fb == NULL || data == NULL || datalen <= 0)
		goto exit;
	iret = g_online_helper[no].onlineip_entry(NULL, fb, data, datalen, datatype_ip, fixchannel[no], fixthr_id[no], NULL);
exit:    
	return iret;
}

static online_sdk_recv_t sdk_recv;

static void online_server_port_add(char *filename)
{

	xmlcfg_t tc;
	int err;
	long v;
	char xpath[255];
	char ipbuff[215];
	struct in_addr addr;

	printf("load %s\n", filename);
	if (xmlcfg_init_file(&tc, filename) != 0)
	{
		printf("load %s fail\n", filename);
		exit(0);
	}
	snprintf(xpath,255,"/conf/listen/ip");
	err = xmlcfg_get_str(&tc, xpath, ipbuff, sizeof(ipbuff));
	if(err < 1)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}
	if(inet_aton(ipbuff, &addr))
		sdk_recv.ip = (addr.s_addr);
	else
	{
		printf("%s transform fail\n", xpath);
		exit(0);
	}
	snprintf(xpath,255,"/conf/listen/port"); 
	err = xmlcfg_get_long(&tc,xpath,&v);            
	if(err)                                         
	{                                               
		printf("load %s fail\n",xpath);             
		exit(0);                                    
	}                                               
	sdk_recv.port = v;
	sdk_recv.port = ntohs(sdk_recv.port);	
	snprintf(xpath,255,"/conf/dyn_name");
	err = xmlcfg_get_str(&tc, xpath, sdk_recv.dynname, sizeof(sdk_recv.dynname));
	if(err < 1)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}
	xmlcfg_close(&tc);
	return ;
}

static void online_dyn_load(char *dyn_name)
{
	printf("load %s start [%s-%s-%d]\n", dyn_name, __FILE__, __func__, __LINE__);
	void *dyn_load_ptr = dlopen(dyn_name, RTLD_LAZY);
	if(!dyn_load_ptr)
	{
		printf("dlopen %s fail [%s-%s-%d]\n", dyn_name, __FILE__, __func__, __LINE__);
		goto leave;
	}
	sdk_dyn.vmp_demod_open = (ol_vmp_demod_open *)dlsym(dyn_load_ptr, "vmp_demod_open");
	if(!sdk_dyn.vmp_demod_open)
	{
		printf("dlsym vmp_demod_open fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		goto leave;
	}	
	sdk_dyn.vmp_demod_close = (ol_vmp_demod_close *)dlsym(dyn_load_ptr, "vmp_demod_close");
	if(!sdk_dyn.vmp_demod_close)
	{
		printf("dlsym vmp_demod_close fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		goto leave;
	}
	sdk_dyn.vmp_demod_get_data = (ol_vmp_demod_get_data *)dlsym(dyn_load_ptr, "vmp_demod_get_data");
	if(!sdk_dyn.vmp_demod_get_data)
	{
		printf("dlsym vmp_demod_get_data fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		goto leave;
	
	}
leave:
	return;
}	
static int online_vmp_start()
{
	int ret = 0;
	void *hand = sdk_dyn.vmp_demod_open(sdk_recv.ip, sdk_recv.port, (vmp_demod_type_t )vmp_demod_type_ip, &ret);
	if(hand == NULL)
	{
		printf("vmp_demod_open fail, ret code: %d\n", ret);
		return -1;
	}	
	vmp_demod_data_info_t info;
	char *buf = malloc(1024*1024);
	int buflen = 0;
	while((buflen = sdk_dyn.vmp_demod_get_data(hand, &info, buf, 1024*1024, &ret)) > 0)
	{
	//	ret = sdk_dyn.vmp_demod_get_data
		online_sdk_ip_header_t *sdk_ip = (online_sdk_ip_header_t *)buf;
		online_fb_t fb;
		memset(&fb, 0, sizeof(online_fb_t));
		snprintf(fb.sessId, sizeof(fb.sessId), "ott%d", fixchannel[0]);	
		fb.sessIdLen         = strlen(fb.sessId);
		fb.capTimeStamp      = info.timestamp;
		fb.analysisTimeStamp = jiffies;
		fb.IPOffset          = 0;
		do_onlineip_helper(&fb, (uint8_t *)(buf + sizeof(online_sdk_ip_header_t)), buflen - sizeof(online_sdk_ip_header_t));
	}
	sdk_dyn.vmp_demod_close(hand, &ret);
	return 0;
}
static void *online_sdk_proc(void *ele)
{
	while(1)
	{
		printf("-------------------------\n");
		online_vmp_start();
		sleep(1);
	}
	return NULL;
}

int online_init(uint32_t channel, int thr_id)
{
	fixchannel[g_online_num] = channel;  
	fixthr_id[g_online_num]  = thr_id; //最好用初始化时使用的通道，必须使用初始化时的线程号
	g_online_num++;
	
	online_server_port_add("./online_sdk_init.xml");
	online_dyn_load(sdk_recv.dynname);

	pthread_t pthid;
	int ret = pthread_create(&pthid ,NULL, online_sdk_proc, NULL);
	if(ret != 0)
	{
		printf("pthread_create fail\n");
		exit(0);
	}
	return 0;
}
