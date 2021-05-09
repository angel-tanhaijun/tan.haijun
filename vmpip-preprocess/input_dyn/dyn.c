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
#include <assert.h>
#include "utils.h"
#include "dyn.h"
#include "xmlcfg.h"
#include "tcpserver.h"
#include "rbque.h"

#define INPUT_USER_LABLE_TYPE                 0x10005001
#define INPUT_USER_LABLE_VENDOR_TYPE          0x10005002
#define INPUT_USER_LABLE_NORMAL_VENDOR_TYPE   0x10005003
#define INPUT_M2_INFO_TYPE                    0x10000000
#define INPUT_INFO_TYPE                       0x1001c001
#define INPUT_INFO_DATA_INFO_TYPE             0x1001c003
#define INPUT_INFO_DATA_INFO_IPOFFSET_TYPE                        0x1001C008
#define INPUT_INFO_DATA_INFO_DATA_TYPE                            0x1001C00D
#define INPUT_INFO_DATA_INFO_DATATYPE_TYPE                        0x1001C007



#define INPUT_USER_LABLE_NORMAL_VENDOR_SESSID_TYPE                0x1000500a
#define INPUT_USER_LABLE_NORMAL_VENDOR_CAP_TIMESTAMP_TYPE         0x10005008
#define INPUT_USER_LABLE_NORMAL_VENDOR_ANALYSIS_TIMESTAMP_TYPE    0x10005009
#define INPUT_USER_LABLE_NORMAL_VENDOR_HOST_IP_TYPE               0x10005005

#define     DYN_MAX_USER_NUM        4
#define     TCPSERVER_HEADER_TYPE 0x435A5223
#define datatype_ip             0x01
#define datatype_eth            0x08
#define datatype_not_ip         0x20

static char *libinfo __attribute__((unused))  = "\n@VERSION@:input_dyn, 1.0.0, "VERSION"\n" ;

static online_helper_t g_online_helper[DYN_MAX_USER_NUM];
static int g_online_helper_num = 0;
static int fixthr_id[DYN_MAX_USER_NUM];
static uint32_t  fixchannel[DYN_MAX_USER_NUM];
static int g_online_num = 0;
static void *recv_rbq_handle = NULL; 



#pragma pack (1)

typedef struct{
	char      sessId[215];
	int       sessIdLen;
	uint64_t  capTimeStamp;     
	uint64_t  analysisTimeStamp;
	uint32_t  IPOffset;         
	uint32_t  hostIp; 
	uint32_t  dataType;
	uint8_t  *data;
	uint32_t  datalen;	
}input_m2info_t;

typedef struct __msg_header_t {
	uint32_t      magic_num;
	uint16_t      checksum;
	uint16_t      msg_type;
	uint32_t      cont_len;
}msg_header_t; /*sizeof = 20B */

#pragma pack (0)         

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
static uint32_t qsize = 2000;
static uint32_t malloc_size = 10*1024*1024;
#define Magic_Value                     0x00000601

static int parse_input_head(uint8_t *head,uint32_t head_len,uint32_t *body_len)
{
	uint16_t checksum = 0;                                                                    
	uint32_t cont_len = 0;
	uint16_t type = 0;

	if(head_len != sizeof(msg_header_t))
		return MSG_ILLEGAL;

	msg_header_t *msg_header = (msg_header_t *)head;
	if(ntohl(msg_header->magic_num) != Magic_Value )
	{
		printf("IP recv  data decode Magic error\n");
		return MSG_ILLEGAL;
	}   

	type = ntohs(msg_header->msg_type);
	cont_len = ntohl(msg_header->cont_len);
	checksum = ( ( ((uint32_t)type )<<16 ) | (uint32_t) (type) ) ^ (Magic_Value )^ (cont_len);
	if(ntohs(msg_header->checksum) != checksum)
	{
		printf("IP recv data decode checksum error\n");
		return MSG_ILLEGAL;
	}   
	*body_len = cont_len;
	return MSG_OK;

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
	iret = g_online_helper[no].onlineip_entry(NULL, fb, data, datalen, fb->extra.dataType, fixchannel[no], fixthr_id[no], NULL);
exit:    
	return iret;
}

static int input_tlv(uint32_t type, uint32_t len, uint8_t *value, input_m2info_t *input_m2info)
{
	printf("type: 0x%x----len: %d\n", type, len);	
	switch(type)
	{
		case INPUT_INFO_DATA_INFO_IPOFFSET_TYPE:
			memcpy(&input_m2info->IPOffset, value, sizeof(input_m2info->IPOffset));
			input_m2info->IPOffset = ntohl(input_m2info->IPOffset);
			printf("ipoffset:%d\n", input_m2info->IPOffset);		
			break;
		case INPUT_USER_LABLE_NORMAL_VENDOR_SESSID_TYPE:
			memcpy(input_m2info->sessId, value, len);
			input_m2info->sessIdLen = len;
			printf("sessid:%s\n", input_m2info->sessId);
			break;
		case INPUT_USER_LABLE_NORMAL_VENDOR_CAP_TIMESTAMP_TYPE:
			memcpy(&input_m2info->capTimeStamp, value, sizeof(input_m2info->capTimeStamp));
			input_m2info->capTimeStamp = ntoh64(input_m2info->capTimeStamp);
			printf("capTimeStamp:%lu\n",input_m2info->capTimeStamp);
			break;
		case INPUT_USER_LABLE_NORMAL_VENDOR_ANALYSIS_TIMESTAMP_TYPE:
			memcpy(&input_m2info->analysisTimeStamp, value, sizeof(input_m2info->analysisTimeStamp));
			input_m2info->analysisTimeStamp = ntoh64(input_m2info->analysisTimeStamp);
			printf("analysisTimeStamp:%lu\n",input_m2info->analysisTimeStamp);
			break;
		case INPUT_USER_LABLE_NORMAL_VENDOR_HOST_IP_TYPE:
			memcpy(&input_m2info->hostIp, value, sizeof(input_m2info->hostIp));
			printf("hostIp:%x\n",input_m2info->hostIp);	
			break;
		case INPUT_INFO_DATA_INFO_DATA_TYPE:
			input_m2info->data = value;
			input_m2info->datalen = len;
			printf("datalen:%d\n", input_m2info->datalen);
			break;
		case INPUT_INFO_DATA_INFO_DATATYPE_TYPE:
			memcpy(&input_m2info->dataType, value, sizeof(input_m2info->dataType));
			input_m2info->dataType = ntohl(input_m2info->dataType); 
			printf("dataType:%x\n", input_m2info->dataType);
			break;	
		default:
			printf("do not use\n");
			break;	
	}
	return 0;
}

static int input_data_proc(uint8_t *data, uint32_t datalen, input_m2info_t *input_m2info)
{
	uint32_t movelen  = 0;
	uint32_t type = 0;
	uint32_t len = 0;
	while(movelen < datalen)
	{
		memcpy(&type, data + movelen, sizeof(type));
		type = ntohl(type);
		movelen += sizeof(type);
		memcpy(&len, data + movelen, sizeof(len));
		len = ntohl(len);
		movelen += sizeof(len);

		if(type == INPUT_M2_INFO_TYPE || 
		   type == INPUT_USER_LABLE_TYPE || 
		   type == INPUT_USER_LABLE_NORMAL_VENDOR_TYPE || 
		   type == INPUT_INFO_TYPE ||
		   type == INPUT_INFO_TYPE ||
		   type == INPUT_INFO_DATA_INFO_TYPE)
		{
			input_data_proc(data + movelen, len, input_m2info);
		}
		else
			input_tlv(type, len, data + movelen, input_m2info);	
		movelen += len;
	}
	return 0;
}

static int input_m2info_push(input_m2info_t *input_m2info)
{
	printf("-------------------------\n");
	if(input_m2info->dataType == 0x01 || input_m2info->dataType == 0x08)
	{
		online_fb_t fb;
		memset(&fb, 0, sizeof(online_fb_t));
		memcpy(fb.sessId, input_m2info->sessId, input_m2info->sessIdLen);
		fb.sessIdLen         = input_m2info->sessIdLen;
		fb.capTimeStamp      = input_m2info->capTimeStamp;
		fb.analysisTimeStamp = input_m2info->analysisTimeStamp;
		fb.IPOffset          = input_m2info->IPOffset;
		fb.extra.hostIp      = input_m2info->hostIp;
		fb.extra.dataType    = input_m2info->dataType;
		do_onlineip_helper(&fb, input_m2info->data, input_m2info->datalen);	
	}
	else
	{
		online_fc_t fc;
		memset(&fc, 0, sizeof(online_fc_t));
		memcpy(fc.sessId, input_m2info->sessId, input_m2info->sessIdLen);
		fc.sessIdLen           = input_m2info->sessIdLen;
		fc.capTimeStamp        = input_m2info->capTimeStamp;
		fc.analysisTimeStamp   = input_m2info->analysisTimeStamp;
		fc.extra.hostIp        = input_m2info->hostIp;
		fc.extra.dataType      = input_m2info->dataType;
		do_onlineld_helper(&fc, input_m2info->data, input_m2info->datalen);	
	}
	return 0;
}

static int online_data_proc(uint8_t *data, uint32_t datalen)
{
	input_m2info_t input_m2info;
	memset(&input_m2info, 0, sizeof(input_m2info_t));
	msg_header_t *msg_header = (msg_header_t *)data;

	input_data_proc(data + sizeof(msg_header_t), ntohl(msg_header->cont_len), &input_m2info);	

	input_m2info_push(&input_m2info);
	return 0;
}

static void *online_rbq_get(void *ele)
{
	rbq_buf_t *rbq_buf = NULL;
	while(1)
	{
		rbq_buf = rbq_get_data(recv_rbq_handle, 0);
		if(rbq_buf == NULL)
		{
			usleep(100);
			continue; 	
		}
		online_data_proc(rbq_buf->buf, rbq_buf->len);

		rbq_put_buf(recv_rbq_handle, rbq_buf);

	}
	return NULL;
}
static int online_rbq_init()
{
	recv_rbq_handle = rbq_malloc(1, 500, qsize, 1, 1, "online_rbq_input");
	assert(recv_rbq_handle != NULL);
	rbq_overcommit(recv_rbq_handle, 50*1024*1024, malloc_size);
	rbq_set_get_buf_mode(recv_rbq_handle, RBQ_GET_BUF_BLOCK);

	pthread_t pthid;
	int ret = pthread_create(&pthid ,NULL, online_rbq_get, NULL);
	if(ret != 0)
	{
		printf("pthread_create fail\n");
		exit(0);
	}
	return 0;
}

static tcpserver_param_t serv_param;

static void online_server_port_add(char *filename)
{

	xmlcfg_t tc;
	xmlcfg_list_t xmllist;
	int i, err;
	long v;
	printf("load %s\n", filename);
	if (xmlcfg_init_file(&tc, filename) != 0)
	{
		printf("load %s fail\n", filename);
		exit(0);
	}
	err = xmlcfg_get_list(&tc, "/conf/listen", &xmllist);
	if (err)
	{
		printf("load /conf/node from %s failed\n", filename);

		xmlcfg_list_free(&xmllist);
		xmlcfg_close(&tc);
		exit(0);
	}

	for (i = 0; i < xmlcfg_list_length(&xmllist); i++)
	{
		err = xmlcfg_list_get_long(&xmllist, i,  "port", &v);
		if (err)
		{
			printf("load /conf/node/[%d]/port failed\n", i);
			exit(0);
		}
		serv_param.listen_port_arr[serv_param.listen_num] = v;                                            
		serv_param.listen_num++;
	}
	xmlcfg_list_free(&xmllist);
	xmlcfg_close(&tc);
	return ;
}


int online_init(uint32_t channel, int thr_id)
{
	fixchannel[g_online_num] = channel;  
	fixthr_id[g_online_num]  = thr_id; //最好用初始化时使用的通道，必须使用初始化时的线程号
	g_online_num++;
	int i = 0;
	
	online_rbq_init();

	serv_param.head_len      = sizeof(msg_header_t);
	serv_param.recv_timeout  = 10000;
	serv_param.parse_head    = parse_input_head;
	serv_param.thr_num       = 1;
	serv_param.rbq_handle    = recv_rbq_handle;
	serv_param.part_num      = 10;
	serv_param.unit_size     = 100;	
	for(i = 0; i < serv_param.thr_num; i++)
		serv_param.cpumap[i] = 20;
	online_server_port_add("./online_server_init.xml");
	if(tcpserver_init(&serv_param)==0)
	{
		printf("tcpserver_init fail\n");
		return -1;
	}   
	tcpserver_start();
	return 0;
}
