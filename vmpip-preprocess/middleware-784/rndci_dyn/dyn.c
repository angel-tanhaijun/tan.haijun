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
#include "mddw.h"
#include "xmlcfg.h"
#include "tcpserver.h"
#include "rbque.h"

#define     DYN_MAX_USER_NUM        4
#define     TCPSERVER_HEADER_TYPE 0x435A5223


static char *libinfo __attribute__((unused))  = "\n@VERSION@:rndci_dyn, 1.0.0, "VERSION"\n" ;

static online_helper_t g_online_helper[DYN_MAX_USER_NUM];
static int g_online_helper_num = 0;
static int fixthr_id[DYN_MAX_USER_NUM];
static int g_online_num = 0;
static void *recv_rbq_handle = NULL; 
static mddw_gsc_info_t m_mddw_gsc;

#pragma pack (1)

typedef struct{
	uint8_t year;
	uint8_t month;
	uint8_t day;
	uint8_t hour;
	uint8_t minute;
	uint8_t second;
}ndci_time_t;

typedef struct{
	uint32_t flag;
	uint16_t len;
	uint32_t count;
	uint8_t  channel;
	uint8_t type;
	ndci_time_t time;
	uint32_t lus;
	uint16_t reserved;
}ndci_header_t;

#pragma pack (0)         


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
static int parse_ndci_head(uint8_t *head,uint32_t head_len,uint32_t *body_len)
{
	*body_len = qsize;
	if(head_len + *body_len > malloc_size)
	{
		printf("IP recv  data too_len\n");
		return MSG_TOO_LONG;
	}
	return MSG_OK;	
}

static int do_onlineld_helper(online_fc_t *fc, uint8_t *data, uint32_t datalen, uint32_t channel)                      
{   
	int no = 0;     
	int iret = -1; 
	if(fc == NULL || data == NULL || datalen <= 0)
		goto exit;
	iret = g_online_helper[no].onlineld_entry(NULL, fc, data, datalen, channel, fixthr_id[no], NULL); 
exit:    
	return iret;
}

static int do_onlinefh_helper(online_fd_t *fd, uint8_t *data, uint32_t datalen, uint32_t channel)
{
	int no = 0;
	int iret = -1;
	if(fd == NULL || data == NULL || datalen <= 0)
		goto exit;
	iret = g_online_helper[no].onlinefh_entry(NULL, fd, data, datalen, 220, channel, fixthr_id[no], NULL);
exit:
	return iret;
}

static int recv_call(uint8_t *data, int dataLen)
{
	ndci_header_t ndci = *(ndci_header_t *)data;		
	if(ntohl(ndci.flag) != TCPSERVER_HEADER_TYPE)
	{
		printf("recv_call flag[%x] is not 0x435A5223\n", ntohl(ndci.flag));
		return 0;
	}
	uint32_t total_len = 0;
	online_fc_t fc;
	memset(&fc, 0, sizeof(online_fc_t));
	snprintf(fc.sessId, 215, "ott%d", ndci.channel);
	fc.sessIdLen = strlen(fc.sessId);
	if(ndci.type != 0)	//非解调消息丢弃
	{
		printf("recv_call ndci.type is %d\n", ndci.type);
		return 0;
	}
//填充userinfo示例	
	total_len      += 4 + 4;//type + len
	total_len      += sizeof(ndci_header_t);
	fc.userInfo     = (uint8_t *)malloc(total_len);	
	fc.userInfoLen  = total_len;
	fc.userInfoType = 0x10005094; //此类型为用户标签可用最小值
	uint32_t type = 0x10005095;
	uint32_t len = sizeof(ndci_header_t);	
	type = ntohl(type);
	len  = ntohl(len);
	memcpy(fc.userInfo, &type, sizeof(uint32_t));
	memcpy(fc.userInfo + sizeof(uint32_t), &len, sizeof(uint32_t));
	memcpy(fc.userInfo + sizeof(uint32_t)*2, &ndci, sizeof(ndci_header_t));

#if 0
	//新协议示例
	online_fd_t fd;
	memset(&fd, 0, sizeof(online_fd_t));
	snprintf(fd.sessId, 215, "ott%d", ndci.channel);
	fd.sessIdLen = strlen(fd.sessId);
	fd.capTimeStamp      = jiffies;
	fd.analysisTimeStamp = jiffies;
	fd.m2BigType         = 0x10999001; //测试类型
	fd.m2AddType         = 0x10999002; //测试类型
	char *prodata = "hello world";
	do_onlinefh_helper(&fd, (uint8_t *)prodata, strlen(prodata), ndci.channel);
#endif
	do_onlineld_helper(&fc, (uint8_t *)(data + sizeof(ndci_header_t)), (dataLen - sizeof(ndci_header_t)), ndci.channel);
	free(fc.userInfo);

	return 0;
}

static uint8_t *chbuff = NULL;
static uint32_t chbuffmaxlen = 0x3000;
static uint32_t chbufflen = 0;

static int online_data_proc(uint8_t *adapt_info, uint8_t *data, uint32_t datalen)
{
	int i = 0;
	uint8_t *movedata = data;
	uint32_t movelen  = 0;
	uint32_t headerType = 0;
	uint16_t port = 0;
	memcpy(&port, adapt_info, sizeof(uint16_t));

	while(movelen < datalen)
	{
		
		if(chbufflen >= sizeof(ndci_header_t))
		{
			if(ntohl(headerType = *(uint32_t *)chbuff) == TCPSERVER_HEADER_TYPE)
			{
				ndci_header_t ndci = *(ndci_header_t *)chbuff;
				if((ntohs(ndci.len) - chbufflen) <= (datalen - movelen))
				{
					memcpy(chbuff + chbufflen, movedata, (ntohs(ndci.len) - chbufflen));
					for(i = 0; i < m_mddw_gsc.mddw_sc_num; i++)
					{
						if(port == m_mddw_gsc.mddw_sc[i].port)
						{
							if(m_mddw_gsc.mddw_sc[i].channel != ndci.channel)
							{
								printf("online_data_proc ClinetPort:%d; port:%d; ip:%s; ndci.channel:%d; mddw_sc[%d].channel:%d;\n", port, m_mddw_gsc.mddw_sc[i].port, m_mddw_gsc.mddw_sc[i].ip, ndci.channel, i, m_mddw_gsc.mddw_sc[i].channel);
								return 0;
							}
						}		
					}
					recv_call(chbuff, ntohs(ndci.len));
					movelen += ntohs(ndci.len) - chbufflen;
					movedata = movedata + (ntohs(ndci.len) - chbufflen);
					chbufflen = 0;
				}
				else
				{
					memcpy(chbuff + chbufflen, movedata, datalen - movelen);
					chbufflen += (datalen - movelen);
					movelen += (datalen - movelen);
					movedata = movedata + (datalen - movelen);
				}
			}
			else
			{
				printf("headerType is %x not %x\n", ntohl(headerType), TCPSERVER_HEADER_TYPE);
				return 0;
			}
		}
		else
		{
			if((datalen - movelen) < (sizeof(ndci_header_t) - chbufflen))
			{
				memcpy(chbuff + chbufflen, movedata, datalen - movelen);
				chbufflen += (datalen - movelen);
				movelen += (datalen - movelen);
				movedata = movedata + (datalen - movelen);
			}
			else
			{
				memcpy(chbuff + chbufflen, movedata, (sizeof(ndci_header_t) - chbufflen));
				movelen += (sizeof(ndci_header_t) - chbufflen);
				movedata = movedata + (sizeof(ndci_header_t) - chbufflen);
				chbufflen += (sizeof(ndci_header_t) - chbufflen);
			}
		}
	}	
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
			usleep(10);
			continue; 	
		}
		online_data_proc(rbq_buf->ext, rbq_buf->buf, rbq_buf->len);

		rbq_put_buf(recv_rbq_handle, rbq_buf);

	}
	return NULL;
}
static int online_rbq_init()
{
	chbuff = malloc(chbuffmaxlen);
	recv_rbq_handle = rbq_malloc(1, 500, qsize, 1, 1, "online_rbq_recv");
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

int online_mddw_init(int thr_id, mddw_gsc_info_t *mddw_gsc)
{
	fixthr_id[g_online_num]  = thr_id; //最好用初始化时使用的通道，必须使用初始化时的线程号
	g_online_num++;
	memcpy(&m_mddw_gsc, mddw_gsc, sizeof(mddw_gsc_info_t));
	int i = 0;
	
	online_rbq_init();

	serv_param.head_len = sizeof(ndci_header_t);
	serv_param.recv_timeout = 10000;
	serv_param.parse_head   = parse_ndci_head;
	serv_param.thr_num      = 1;
	serv_param.rbq_handle   = recv_rbq_handle;
	serv_param.part_num     = 10;
	serv_param.unit_size    = 100;	
	for(i = 0; i < serv_param.thr_num; i++)
		serv_param.cpumap[i] = 20;
	serv_param.listen_num = mddw_gsc->mddw_sc_num;
	for(i = 0; i < serv_param.listen_num ; i++)
		serv_param.listen_port_arr[i] = mddw_gsc->mddw_sc[i].port;
	if(tcpserver_init(&serv_param)==0)
	{
		printf("tcpserver_init fail\n");
		return -1;
	}   
	tcpserver_start();
	return 0;
}
