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
#include "tcpclient_v2.h"

#define     DYN_MAX_USER_NUM        4
#define     TCPCLIENT_HEADER_TYPE 0x435A5223

#define pcapName "/home/tan.haijun/workbench/nca/pcap/sip/sip/sdp.pcap"


static char *libinfo __attribute__((unused))  = "\n@VERSION@:ndci_dyn, 1.0.0, "VERSION"\n" ;
static online_helper_t g_online_helper[DYN_MAX_USER_NUM];
static int g_online_helper_num = 0;
static int fixthr_id[DYN_MAX_USER_NUM];
static int g_online_num = 0;
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
	uint32_t flag; //固定填#RZC（0x435A5223)
	uint16_t len;  //固定8192=0x2000
	uint32_t count; //每发送一次命令，包计数器加1,循环计数
	uint8_t  channel; //设备通道号：0-15:通道1用0表示；......通道16用15表示；
	uint8_t type; //0：解调数据 ；2：星座和状态信息；
	ndci_time_t time;  //时间戳：年-月-日-时-分-秒,字节“年”在前，字节“秒”在后, 年份取最后两位数字，例如2019年，只取19
	uint32_t lus; //采用秒脉冲清零复位模式；利用参考10M时钟计数（1us）；
	uint16_t reserved; //预留字节2个
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

static int tcp_client_check(void *ele, char *header, int headerLen, void **user_data)
{
	uint32_t headerType = 0;
	uint16_t dataLen = 0;
	headerType = *(uint32_t *)header;
	if((headerType) != TCPCLIENT_HEADER_TYPE)
	{
		printf("headerType is %x not %x\n", (headerType), TCPCLIENT_HEADER_TYPE);
		return -1;
	}
	dataLen = *(uint16_t *)(header + 4);
	return ((dataLen) - headerLen); //返回值为接下来应获取的数据长度，除去头部长度以后
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

static int tcp_client_call(void *ele, char *data, int dataLen, void **user_data)
{
	int i = 0;
	mddw_sc_t mddw;
	memset(&mddw, 0, sizeof(mddw_sc_t));
	ndci_header_t ndci = *(ndci_header_t *)data;		
	tcpclient_scoket_info_t *fdSocketInfo = (tcpclient_scoket_info_t *)ele;
	if((ndci.flag) != 0x435A5223)
	{
		printf("tcp_client_call flag[%x] is not 0x435A5223\n", (ndci.flag));
		return 0;
	}
	for(i = 0; i < m_mddw_gsc.mddw_sc_num; i++)
	{
		if(fdSocketInfo->serverPort == m_mddw_gsc.mddw_sc[i].port && strcmp(fdSocketInfo->serverIp, m_mddw_gsc.mddw_sc[i].ip) == 0)
		{

			mddw.Stat_ID = m_mddw_gsc.mddw_sc[i].Stat_ID;
			memcpy(mddw.Stat_Sig_Type, m_mddw_gsc.mddw_sc[i].Stat_Sig_Type, 16);
			mddw.Stat_Freq = m_mddw_gsc.mddw_sc[i].Stat_Freq;
			mddw.Stat_Width = m_mddw_gsc.mddw_sc[i].Stat_Width;
			memcpy(mddw.Stat_Band, m_mddw_gsc.mddw_sc[i].Stat_Band, 2);
			memcpy(mddw.Stat_Pol, m_mddw_gsc.mddw_sc[i].Stat_Pol, 1);
#if 0
			if(m_mddw_gsc.mddw_sc[i].channel != ndci.channel)
			{
				printf("tcp_client_call serverPort:%d; serverIp:%s; port:%d; ip:%s; ndci.channel:%d; mddw_sc[%d].channel:%d;\n", fdSocketInfo->serverPort, fdSocketInfo->serverIp, m_mddw_gsc.mddw_sc[i].port, m_mddw_gsc.mddw_sc[i].ip, ndci.channel, i, m_mddw_gsc.mddw_sc[i].channel);
				return 0;
			}
#endif
		}		
	}
	uint32_t total_len = 0, total2_len = 0, add_len = 0;
	online_fc_t fc;
	memset(&fc, 0, sizeof(online_fc_t));
	snprintf(fc.sessId, 215, "ott%d", ndci.channel);
	fc.sessIdLen = strlen(fc.sessId);
	if(ndci.type != 0)
	{	
		printf("tcp_client_call ndci.type is %d\n", ndci.type);
		return 0;
	}
	total_len      += 4 + 4;
//	total_len      += 4 + 4;//type + len
//	total_len      += sizeof(ndci_header_t);
	total_len      += 4 + 4;//type + len
	total_len      += sizeof(mddw_sc_t);
	total2_len     = total_len - 8;
	fc.userInfo     = (uint8_t *)malloc(total_len);	
	fc.userInfoLen  = total_len;
	fc.userInfoType = 0x10005004; //此类型为用户标签可用最小值
	uint32_t type = 0;
	uint32_t len = 0;

	type = 0x100050a0;
	len =  total2_len;	
	type = ntohl(type);
	len  = ntohl(len);
	memcpy(fc.userInfo, &type, sizeof(uint32_t));
	memcpy(fc.userInfo + sizeof(uint32_t), &len, sizeof(uint32_t));

#if 0
	type = 0x100050a4;
	len = sizeof(ndci_header_t);	
	type = ntohl(type);
	len  = ntohl(len);
	memcpy(fc.userInfo + add_len, &type, sizeof(uint32_t));
	memcpy(fc.userInfo + sizeof(uint32_t) + add_len, &len, sizeof(uint32_t));
	memcpy(fc.userInfo + sizeof(uint32_t)*2 + add_len, &ndci, sizeof(ndci_header_t));
	type = 0x100050a1;
	len  = sizeof(mddw_sc_t);
	type = ntohl(type);
	len  = ntohl(len);
	memcpy(fc.userInfo + (sizeof(uint32_t)*2 + sizeof(ndci_header_t) + add_len), &type, sizeof(uint32_t));
	memcpy(fc.userInfo + (sizeof(uint32_t)*3 + sizeof(ndci_header_t) + add_len), &len, sizeof(uint32_t));
	memcpy(fc.userInfo + (sizeof(uint32_t)*4 + sizeof(ndci_header_t) + add_len), &mddw, sizeof(mddw_sc_t));	
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
#endif
	type = 0x100050a1;
	len  = sizeof(mddw_sc_t);
	type = ntohl(type);
	len  = ntohl(len);
	memcpy(fc.userInfo + (sizeof(uint32_t)*2 + add_len), &type, sizeof(uint32_t));
	memcpy(fc.userInfo + (sizeof(uint32_t)*3 + add_len), &len, sizeof(uint32_t));
	memcpy(fc.userInfo + (sizeof(uint32_t)*4 + add_len), &mddw, sizeof(mddw_sc_t));
	do_onlineld_helper(&fc, (uint8_t *)(data + sizeof(ndci_header_t)), (dataLen - sizeof(ndci_header_t)), ndci.channel);
	free(fc.userInfo);

	return 0;
}

int online_mddw_init(mddw_dyn_init_t *mddw_dyn_init, mddw_gsc_info_t *mddw_gsc)
{
	int i = 0;
	fixthr_id[g_online_num]  = mddw_dyn_init->thr_id[0]; //只能用初始化时使用的通道和线程号
	tcpclient_check_t tcpclient_check;
	g_online_num++;
	memcpy(&m_mddw_gsc, mddw_gsc, sizeof(mddw_gsc_info_t));

	tcpclient_hander_t *hander = (tcpclient_hander_t *)malloc(sizeof(tcpclient_hander_t));
	memset(hander, 0, sizeof(tcpclient_hander_t));
	tcpclient_check.headerLen = 24; 
	tcpclient_check.bufMaxLen = 1024 * 1024 * 10;
	tcpclient_add_rules(hander, &tcpclient_check);		
	tcpclient_init(hander,  mddw_gsc->mddw_sc_num, 30);
	for(i = 0; i < mddw_gsc->mddw_sc_num; i++)
	{
		tcpclient_add_socket(hander, mddw_gsc->mddw_sc[i].port, mddw_gsc->mddw_sc[i].ip);
	}
	tcpclient_helper_t tcpclient_helper;
	tcpclient_helper.check_helper = tcp_client_check;
	tcpclient_helper.tcpclient_recv = tcp_client_call; 
	tcpclient_register(hander, &tcpclient_helper);
	tcpclient_recv_start(hander);
	return 0;
}

int online_mddw_push(mddw_dyn_push_t *mddw_dyn_push)
{
	mddw_dyn_push->thrnum = 1;
	return 0;
}
