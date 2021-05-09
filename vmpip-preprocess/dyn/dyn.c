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
#include "SoftBus.h"
#define     DYN_MAX_USER_NUM        4

#define datatype_ip             0x01
#define datatype_eth            0x08
#define datatype_not_ip         0x20
#define pcapName "/home/tan.haijun/workbench/nca/pcap/sip/sip/sdp.pcap"
static char *libinfo __attribute__((unused))  = "\n@VERSION@:dyn, 1.0.0, "VERSION"\n" ;

static online_helper_t g_online_helper[DYN_MAX_USER_NUM];
static int g_online_helper_num = 0;
static int fixthr_id[DYN_MAX_USER_NUM];
static uint32_t  fixchannel[DYN_MAX_USER_NUM];
static int g_online_num = 0;

static int do_online_helper(online_fb_t *fb, uint8_t *data, uint32_t datalen)                      
{   

	void *user_data[DYN_MAX_USER_NUM];                                                           
	int no = 0;     
	int iret = -1; 
	if(fb == NULL || data == NULL || datalen <= 0)
		goto exit;
	iret = g_online_helper[no].onlineip_entry(NULL, fb, data, datalen, datatype_ip, fixchannel[no], fixthr_id[no], NULL); 
exit:    
	return iret;
}

static void pcap_read_proc(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *pktset)
{
	char *user = "hello world!";
	online_fb_t fb;
	memset(&fb, 0, sizeof(online_fb_t));
	snprintf(fb.sessId, sizeof(fb.sessId), "%s%u", "ott_", fixchannel[0]);
	fb.sessIdLen = strlen(fb.sessId);
	fb.capTimeStamp = ((pkthdr->ts.tv_sec * 1000) + (pkthdr->ts.tv_usec / 1000));
	fb.analysisTimeStamp = jiffies;
	fb.userInfoLen = strlen(user);
	fb.userInfoType = 0x10005004;
	fb.userInfo = (uint8_t *)malloc(fb.userInfoLen);
	memcpy((char *)fb.userInfo, user, fb.userInfoLen);
	fb.IPOffset = 0;
	do_online_helper(&fb, (uint8_t *)pktset + 14, pkthdr->caplen - 14);
	free(fb.userInfo);	
}


static void *pcap_info_get(void *ele)
{
	pcap_t   *pfile_read;
	char eBuf[1024];
	pfile_read = pcap_open_offline(pcapName, eBuf);
	if(!pfile_read)
	{
		printf("pcap_open_offine(%s) error!\n", pcapName);
		return NULL;
	}
	pcap_loop(pfile_read, -1, pcap_read_proc, NULL);
	return NULL;
}	
static REGINFO reginfo={0};
static void* init_cb_func (const BUSDATAIDENT stDataIdent,  const int iLen,  const  BYTE*  pbyData)
{
	return NULL;
}

static int init_soft_line()
{
	int i=0;
	int ret;
	reginfo.iAppEntityNo=20001;
	reginfo.iSlotNum=1;
	reginfo.OnRecvData=(CallBackFunc)init_cb_func;

	for(i=0;i<reginfo.iSlotNum;i++)
	{
		reginfo.arSlotGroup[i].iSlotType=1;
		reginfo.arSlotGroup[i].iFootNum=1;

		reginfo.arSlotGroup[i].arFoot[0][0]=1; //引脚序号
		reginfo.arSlotGroup[i].arFoot[0][1]=2; //引脚类型 1,发送引脚 2,接收引脚
		reginfo.arSlotGroup[i].arFoot[0][2]=1; //引脚优先级
	}
	ret = RegBus(reginfo);
	if(ret != 1)
	{
		printf("reg softline error! ret:%d\n",ret);
		fprintf(stderr,"reg softline error! ret:%d\n",ret);
		exit(0);
	}

	printf("softline reg success!\n");

	return 0;
}

extern "C"
{
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
	int online_init(uint32_t channel, int thr_id)
	{
		fixchannel[g_online_num] = channel;  
		fixthr_id[g_online_num]  = thr_id; //只能用初始化时使用的通道和线程号
		g_online_num++;
		pthread_t pid;
		//init_soft_line(); //软件总线初始化
#if 1
		int ret = pthread_create(&pid, NULL, pcap_info_get, NULL);
		if(ret != 0)
		{
			printf("dyn_user_init_helper fail\n");
			return -1;
		}
#endif
		return 0;
	}
}
