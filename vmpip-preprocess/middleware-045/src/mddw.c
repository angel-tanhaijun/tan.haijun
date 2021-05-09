/*************************************************************************
	> File Name: mddw.c
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年08月25日 星期二 11时21分26秒
 ************************************************************************/

#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <dlfcn.h>
#include <assert.h>
#include "dyn.h"
#include "mddw.h"
#include "cJSON.h"
#include "xmlcfg.h"

#define MDDW_MAX_CONF_NUM       64
#define MDDW_DVB_DRIV_TYPE      0
#define MDDW_DVB_PASS_TYPE      1
#define MDDW_OFDM_DRIV_TYPE      2
#define MDDW_OFDM_PASS_TYPE      3

#pragma pack (1)
typedef struct{
	uint16_t port;
}udp_recv_info_t;

typedef struct{
	uint32_t        udp_recv_num;
	udp_recv_info_t udp_recv[MDDW_MAX_CONF_NUM];
}mddw_xml_conf_t;

typedef int online_register_helper(online_helper_t *online_helper);
typedef int online_mddw_init_helper(mddw_dyn_init_t *mddw_dyn_init, mddw_gsc_info_t *mddw_gsc);
typedef int online_mddw_push_helper(mddw_dyn_push_t *mddw_dyn_push);

typedef int mddw_init_helper(mddw_init_t *mddw_init, online_helper_t *online);
typedef int mddw_push_info_helper(mddw_push_t *mddw_push);

typedef struct{
	online_mddw_init_helper *online_mddw_init;
	online_register_helper  *online_register;
	online_mddw_push_helper *online_mddw_push;
}online_dyn_load_t;


#pragma pack (0)
static char *libinfo __attribute__((unused))  = "\n@VERSION@:libmddw, 1.0.0, "VERSION"\n" ;

static mddw_gsc_info_t mddw_gsc[4];

static void *online_mddw_load(char *dyn_name)
{
	printf("load %s start [%s-%s-%d]\n", dyn_name, __FILE__, __func__, __LINE__);
	online_dyn_load_t *dyn_load = (online_dyn_load_t *)malloc(sizeof(online_dyn_load_t));
	void *dyn_load_ptr = dlopen(dyn_name, RTLD_LAZY);
	if(!dyn_load_ptr)
	{
		printf("dlopen %s fail [%s-%s-%d]\n", dyn_name, __FILE__, __func__, __LINE__);
		goto leave;
	}
	dyn_load->online_mddw_push = (online_mddw_push_helper *)dlsym(dyn_load_ptr, "online_mddw_push");
	if(!dyn_load->online_mddw_push)
	{
		printf("dlsym online_mddw_push fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		goto leave;
	}   
	dyn_load->online_mddw_init = (online_mddw_init_helper *)dlsym(dyn_load_ptr, "online_mddw_init");
	if(!dyn_load->online_mddw_init)
	{
		printf("dlsym online_mddw_init fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		goto leave;
	}   
	dyn_load->online_register = (online_register_helper *)dlsym(dyn_load_ptr, "online_register");
	if(!dyn_load->online_register)
	{
		printf("dlsym online_register fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		goto leave;
	}
	printf("load %s end [%s-%s-%d]\n", dyn_name, __FILE__, __func__, __LINE__);
	return (void *)dyn_load;
leave:
	printf("online_mddw_load fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
	free(dyn_load);
	//exit(0);
	return NULL;
}   



static void *mddw_read_xml(mddw_xml_conf_t *mddw_xml, char *filename)
{
	int err, i;
	char xpath[255];
	long v;
	xmlcfg_t tc;
	xmlcfg_list_t item_list;
	if (xmlcfg_init_file(&tc, filename) != 0)
	{
		printf("load %s fail\n", filename);
		exit(0);
	}
	snprintf(xpath,255,"/conf/udp_conn");
	err = xmlcfg_get_list(&tc, xpath, &item_list);      
	if (err)                                            
	{                                                   
		printf("load %s(%s) failed\n", filename, xpath);
		exit(0);                                        
	}           
	for(i = 0; i < xmlcfg_list_length(&item_list); i++ )
	{
#if 0
		err = xmlcfg_list_get_str(&item_list, i, "server_ip", serverip, 512);   
		if(err < 1)
		{
			printf("%s ###/config/server_conn[%d]/server_ip failed\n", tcpclient_filename, i);
			exit(0);

		}
#endif
		err = xmlcfg_list_get_long(&item_list, i, "recv_port", &v);
		if(err)
		{
			printf("%s ###/conf/udp_conn[%d]/recv_port failed\n", filename, i);
			exit(0);
		}
		mddw_xml->udp_recv[i].port = v;
		mddw_xml->udp_recv_num++;
	}
	err = xmlcfg_list_free(&item_list);     
	if(err)                                 
	{                                       
		printf("xmlcfg_list_free falied\n");
		exit(0);                            
	}                                       
	err = xmlcfg_close(&tc);                
	if(err)                                 
	{                                       
		printf("xmlcfg_close falied\n");    
		exit(0);                            
	}
	return NULL; 
}

static int mddw_set_xml_conf(mddw_xml_conf_t *mddw_xml)
{
	int i = 0;
	for(i = 0; i < mddw_xml->udp_recv_num; i++)
	{
		mddw_gsc[0].mddw_sc[mddw_gsc[0].mddw_sc_num].port = mddw_xml->udp_recv[i].port;
		mddw_gsc[0].mddw_sc_num++;
	}
	return 0;
}

int mddw_init(mddw_init_t *mddw_init, online_helper_t *online)
{
	mddw_xml_conf_t mddw_xml;
	memset(&mddw_xml, 0, sizeof(mddw_xml_conf_t));
	mddw_read_xml(&mddw_xml, "./mddw_xml_conf.xml");
	mddw_set_xml_conf(&mddw_xml);
	mddw_dyn_push_t mddw_dyn_push;
	memset(&mddw_dyn_push, 0, sizeof(mddw_dyn_push_t));
	mddw_dyn_init_t mddw_dyn_init;
	memset(&mddw_dyn_init, 0, sizeof(mddw_dyn_init));
	int i= 0, j = 0;

	online_dyn_load_t *dyn_hk = (online_dyn_load_t *)online_mddw_load("../mddw_dyn/libhk.so");	
	if(dyn_hk == NULL)
	{
		printf("online_mddw_load ../mddw_dyn/libhk.so fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
	//	exit(0);
	}
	else
	{
		dyn_hk->online_register(online);
		dyn_hk->online_mddw_push(&mddw_dyn_push);
		for(i = 0; i < mddw_dyn_push.thrnum; i++)
		{
			for(j = 0; j < mddw_init->thrnum; j++)
			{
				if(mddw_init->canuse[j] == 0)
				{
					mddw_dyn_init.thr_id[mddw_dyn_init.thrnum] = mddw_init->thr_id[j];
					mddw_dyn_init.thrnum++;
					mddw_init->canuse[j] = 1;
					break;
				}
			}
		}	
		dyn_hk->online_mddw_init(&mddw_dyn_init, &mddw_gsc[0]);
	}
	return 0;
}

int mddw_push_info(mddw_push_t *mddw_push)
{
	mddw_push->thr_num = 4;
	return 0;
}

