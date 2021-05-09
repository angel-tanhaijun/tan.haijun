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

#define MDDW_MAX_CONF_NUM       64
#define MDDW_DVB_DRIV_TYPE      0
#define MDDW_DVB_PASS_TYPE      1
#define MDDW_OFDM_DRIV_TYPE      2
#define MDDW_OFDM_PASS_TYPE      3

#pragma pack (1)
typedef struct{
	int      LineID;
	char     DeviceID[MDDW_MAX_BUFF_LEN];
	char     ProtoType[MDDW_MAX_BUFF_LEN];
	char     IPAddr[MDDW_MAX_BUFF_LEN];
	uint16_t Port;
	int      DataRevType;
	int      Sta;
	int      Stat_ID;
	char     Stat_Sig_Type[MDDW_MAX_BUFF_LEN];
	float    Stat_Freq;
	float    Stat_Width;
	char     Stat_Band[MDDW_MAX_BUFF_LEN];
	char     Stat_Pol[MDDW_MAX_BUFF_LEN];
}LineConfig_t;

typedef struct{
	uint32_t      ServiceId;
	uint32_t      LineConfigNum;
	LineConfig_t  LineConfig[MDDW_MAX_CONF_NUM]; 	
}mddw_json_conf_t;

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

static int mddw_conf_init(mddw_json_conf_t *mddw_json, char *json)
{
	int i = 0;
	cJSON    *root = NULL;
	root = cJSON_Parse(json);
	if(NULL == root)
	{
		printf("load %s fail [%s-%s-%d]\n", json, __FILE__, __func__, __LINE__);
		exit(0);
	}
	cJSON *item_si = cJSON_GetObjectItem(root, "ServiceId");
	if(NULL == item_si)
	{
		printf("load %s fail [%s-%s-%d]\n", "ServiceId", __FILE__, __func__, __LINE__);
		exit(0);;
	}
	mddw_json->ServiceId = (uint32_t )item_si->valueint;	
	cJSON *item_lc = cJSON_GetObjectItem(root, "LineConfig");
	if(NULL == item_lc)
	{
		printf("load %s fail [%s-%s-%d]\n", "LineConfig", __FILE__, __func__, __LINE__);
		exit(0);
	}
	if(cJSON_GetArraySize(item_lc) > MDDW_MAX_CONF_NUM)
	{
		printf("we only support %d channel [%s-%s-%d]\n", MDDW_MAX_CONF_NUM, __FILE__, __func__, __LINE__);
		exit(0);
	}
	mddw_json->LineConfigNum = 0;	
	for(i = 0;i < cJSON_GetArraySize(item_lc); i++)
	{
		cJSON *item_lc_arr = cJSON_GetArrayItem(item_lc, i);
		if(NULL == item_lc_arr)
		{
			printf("load %s fail [%s-%s-%d]\n", "LineConfig", __FILE__, __func__, __LINE__);
			exit(0);
		}
		cJSON *item_li = cJSON_GetObjectItem(item_lc_arr, "LineID");
		if(NULL == item_li)
		{
			printf("load LineConfig[%d] %s fail [%s-%s-%d]\n", i, "LineID", __FILE__, __func__, __LINE__);
			exit(0);
		}
		mddw_json->LineConfig[i].LineID = (int )item_li->valueint;
		cJSON *item_di = cJSON_GetObjectItem(item_lc_arr, "DeviceID");
		if(NULL == item_di)
		{
			printf("load LineConfig[%d] %s fail [%s-%s-%d]\n", i, "DeviceID", __FILE__, __func__, __LINE__);
			exit(0);
		}
		snprintf(mddw_json->LineConfig[i].DeviceID, MDDW_MAX_BUFF_LEN, "%s", item_di->valuestring);
		cJSON *item_pt = cJSON_GetObjectItem(item_lc_arr, "ProtoType");
		if(NULL == item_pt)
		{
			printf("load LineConfig[%d] %s fail [%s-%s-%d]\n", i, "ProtoType", __FILE__, __func__, __LINE__);
			exit(0);
		}	
		snprintf(mddw_json->LineConfig[i].ProtoType, MDDW_MAX_BUFF_LEN, "%s", item_pt->valuestring);
		cJSON *item_ia = cJSON_GetObjectItem(item_lc_arr, "IPAddr");
		if(NULL == item_ia)
		{
			printf("load LineConfig[%d] %s fail [%s-%s-%d]\n", i, "IPAddr", __FILE__, __func__, __LINE__);
			exit(0);
		}	
		snprintf(mddw_json->LineConfig[i].IPAddr, MDDW_MAX_BUFF_LEN, "%s", item_ia->valuestring);
		cJSON *item_p = cJSON_GetObjectItem(item_lc_arr, "Port");
		if(NULL == item_p)
		{
			printf("load LineConfig[%d] %s fail [%s-%s-%d]\n", i, "Port", __FILE__, __func__, __LINE__);
			exit(0);
		}	
		mddw_json->LineConfig[i].Port = (uint16_t)item_p->valueint; 
		cJSON *item_drt = cJSON_GetObjectItem(item_lc_arr, "DataRevType");
		if(NULL == item_drt)
		{
			printf("load LineConfig[%d] %s fail [%s-%s-%d]\n", i, "DataRevType", __FILE__, __func__, __LINE__);
			exit(0);
		}	
		mddw_json->LineConfig[i].DataRevType = (int)item_drt->valueint;
		cJSON *item_s = cJSON_GetObjectItem(item_lc_arr, "Sta");
		if(NULL == item_s)
		{
			printf("load LineConfig[%d] %s fail [%s-%s-%d]\n", i, "Sta", __FILE__, __func__, __LINE__);
			exit(0);
		}	
		mddw_json->LineConfig[i].Sta = (int)item_s->valueint;
		cJSON *item_sd = cJSON_GetObjectItem(item_lc_arr, "Stat_ID");
		if(NULL == item_sd)
		{
			printf("load LineConfig[%d] %s fail [%s-%s-%d]\n", i, "Stat_ID", __FILE__, __func__, __LINE__);
			exit(0);
		}	
		mddw_json->LineConfig[i].Stat_ID = (int)item_sd->valueint; 
		cJSON *item_sst = cJSON_GetObjectItem(item_lc_arr, "Stat_Sig_Type");
		if(NULL == item_sst)
		{
			printf("load LineConfig[%d] %s fail [%s-%s-%d]\n", i, "Stat_Sig_Type", __FILE__, __func__, __LINE__);
			exit(0);
		}	
		snprintf(mddw_json->LineConfig[i].Stat_Sig_Type, MDDW_MAX_BUFF_LEN, "%s",  item_sst->valuestring);
		cJSON *item_sf = cJSON_GetObjectItem(item_lc_arr, "Stat_Freq");
		if(NULL == item_sf)
		{
			printf("load LineConfig[%d] %s fail [%s-%s-%d]\n", i, "Stat_Freq", __FILE__, __func__, __LINE__);
			exit(0);
		}
		mddw_json->LineConfig[i].Stat_Freq = (float)item_sf->valuedouble;
		cJSON *item_sw = cJSON_GetObjectItem(item_lc_arr, "Stat_Width");
		if(NULL == item_sw)
		{
			printf("load LineConfig[%d] %s fail [%s-%s-%d]\n", i, "Stat_Width", __FILE__, __func__, __LINE__);
			exit(0);
		}	
		mddw_json->LineConfig[i].Stat_Width = (float)item_sw->valuedouble;
		cJSON *item_sb = cJSON_GetObjectItem(item_lc_arr, "Stat_Band");
		if(NULL == item_sb)
		{
			printf("load LineConfig[%d] %s fail [%s-%s-%d]\n", i, "Stat_Band", __FILE__, __func__, __LINE__);
			exit(0);
		}	
		snprintf(mddw_json->LineConfig[i].Stat_Band, MDDW_MAX_BUFF_LEN, "%s",  item_sb->valuestring);
		cJSON *item_sp = cJSON_GetObjectItem(item_lc_arr, "Stat_Pol");
		if(NULL == item_sp)
		{
			printf("load LineConfig[%d] %s fail [%s-%s-%d]\n", i, "Stat_Pol", __FILE__, __func__, __LINE__);
			exit(0);
		}	
		snprintf(mddw_json->LineConfig[i].Stat_Pol, MDDW_MAX_BUFF_LEN, "%s",  item_sp->valuestring);
		mddw_json->LineConfigNum++;
	}

	cJSON_Delete(root);
	return 0;
}
static int mddw_read_json(mddw_json_conf_t *mddw_json, char *filename)
{
	char *buff = NULL;
	uint32_t bufflen = 0;
	FILE *fp = fopen(filename, "r+");
	if(fp == NULL)
	{
		printf("fopen %s fail [%s-%s-%d]\n", filename, __FILE__, __func__, __LINE__);
		exit(0);
	}
	fseek(fp, 0L, SEEK_END);		
	bufflen = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	buff = (char *)malloc(bufflen);
	fread(buff, bufflen, 1, fp);
	mddw_conf_init(mddw_json, buff);
	fclose(fp);
	free(buff);
	return 0;
}

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

static int mddw_set_conf_exc(int type, LineConfig_t *LineConfig)
{
	mddw_gsc[type].mddw_sc[mddw_gsc[type].mddw_sc_num].channel = LineConfig->LineID;
	mddw_gsc[type].mddw_sc[mddw_gsc[type].mddw_sc_num].port = LineConfig->Port;
	snprintf(mddw_gsc[type].mddw_sc[mddw_gsc[type].mddw_sc_num].ip, MDDW_MAX_BUFF_LEN, "%s", LineConfig->IPAddr);
	mddw_gsc[type].mddw_sc[mddw_gsc[type].mddw_sc_num].Stat_ID = LineConfig->Stat_ID;
	memcpy(mddw_gsc[type].mddw_sc[mddw_gsc[type].mddw_sc_num].Stat_Sig_Type, LineConfig->Stat_Sig_Type, 16);
	mddw_gsc[type].mddw_sc[mddw_gsc[type].mddw_sc_num].Stat_Freq = LineConfig->Stat_Freq;
	mddw_gsc[type].mddw_sc[mddw_gsc[type].mddw_sc_num].Stat_Width = LineConfig->Stat_Width;
	memcpy(mddw_gsc[type].mddw_sc[mddw_gsc[type].mddw_sc_num].Stat_Band, LineConfig->Stat_Band, 2);
	memcpy(mddw_gsc[type].mddw_sc[mddw_gsc[type].mddw_sc_num].Stat_Pol, LineConfig->Stat_Pol, 1);	
	mddw_gsc[type].mddw_sc_num++;
	return 0;
}

static int mddw_set_conf(mddw_json_conf_t *mddw_json)
{
	int i = 0;
	for(i = 0; i < mddw_json->LineConfigNum; i++)
	{
		printf("Sta:%d; DeviceID:%s; DataRevType:%d; LineID:%d; IPAddr%s; Port:%d; ProtoType:%s\n", mddw_json->LineConfig[i].Sta, mddw_json->LineConfig[i].DeviceID, mddw_json->LineConfig[i].DataRevType, mddw_json->LineConfig[i].LineID, mddw_json->LineConfig[i].IPAddr, mddw_json->LineConfig[i].Port, mddw_json->LineConfig[i].ProtoType);
		if(mddw_json->LineConfig[i].Sta == 1)
		{
			continue;
		}
#if 0
		if(strncmp(mddw_json->LineConfig[i].DeviceID, "DVB", strlen("DVB")) == 0 && mddw_json->LineConfig[i].DataRevType == 0 && strncmp(mddw_json->LineConfig[i].ProtoType, "udp") == 0)
		{
			mddw_set_conf_exc(MDDW_DVB_DRIV_TYPE, &mddw_json->LineConfig[i]);
		}
#endif
		if(strncmp(mddw_json->LineConfig[i].DeviceID, "DVB", strlen("DVB")) == 0 && mddw_json->LineConfig[i].DataRevType == 1 && strncmp(mddw_json->LineConfig[i].ProtoType, "udp", strlen("udp")) == 0)
		{
			 mddw_set_conf_exc(MDDW_DVB_PASS_TYPE, &mddw_json->LineConfig[i]);
		}
		else if(strncmp(mddw_json->LineConfig[i].DeviceID, "OFDM", strlen("OFDM")) == 0 && mddw_json->LineConfig[i].DataRevType == 0 && strncmp(mddw_json->LineConfig[i].ProtoType, "tcp", strlen("tcp")) == 0)
		{
			 mddw_set_conf_exc(MDDW_OFDM_DRIV_TYPE, &mddw_json->LineConfig[i]);
		}
#if 0
		if(strncmp(mddw_json->LineConfig[i].DeviceID, "OFDM", strlen("OFDM")) == 0 && mddw_json->LineConfig[i].DataRevType == 1)
		{
			mddw_set_conf_exc(MDDW_OFDM_PASS_TYPE, &mddw_json->LineConfig[i]);
		}
#endif
	}	
	return 0;
}


int mddw_init(mddw_init_t *mddw_init, online_helper_t *online)
{
	mddw_json_conf_t mddw_json;
	memset(&mddw_json, 0, sizeof(mddw_json_conf_t));
	mddw_read_json(&mddw_json, "./lineconf.json");
	mddw_set_conf(&mddw_json);	
	mddw_dyn_push_t mddw_dyn_push;
	memset(&mddw_dyn_push, 0, sizeof(mddw_dyn_push_t));
	mddw_dyn_init_t mddw_dyn_init;
	memset(&mddw_dyn_init, 0, sizeof(mddw_dyn_init));
	int ret = 0, i= 0, j = 0;

#if 1
	online_dyn_load_t *dyn_ofdm_d = (online_dyn_load_t *)online_mddw_load("../mddw_dyn/libndci.so");	
	if(dyn_ofdm_d == NULL)
	{
		printf("online_mddw_load dyn_ofdm_d fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
	//	exit(0);
	}
	else
	{
		dyn_ofdm_d->online_register(online);
		dyn_ofdm_d->online_mddw_push(&mddw_dyn_push);
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
		dyn_ofdm_d->online_mddw_init(&mddw_dyn_init, &mddw_gsc[MDDW_OFDM_DRIV_TYPE]);
	}
#endif
	memset(&mddw_dyn_init, 0, sizeof(mddw_dyn_init));
	online_dyn_load_t *dyn_dvb_p = (online_dyn_load_t *)online_mddw_load("../mddw_dyn/librdvb.so");	
	if(dyn_dvb_p == NULL)
	{
		printf("online_mddw_load dyn_dvb_p fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
	//	exit(0);
	}
	else
	{
		dyn_dvb_p->online_register(online);
		dyn_dvb_p->online_mddw_push(&mddw_dyn_push);                                   
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
		dyn_dvb_p->online_mddw_init(&mddw_dyn_init, &mddw_gsc[MDDW_DVB_PASS_TYPE]);
	}
#if 0
	online_dyn_load_t *dyn_ofdm_p = (online_dyn_load_t *)online_mddw_load("../mddw_dyn/librndci.so");	
	if(dyn_ofdm_p == NULL)
	{
		printf("online_mddw_load dyn_ofdm_p fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
	//	exit(0);
	}
	else
	{
		dyn_ofdm_p->online_register(online);
		dyn_ofdm_p->online_mddw_init(mddw_init->thr_id[1], &mddw_gsc[MDDW_OFDM_PASS_TYPE]);
	}
	online_dyn_load_t *dyn_dvb_d = (online_dyn_load_t *)online_mddw_load("../mddw_dyn/libdvb.so");	
	if(dyn_dvb_d == NULL)
	{
		printf("online_mddw_load dyn_dvb_d fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
	//	exit(0);
	}
	else
	{
		dyn_dvb_d->online_register(online);
		dyn_dvb_d->online_mddw_init(mddw_init->thr_id[2], &mddw_gsc[MDDW_DVB_DRIV_TYPE]);
	}
#endif
	return 0;
}

int mddw_push_info(mddw_push_t *mddw_push)
{
	mddw_push->thr_num = 32;
	return 0;
}

