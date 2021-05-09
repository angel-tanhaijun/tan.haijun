/*************************************************************************
	> File Name: online.c
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月20日 星期六 16时52分35秒
 ************************************************************************/

#include "offline.h"

void *online_mddw_load(char *mdww_name)
{
	printf("load %s start [%s-%s-%d]\n", mdww_name, __FILE__, __func__, __LINE__);
	online_mddw_load_t *online_mddw = malloc(sizeof(online_mddw_load_t));
	void *mdww_load_ptr = dlopen(mdww_name, RTLD_LAZY);
	if(!mdww_load_ptr)
	{
		printf("dlopen %s fail [%s-%s-%d]\n", mdww_name, __FILE__, __func__, __LINE__);
		return NULL;
	}
	online_mddw->mddw_push_info = (mddw_push_info_helper *)dlsym(mdww_load_ptr, "mddw_push_info");
	if(!online_mddw->mddw_push_info)
	{
		printf("dlsym mddw_push_info fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		return NULL;
	}
	online_mddw->mddw_init = (mddw_init_helper *)dlsym(mdww_load_ptr, "mddw_init");
	if(!online_mddw->mddw_init)
	{
		printf("dlsym mddw_init fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		return NULL;
	}
	printf("load %s end [%s-%s-%d]\n", mdww_name, __FILE__, __func__, __LINE__);
	return (void *)online_mddw;
}

void online_dyn_load(online_info_t *oninfo, int thr_id)
{
	printf("load %s start [%s-%s-%d]\n", oninfo->dyn_name, __FILE__, __func__, __LINE__);
	online_dyn_load_t *dyn_load = (online_dyn_load_t *)malloc(sizeof(online_dyn_load_t));
	void *dyn_load_ptr = dlopen(oninfo->dyn_name, RTLD_LAZY);
	if(!dyn_load_ptr)
	{
		printf("dlopen %s fail [%s-%s-%d]\n", oninfo->dyn_name, __FILE__, __func__, __LINE__);
		goto leave;
	}
	dyn_load->online_init = (online_init_helper *)dlsym(dyn_load_ptr, "online_init");
	if(!dyn_load->online_init)
	{
		printf("dlsym online_init fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		goto leave;
	}	
	dyn_load->online_register = (online_register_helper *)dlsym(dyn_load_ptr, "online_register");
	if(!dyn_load->online_register)
	{
		printf("dlsym online_register fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		goto leave;
	}
	dyn_load->dyn_channel = oninfo->dyn_channel;
	dyn_load->thr_id      = thr_id;
	online_start(dyn_load);
	return;
leave:
	free(dyn_load);
	return;
}	

void online_mddw_init(online_mddw_load_t *online_mddw, int min_thrid, int max_thrid)
{
	int i = 0;
	online_helper_t online;
	mddw_init_t mddw_init;
	memset(&mddw_init, 0, sizeof(mddw_init_t));

	online_mddw_start(&online);
	for(i = min_thrid; i < max_thrid; i++)
	{
		mddw_init.thr_id[mddw_init.thrnum] = i;
		mddw_init.thrnum++;	
	}
	online_mddw->mddw_init(&mddw_init, &online);
	return ;
}

void *online_init(offline_init_t *offinit)
{
	if(offinit->online_conn_swicth == OFFLINE_SWITCH_CLOSE)
		return NULL;
	printf("load %s [%s-%s-%d]\n", offinit->online_conn_path, __FILE__, __func__, __LINE__);	
	xmlcfg_t tc;
	xmlcfg_list_t dynlist;
	int err, i;
	char xpath[255];
	long v;
	int thr_num	 = offinit->thr_num;
	online_ginfo_t *goninfo = NULL;
	goninfo = (online_ginfo_t *)malloc(sizeof(online_ginfo_t));
	assert(goninfo);
	memset(goninfo, 0, sizeof(online_ginfo_t));
	online_info_t *poninfo = NULL;

	if (xmlcfg_init_file(&tc, offinit->online_conn_path) != 0)
	{
		printf("load %s fail\n", offinit->online_conn_path);
		exit(0);
	}
	snprintf(xpath, 255, "/conf/dyn_info");
	err = xmlcfg_get_list(&tc, xpath, &dynlist);
	if (err)
	{
		printf("load %s failed\n", xpath);
		exit(0);
	}
	for(i = 0; i < xmlcfg_list_length(&dynlist); i++)
	{
		online_info_t *oninfo = malloc(sizeof(online_info_t));
		assert(oninfo);
		memset(oninfo, 0, sizeof(online_info_t));
		snprintf(xpath, 255, "/conf/dyn_info[%d]/dyn_path", i + 1);
		err = xmlcfg_get_str(&tc, xpath, oninfo->dyn_name, OFFLINE_MAX_PATH_LEN);
		if (err < 1)
		{
			printf("load %s fail\n", xpath);
			exit(0);
		}
		snprintf(xpath, 255, "/conf/dyn_info[%d]/dyn_channel", i + 1);
		err = xmlcfg_get_long(&tc, xpath, &v);
		if(err)
		{
			printf("load %s fail\n", xpath);
			exit(0); 
		}
		oninfo->dyn_channel = v;
		oninfo->dyn_thrid   = thr_num;
		oninfo->next        = NULL;
		if(goninfo->oninfo == NULL)
		{
			goninfo->oninfo = oninfo;
			poninfo = oninfo;
			poninfo->next = NULL;
		}
		else
		{
			poninfo->next = (void *)oninfo;
			poninfo = oninfo;
			poninfo->next = NULL;
		}
//		online_dyn_load(oninfo, thr_num);	
		thr_num++;
	}
	err = xmlcfg_list_free(&dynlist);
	if(err)
	{
		printf("xmlcfg_list_free error [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		exit(0);
	}
	err = xmlcfg_close(&tc);
	if(err)                                                                         
	{                                                                               
		printf("xmlcfg_close error [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		exit(0);                                                                    
	}                           
	goninfo->exthrnum = i;	
	return (void *)goninfo;
}

