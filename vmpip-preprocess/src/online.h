/*************************************************************************
	> File Name: online.h
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月20日 星期六 17时00分07秒
 ************************************************************************/


#ifndef __ONLINE_H__
#define __ONLINE_H__
#include "offline.h"
#include "dyn.h"
#include "mddw.h"

typedef int online_init_helper(int thr_id, uint32_t channel);
typedef int online_register_helper(online_helper_t *online_helper);
typedef int online_mddw_init_helper(int thr_id, mddw_gsc_info_t *mddw_gsc);

typedef int mddw_init_helper(mddw_init_t *mddw_init, online_helper_t *online);
typedef int mddw_push_info_helper(mddw_push_t *mddw_push);

#pragma pack (1)
typedef struct{
	char       dyn_name[OFFLINE_MAX_PATH_LEN];
	uint32_t   dyn_channel;
	int        dyn_thrid;
	void       *next;
}online_info_t;

typedef struct{
	uint32_t       exthrnum;
	online_info_t *oninfo;
}online_ginfo_t;

typedef struct{
	online_init_helper      *online_init;
	online_mddw_init_helper *online_mddw_init;
	online_register_helper  *online_register;
	uint32_t                dyn_channel;
	int                     thr_id;
}online_dyn_load_t;

typedef struct{
	mddw_push_info_helper *mddw_push_info;
	mddw_init_helper      *mddw_init;	
}online_mddw_load_t;

#pragma pack (0)
void online_dyn_load(online_info_t *oninfo, int thr_id);
void *online_mddw_load(char *mdww_name);

#endif
