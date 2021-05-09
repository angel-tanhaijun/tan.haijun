/*************************************************************************
	> File Name: offline_diy.h
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月19日 星期五 09时31分35秒
 ************************************************************************/

#ifndef __OFFLINE_DIY_H__
#define __OFFLINE_DIY_H__




#pragma pack (1)

typedef int offline_diy_gain_helper(void *session,char *filename, uint32_t filetype, void *ele, int thr_id, void **user_data);

typedef int offline_diy_entry_helper(void *session, uint8_t *data, uint32_t datalen, uint32_t datatype, uint8_t *userinfo, uint32_t userinfolen, uint32_t userinfotype, void *ele, int thr_id, void **user_data);

typedef struct{
	offline_diy_entry_helper *diy_entry;
}diy_helper_t;

typedef int offline_diy_init_helper(int thr_num);
typedef int offline_diy_register_helper(diy_helper_t *diy_helper);

typedef struct{
	uint32_t                     canflag;   //动态库是否可以的标识，0代表可用
	offline_diy_init_helper      *diy_init;
	offline_diy_gain_helper      *diy_gain;
	offline_diy_register_helper  *diy_register;
}offline_diy_helper_t;

#pragma pack (0)

int offline_diy_load(offline_diy_helper_t *diy_helper, char *libname);

#endif
