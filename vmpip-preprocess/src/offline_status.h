/*************************************************************************
	> File Name: offline_status.h
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月10日 星期三 15时46分35秒
 ************************************************************************/
#ifndef __OFFLINE_STATUS_H__
#define __OFFLINE_STATUS_H__
#include "offline.h"

#define OFFLINE_STATUS_PROC_PROG_TYPE     1
#define OFFLINE_STATUS_NOTF_MESS_TYPE     2
#define OFFLINE_STATUS_ERRO_MESS_TYPE     3
#define OFFLINE_STATUS_CAHN_STAT_TYPE     4
#define OFFLINE_PROC_START_TYPE           1
#define OFFLINE_PROC_END_TYPE             2
#define OFFLINE_MAX_BUFF_LEN              512

#pragma pack (1)
typedef struct{
	uint32_t channel;
	uint32_t status_type;
	uint32_t proc_type;
	uint32_t rep_switch;
	char     sessid[OFFLINE_SESSID_LEN];
	char     file_type[OFFLINE_MAX_BUFF_LEN];
	char     err_info[OFFLINE_MAX_BUFF_LEN];
	char     file_name[OFFLINE_MAX_BUFF_LEN];
	char     rep_path[OFFLINE_MAX_PATH_LEN]; 	
	char     clientip[OFFLINE_CLIENTIP_LEN];
	offline_vshell_count_t offline_count;
}offline_status_t;

typedef struct{
	char clientip[OFFLINE_CLIENTIP_LEN];
}offline_status_ex_t;

#pragma pack (0)

void offline_status_getp2(offline_status_t *pstatus, int thr_id);
void offline_status_init(int thr_num);

#endif

