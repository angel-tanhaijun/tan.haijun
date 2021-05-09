/*************************************************************************
	> File Name: offline.h
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月01日 星期一 09时55分16秒
 ************************************************************************/

#ifndef __OFFLINE_H__
#define __OFFLINE_H__

#define _GNU_SOURCE

#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <dirent.h>
#include <time.h>
#include <dlfcn.h>
#include <pthread.h>

#define OFFLINE_MAX_PATH_LEN       300

#include "offline_diy.h"
#include "vshell.h"
#include "minihash.0.9.h"
#include "capture.h"
#include "firebird_cache.h"
#include "lla.h"
#include "online.h"
#include "offline_dataproc.h"
#include "memory_pool.h"
#include "firebird_flowstat.h"
#include "zlog.h"
#include "firebird_iphc.h"
#include "tcpsend.h"
#include "offline_define_log.h"
#include "offline_scan.h"
#include "offline_comm.h"
#include "xmlcfg.h"
#include "jiffies.h"
#include "offline_vshell.h"
#include "offline_status.h"

#define OFFLINE_SWITCH_OPEN           1
#define OFFLINE_SWITCH_CLOSE          0

#define  OFFLINE_DATA_DEFAULT_MAX_LEN       (5 * 1024 * 1024)
#pragma pack (1)

typedef struct{
	uint32_t offline_mode;
	uint32_t vshell_port;
	char     scan_path[OFFLINE_MAX_PATH_LEN];
	uint32_t channel_num;
	uint32_t thr_num;
	uint32_t ex_thr_num;
	uint32_t rep_switch;
	uint32_t rep_timep;   //状态上报时间间隔,针对进度信息,单位秒
	uint32_t rep_timec;   //状态上报时间间隔,针对通道信息，单位秒
	char     rep_path[OFFLINE_MAX_PATH_LEN];
	char     link_conn_path[OFFLINE_MAX_PATH_LEN];
	char     m2_conn_path[OFFLINE_MAX_PATH_LEN];
	char     dis_conn_path[OFFLINE_MAX_PATH_LEN];
	char     pv_conn_path[OFFLINE_MAX_PATH_LEN];
	uint32_t diy_lib_switch;
	char     diy_lib_path[OFFLINE_MAX_PATH_LEN];
	uint32_t online_conn_swicth;
	char     online_conn_path[OFFLINE_MAX_PATH_LEN];
	uint32_t max_cache_len;
	char     downpath[OFFLINE_MAX_PATH_LEN];
	uint32_t downswitch;
	uint32_t pcapsize;
	uint32_t mddw_dyn_switch;
	char     mddw_dyn_path[OFFLINE_MAX_PATH_LEN];
	char     downlnwpath[OFFLINE_MAX_PATH_LEN];
	uint32_t downlnwswitch;
	uint32_t lnwsize;
}offline_init_t;


#pragma pack (0)



void *offline_scan_init(offline_init_t *offinit, int thr_num, uint32_t channel_num);
void offline_link_network_proc(uint8_t *data, uint32_t datalen, offline_dataproc_info_t *pdataproc, int thr_id);
int offline_link_init(uint32_t diy_switch, char *diy_path, uint32_t max_cache_len, uint32_t g_offline_link_bucket, uint32_t g_offline_link_node, int thr_num, int exthrnum);
void offline_link_proc(offline_dataproc_extra_t *pextra, offline_dataproc_info_t *dataproc, int thr_id);
void *offline_init(char *offline_cfg);
void offline_status_get(offline_vshell_count_t *poffline_count, uint32_t channel, char *sessid, char *file_type, char *filename, char *err_info, uint32_t proc_type, uint32_t status_type, offline_status_ex_t *status_ex, int thr_id);

void offline_down_network_info_set(offline_init_t *offinit);
void offline_down_pcap_info_set(offline_init_t *offinit);
void online_mddw_init(online_mddw_load_t *online_mddw, int min_thrid, int max_thrid);
uint32_t offline_get_max_thr_num();
void *online_init(offline_init_t *offinit);
#endif

