/*************************************************************************
	> File Name: offline_vshell.h
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月17日 星期三 10时07分33秒
 ************************************************************************/

#ifndef __OFFLINE_VSHELL_H__
#define __OFFLINE_VSHELL_H__
#include "offline.h"

#pragma pack (1)

typedef struct{
	uint32_t countflag;
	uint32_t thr_id;
	uint64_t inpkts;
	uint64_t outpkts;
	uint64_t errpkts;
	uint64_t linpkts;
	uint64_t loutpkts;
	uint64_t lerrpkts;
	uint64_t inbytes;
	uint64_t outbytes;
	uint64_t errbytes;
	uint64_t linbytes;
	uint64_t loutbytes;
	uint64_t lerrbytes;
	uint64_t ljiffies;
	uint64_t infiles;
	uint64_t outfiles;
	uint64_t errfiles;
	char     nowfilename[OFFLINE_MAX_NAME_LEN];

	uint64_t inpktsf;
	uint64_t outpktsf;
	uint64_t errpktsf;
	uint64_t inbytesf;
	uint64_t outbytesf;
	uint64_t errbytesf;
	uint64_t djiffiesf;
	uint64_t sjiffiesf;
}offline_vshell_count_t;
	


typedef struct{
	offline_vshell_count_t offline_count[OFFLINE_MAX_CHANNEL_NUM];
}offline_vshell_gcount_t;

#pragma pack (0)






#endif

