/*************************************************************************
	> File Name: offline_scan.h
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月04日 星期四 20时22分20秒
 ************************************************************************/

#ifndef __OFFLINE_SCAN_H__
#define __OFFLINE_SCAN_H__

#include "offline.h"
#define   OFFLINE_MAX_THR_NUM       64
#define   OFFLINE_MAX_CHANNEL_NUM        33

#pragma pack (1)

#pragma pack (0)


void offline_scan_start(void *hander);
int comm_rmdircont_operation(const char *dir);
int comm_rmdir_operation(const char *dir);
int comm_mkdirs_operation(const char *dir);
int comm_rename_operation(const char *oldname, char *newname);


#endif
