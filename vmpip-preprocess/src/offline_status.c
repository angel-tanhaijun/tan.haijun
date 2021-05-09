/*************************************************************************
	> File Name: offline_status.c
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月10日 星期三 15时46分20秒
 ************************************************************************/

#include "offline.h"

#define OFFLINE_STATUS_MAX_CONTENT_LEN              (64 * 1024)

static void   *offline_status_rbq_hand = NULL;
static void offline_status_rep(offline_status_t *pstatus, int thr_id)
{
	char wpath[OFFLINE_MAX_PATH_LEN] = {0};
//	snprintf(wpath, OFFLINE_MAX_PATH_LEN, "%s/%s_%d", pstatus->rep_path, "ott", pstatus->channel);
	snprintf(wpath, OFFLINE_MAX_PATH_LEN, "%s/%s", pstatus->rep_path, pstatus->sessid);
	printf("pstatus->rep_path:%s->%s\n", pstatus->rep_path, wpath);
	if(access(wpath, F_OK) != 0)
	{
		comm_mkdirs_operation(wpath);	
	}	 
	
	time_t ptime;
	struct tm *ptm = NULL;
	time(&ptime);
	ptm = localtime(&ptime);
	char datatime[200] = {0};
	char writepath[OFFLINE_MAX_PATH_LEN] = {0};
	char writecontent[OFFLINE_STATUS_MAX_CONTENT_LEN] = {0};	
	
	snprintf(datatime, 200, "%04d%02d%02d", ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday);
	snprintf(writepath, OFFLINE_MAX_PATH_LEN, "%s/processing_progress_%s.log", wpath, datatime);
	printf("writepath:%s\n", writepath);	
	
	FILE *fp = fopen(writepath,"ab+");
	if(fp == NULL)
	{
		printf("fopen %s error [%s-%s-%d]\n", writepath, __FILE__, __func__, __LINE__);
		return;
	}
	switch(pstatus->status_type)
	{
		case OFFLINE_STATUS_PROC_PROG_TYPE:	
			if(pstatus->proc_type == OFFLINE_PROC_START_TYPE)
				snprintf(writecontent, OFFLINE_STATUS_MAX_CONTENT_LEN, "journal_type:%d;process_state:start;file_type:%s;file_name:%s;client_ip:%s;now_time:%lu;\n", OFFLINE_STATUS_PROC_PROG_TYPE, pstatus->file_type, pstatus->file_name, pstatus->clientip, jiffies);	
			if(pstatus->proc_type == OFFLINE_PROC_END_TYPE)
				snprintf(writecontent, OFFLINE_STATUS_MAX_CONTENT_LEN, 
						"journal_type:%d;process_state:end;file_type:%s;file_name:%s;pkt_num:%lu;all_pkt_len:%lu;in_pkt_num:%lu;in_pkt_len:%lu;client_ip:%s;expend_time:%lu;now_time:%lu;\n", 
						OFFLINE_STATUS_PROC_PROG_TYPE, 
						pstatus->file_type, 
						pstatus->file_name, 
						pstatus->offline_count.outpktsf, 
						pstatus->offline_count.outbytesf, 
						pstatus->offline_count.inpktsf, 
						pstatus->offline_count.inbytesf, 
						pstatus->clientip,
						(jiffies - pstatus->offline_count.sjiffiesf), 
						jiffies);	
			break;
		case OFFLINE_STATUS_NOTF_MESS_TYPE:
			snprintf(writecontent, OFFLINE_STATUS_MAX_CONTENT_LEN, 
					"journal_type:%d;process_state:being_processed;file_type:%s;file_name:%s;already_deal_pkt_num:%lu;already_deal_pkt_len:%lu;in_pkt_num:%lu;in_pkt_len:%lu;client_ip:%s;now_time:%lu;\n", 
					OFFLINE_STATUS_NOTF_MESS_TYPE,
					pstatus->file_type,
					pstatus->file_name,
					pstatus->offline_count.outpktsf,
					pstatus->offline_count.outbytesf,
					pstatus->offline_count.inpktsf,
					pstatus->offline_count.inbytesf,
					pstatus->clientip,
					jiffies);
			break;
		case OFFLINE_STATUS_ERRO_MESS_TYPE:
				snprintf(writecontent, OFFLINE_STATUS_MAX_CONTENT_LEN,
						"journal_type:%d;process_state:being_processed;file_type:%s;file_name:%s;cause_of_error:%s;client_ip:%s;now_time:%lu;\n",
						OFFLINE_STATUS_ERRO_MESS_TYPE,
						pstatus->file_type,
						pstatus->file_name,
						pstatus->err_info,
						pstatus->clientip,
						jiffies);	
			break;
		case OFFLINE_STATUS_CAHN_STAT_TYPE:
				snprintf(writecontent, OFFLINE_STATUS_MAX_CONTENT_LEN,
					"journal_type:%d;in_pkt_num:%lu;in_pkt_len:%lu;out_pkt_num:%lu;out_pkt_len:%lu;in_file_num:%lu;out_file_num:%lu;client_ip:%s;now_time:%lu;\n",
					OFFLINE_STATUS_CAHN_STAT_TYPE,
					pstatus->offline_count.inpkts,
					pstatus->offline_count.inbytes,
					pstatus->offline_count.outpkts,
					pstatus->offline_count.outbytes,
					pstatus->offline_count.infiles,
					pstatus->offline_count.outfiles,
					pstatus->clientip,
					jiffies);	
			break;
		default :
			printf("offline_status_rep error [%s-%s-%d]\n", __FILE__, __func__, __LINE__);	
			goto leave;
			break;
	}
	fwrite(writecontent, strlen(writecontent), 1, fp);
leave:
	fclose(fp);
	return;
}

static void *offline_status_put(void *ele) 
{
	char thread_name[128] = {0};
	int cpu_id = 0;
	cpu_set_t mask;                                                                             
	CPU_ZERO(&mask);
	CPU_SET(cpu_id, &mask);
	int ret = sched_setaffinity(0, sizeof(cpu_set_t), &mask);
	if(ret == -1)
		printf("%s(%d):offline_status_put, cpu_id=%d, cpu bind failed\n", __FILE__, __LINE__, cpu_id);
	else
		printf("%s(%d):offline_status_put, cpu_id=%d, cpu bind succeed\n", __FILE__, __LINE__, cpu_id);
	snprintf(thread_name, sizeof(thread_name), "%s", "offline_status_put");
	prctl(PR_SET_NAME, thread_name);

	rbq_buf_t *rbq_buf = NULL;
	offline_status_t *pstatus = NULL;
	while(1)
	{
		if(offline_status_rbq_hand == NULL)
		{
			usleep(100);
			continue;
		}
		rbq_buf = rbq_get_data(offline_status_rbq_hand, 0);
		if(rbq_buf == NULL)
		{
			usleep(100);
			continue;   
		}
		pstatus = (offline_status_t *)rbq_buf->buf;
	
		offline_status_rep(pstatus, 0);

		rbq_put_buf(offline_status_rbq_hand, rbq_buf);
	}	
	return NULL;	
}	

void offline_status_getp2(offline_status_t *pstatus, int thr_id)
{
	rbq_buf_t *rbq_buf = NULL;
	while((rbq_buf = rbq_get_buf(offline_status_rbq_hand, sizeof(offline_status_t), 1, thr_id)) == NULL)	
	{
		usleep(50);
		continue;
	}
	assert(rbq_buf);
	rbq_buf->len = sizeof(offline_status_t);
	memcpy(rbq_buf->buf, pstatus, sizeof(offline_status_t));
	rbq_put_data(offline_status_rbq_hand, rbq_buf);
	return;
}

void offline_status_init(int thr_num)
{
	offline_status_rbq_hand = rbq_malloc(thr_num, 500, 500, thr_num, 1, "offline_status_rbq_hand");
	assert(offline_status_rbq_hand != NULL);	
	rbq_overcommit(offline_status_rbq_hand, 50*1024*1024, 10*1024*1024);
	pthread_t statusid;
	int ret = pthread_create(&statusid, NULL, offline_status_put, NULL);
	if(ret != 0)
	{
		printf("offline_status_init error [%s-%s-%d]\n", __FILE__, __func__, __LINE__);	
		exit(0);
	}
	return;
}



