/*************************************************************************
	> File Name: offline_scan.c
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月04日 星期四 14时36分17秒
 ************************************************************************/

#include "offline.h"


#define   OFFLINE_MAX_FILE_NAME_LEN      100
#define   OFFLINE_GSCAN_PATH_LEN         200
#define   OFFLINE_GSCAN_FILENAME_LEN     300

#pragma pack (1) 

static uint32_t offline_scan_thr_id = 0;
static zlog_category_t *offline_scan_zlog = NULL;
static void *g_offline_scan_handle[OFFLINE_MAX_THR_NUM];
typedef struct{
	int      thr_id;
	int      cpu_id;
	uint32_t channel_num;   //此数量不可超过OFFLINE_MAX_CHANNEL_NUM
	uint32_t gchannel[OFFLINE_MAX_CHANNEL_NUM];
	char     gscan_filename[OFFLINE_MAX_CHANNEL_NUM][OFFLINE_MAX_FILE_NAME_LEN];
}offline_scan_gthr_t;

typedef struct{
	int thr_num;
	offline_scan_gthr_t *gthr[OFFLINE_MAX_THR_NUM]; 
}offline_scan_init_t;

typedef struct offline_scan_path{
	char                 path[OFFLINE_GSCAN_FILENAME_LEN];
	uint32_t             pathlen;
	struct offline_scan_path *pnext;
}offline_scan_path_t;

typedef struct{
	offline_scan_path_t *pathinfo;
	uint32_t   filesum;//记录需要处理的文件总数
	uint32_t   filedone; //已经处理的文件数量
	uint32_t   cmpflag; //标识此数据源是否可以进行下一次处理
	uint32_t   type;
	//以下为vender填充	
	uint32_t   channel;
	uint8_t    sessid[OFFLINE_SESSID_LEN];
	uint32_t   sessidlen;
	uint8_t    clientip[OFFLINE_CLIENTIP_LEN];
	uint32_t   clientiplen;	
}offline_scan_value_t;

typedef struct{
	char gscanpath[OFFLINE_GSCAN_PATH_LEN];
}offline_scan_key_t;

#pragma pack (0) 
int comm_rmdircont_operation(const char *dir)
{
	char cur_dir[] = ".";
	char up_dir[] = "..";
	char dir_name[512] = {0};
	DIR *dirp = NULL;
	struct dirent *dp = NULL;
	struct stat dir_stat;
	int ret = 0;
	//参数传递进来目录不存在，直接返回
	if( 0 != access(dir, F_OK))
	{
		zlog_error(offline_scan_zlog, "%s is not exit", dir);
		return 0;
	}
	if(0 > stat(dir, &dir_stat))
	{
		zlog_error(offline_scan_zlog, "%s get directory stat error", dir);
		perror("get directory stat error");
		return -1;
	}
	if(S_ISREG(dir_stat.st_mode))
	{
		ret = remove(dir);
		if(ret != 0)
		{
			zlog_error(offline_scan_zlog, "remove %s fail;errno = %d", dir, errno);
		}
	}
	else if(S_ISDIR(dir_stat.st_mode))
	{
		dirp = opendir(dir);
		if(dirp == NULL)
			zlog_error(offline_scan_zlog, "opendir %s fail;errno = %d", dir, errno);

		while((dp = readdir(dirp)) != NULL)
		{
			if( (0 == strcmp(cur_dir, dp->d_name)) || (0 == strcmp(up_dir, dp->d_name)) )
				continue;
			sprintf(dir_name, "%s/%s", dir, dp->d_name);
			comm_rmdir_operation(dir_name);
		}
		if(dirp != NULL)
			closedir(dirp);
	}
	else
	{
		perror("unknow file type");
	}
	return 0;
}
int comm_rmdir_operation(const char *dir)
{
	char cur_dir[] = ".";
	char up_dir[] = "..";
	char dir_name[512] = {0};
	DIR *dirp = NULL;
	struct dirent *dp = NULL;
	struct stat dir_stat;
	int ret = 0;
	//参数传递进来目录不存在，直接返回
	if( 0 != access(dir, F_OK))
	{
		zlog_error(offline_scan_zlog, "%s is not exit", dir);
		return 0;
	}
	if(0 > stat(dir, &dir_stat))
	{
		zlog_error(offline_scan_zlog, "%s get directory stat error", dir);
		perror("get directory stat error");
		return -1;
	}
	if(S_ISREG(dir_stat.st_mode))
	{
		ret = remove(dir);
		if(ret != 0)
		{
			zlog_error(offline_scan_zlog, "remove %s fail;errno = %d", dir, errno);
		}
	}
	else if(S_ISDIR(dir_stat.st_mode))
	{
		dirp = opendir(dir);
		if(dirp == NULL)
			zlog_error(offline_scan_zlog, "opendir %s fail;errno = %d", dir, errno);

		while((dp = readdir(dirp)) != NULL)
		{
			if( (0 == strcmp(cur_dir, dp->d_name)) || (0 == strcmp(up_dir, dp->d_name)) )
				continue;
			sprintf(dir_name, "%s/%s", dir, dp->d_name);
			comm_rmdir_operation(dir_name);
		}
		if(dirp != NULL)
			closedir(dirp);
		ret = rmdir(dir);
		if(ret != 0)
			zlog_error(offline_scan_zlog, "rmdir %s fail;errno = %d", dir, errno);
	}
	else
	{
		perror("unknow file type");
	}
	return 0;
}

int comm_mkdirs_operation(const char *dir)
{
	int i = 0, len = 0, ret = 0;
	char str[512] = {0};
	strncpy(str, dir, 512);
	len = strlen(str);
	for(i = 0; i < len; i++)
	{
		if(str[i] == '/')
		{
			str[i] = '\0';
			if(access(str, 0) != 0)
			{
				ret = mkdir(str, 0777);
				if(ret != 0)
					zlog_error(offline_scan_zlog, "mkdir %s fail;errno = %d", str, errno);

			}
			str[i] = '/';
		}
	}
	if((len > 0) && (access(str,0) != 0))
	{
		ret = mkdir(str, 0777);
		if(ret != 0)
			zlog_error(offline_scan_zlog, "mkdir %s fail;errno = %d", str, errno);
	}
	return 0;
}

int comm_rename_operation(const char *oldname, char *newname)
{
	return rename(oldname, newname);
}

static void load_tcp_ip_port_conf(group_param_t *param, char *filename)
{
	xmlcfg_t tc;
	xmlcfg_list_t xmllist;
	int i, err;
	long v;
	printf("load_tcp_ip_port_conf load %s\n", filename);
	if (xmlcfg_init_file(&tc, filename) != 0)
	{
		printf("load %s fail\n", filename);
		exit(0);
	}
	err = xmlcfg_get_list(&tc, "/conf/node", &xmllist);
	if (err)
	{
		printf("load /conf/node from %s failed\n", filename);

		xmlcfg_list_free(&xmllist);
		xmlcfg_close(&tc);

		exit(0);
	}

	for (i = 0; i < xmlcfg_list_length(&xmllist); i++)
	{

		err = xmlcfg_list_get_str(&xmllist, i,"ip", param->ip[param->num], 20);
		if (err < 1)
		{
			printf("load /conf/node/[%d]/ip failed\n", i);
			exit(0);
		}

		err = xmlcfg_list_get_long(&xmllist, i,  "port", &v);
		if (err)
		{
			printf("load /conf/node/[%d]/port failed\n", i);
			exit(0);
		}
		param->port[param->num] = v;                                            
		param->num++;
		if(param->num > CONN_NUM_A_GROUP)
		{
			printf("thr group_param->num(%d) must < CONN_NUM_A_GROUP(%d)",param->num, CONN_NUM_A_GROUP);
			exit(0);
		}
	}
	xmlcfg_list_free(&xmllist);
	xmlcfg_close(&tc);
	return ;
}

static void init_get_cpu(offline_comm_send_rbq_t *send_rbq, uint8_t *data, uint32_t dataLen)
{
	if(dataLen <= 0 || data == NULL || send_rbq == NULL)
	{
		printf("init_get_cpu fail %s-%d\n", __FILE__, __LINE__);
		exit(0);
	}
	uint32_t dealLen = 0, udataLen = 0;
	uint8_t  *udata = data;
	int i = 0;
	char cpubuf[128] = {0};
	while(dealLen < dataLen)
	{
		if(*(data + dealLen) == ';')
		{
			memset(cpubuf, 0, sizeof(cpubuf));
			memcpy(cpubuf, udata, udataLen);
			send_rbq->CIG[i].CpuOccupy = 1;
			send_rbq->CIG[i].CpuId = atoi(cpubuf);
			udataLen = 0;
			udata = data + dealLen + 1;
			i++;
		}
		udataLen++;
		dealLen++;
	}
	return ;    
}

static void offline_scan_read_dis(char *dis_filename, offline_comm_send_rbq_t *send_rbq)
{
	xmlcfg_t tc;
	int err;
	char xpath[255] = {0}, tmp_buff[512] = {0};
	long v;
	
	printf("offline_scan_read_dis load %s\n", dis_filename);
	if (xmlcfg_init_file(&tc, dis_filename) != 0)
	{
		printf("load %s fail\n", dis_filename);
		exit(0);
	}

	snprintf(xpath,255,"/conf/rbq/send/qlen");
	err = xmlcfg_get_long(&tc,xpath,&v);
	if(err)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}
	send_rbq->send_qlen = v;

	snprintf(xpath,255,"/conf/rbq/send/qsize");
	err = xmlcfg_get_long(&tc,xpath,&v);
	if(err)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}
	send_rbq->send_qsize = v;

	snprintf(xpath,255,"/conf/rbq/send/block_mod");
	err = xmlcfg_get_long(&tc,xpath,&v);
	if(err)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}
	send_rbq->block_mod = v;

	snprintf(xpath,255,"/conf/thread/send_thr_num");          
	
	err = xmlcfg_get_long(&tc,xpath,&v);
	if(err)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}
	send_rbq->send_thr_num = v;

	snprintf(xpath,255,"/conf/cpu_id_grep");
	err = xmlcfg_get_str(&tc, xpath, tmp_buff,128);
	if(err < 1)
	{
		printf("load %s fail\n", xpath);
		exit(0);
	}                                                            
	init_get_cpu(send_rbq, (uint8_t *)tmp_buff, strlen(tmp_buff));	
	xmlcfg_close(&tc);
	return ;
}

void *offline_scan_init(offline_init_t *offinit, int thr_num, uint32_t channel_num)
{
	if(thr_num < 0 || channel_num < 0 || offinit == NULL || thr_num > OFFLINE_MAX_THR_NUM)
	{
		printf("offline_scan_init error [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		return NULL;
	}
	static uint32_t addflag[OFFLINE_MAX_THR_NUM], i = 0, j = 0, err = 0, exc = 0, rem = 0, sum = 0, channel = 0;
	
	offline_link_init(offinit->diy_lib_switch, offinit->diy_lib_path, offinit->max_cache_len, channel_num, channel_num*100, thr_num, offinit->ex_thr_num); //1

	offline_comm_init_t comm_init;
	memset(&comm_init, 0, sizeof(offline_comm_init_t));

	offline_comm_read_link(offinit->m2_conn_path, &comm_init.m2_send_rbq);
	comm_init.link_send_rbq.write_thr_num = thr_num + offinit->ex_thr_num;
	offline_comm_read_link(offinit->link_conn_path, &comm_init.link_send_rbq);
	comm_init.m2_send_rbq.write_thr_num = thr_num + offinit->ex_thr_num;
	offline_comm_read_link(offinit->pv_conn_path, &comm_init.pv_send_rbq);
	comm_init.pv_send_rbq.write_thr_num = thr_num + offinit->ex_thr_num;
	load_tcp_ip_port_conf(&comm_init.link_send_rbq.group_param, offinit->link_conn_path);
	load_tcp_ip_port_conf(&comm_init.m2_send_rbq.group_param, offinit->m2_conn_path);
	load_tcp_ip_port_conf(&comm_init.pv_send_rbq.group_param, offinit->pv_conn_path);
	offline_link_tcpsend_init(&comm_init); //1
	offline_scan_read_dis(offinit->dis_conn_path, &comm_init.dis_send_rbq);
	comm_init.dis_send_rbq.write_thr_num = thr_num + offinit->ex_thr_num;
	offline_link_dis_init(&comm_init.dis_send_rbq);
	
	offline_scan_zlog = zlog_get_category("offline_link_zlog");
	if(!offline_scan_zlog)
	{
		printf("zlog_get_category [offline_scan_zlog] error [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		exit(0);
	}	
	offline_scan_init_t *pscan_init = (offline_scan_init_t *)malloc(sizeof(offline_scan_init_t));	
	assert(pscan_init);
	if(thr_num >= channel_num)
	{
		exc = 1;
		thr_num = channel_num; 		
		exc = 1;
		rem = 0;
	}
	else
	{
		exc = channel_num/thr_num;
		rem = channel_num%thr_num;
	}
	pscan_init->thr_num = thr_num;

	
	for(i = 0; i < thr_num; i ++)
	{
		g_offline_scan_handle[i] = (mini_hash_t *)malloc(sizeof(mini_hash_t));
		assert(g_offline_scan_handle[i]);
		err = mini_hash_create((mini_hash_t *)g_offline_scan_handle[i], channel_num, channel_num * 100, sizeof(offline_scan_key_t), sizeof(offline_scan_value_t), fifo_expire);
		if(err)
		{
			printf("mini_hash_create error [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
			exit(0);
		}
		err = mini_hash_build_table((mini_hash_t *)g_offline_scan_handle[i]);
		if(err)
		{
			printf("mini_hash_build_table error [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
			exit(0);
		}
		pscan_init->gthr[i] = malloc(sizeof(offline_scan_gthr_t));
		assert(pscan_init->gthr);
		memset(pscan_init->gthr[i], 0, sizeof(offline_scan_gthr_t));
		if(comm_init.dis_send_rbq.CIG[i].CpuOccupy == 1)
			pscan_init->gthr[i]->cpu_id = comm_init.dis_send_rbq.CIG[i].CpuId;
		for(j = 0; j < exc;j ++)
		{
			pscan_init->gthr[i]->gchannel[pscan_init->gthr[i]->channel_num] = channel; 
			snprintf(pscan_init->gthr[i]->gscan_filename[pscan_init->gthr[i]->channel_num], OFFLINE_MAX_FILE_NAME_LEN, "%s/%d%s", offinit->scan_path, channel, ".xml");
			pscan_init->gthr[i]->channel_num++;
			channel++;
			if(sum < rem && addflag[i] == 0)
			{
				pscan_init->gthr[i]->gchannel[pscan_init->gthr[i]->channel_num] = channel;
				snprintf(pscan_init->gthr[i]->gscan_filename[pscan_init->gthr[i]->channel_num], OFFLINE_MAX_FILE_NAME_LEN, "%s/%d%s", offinit->scan_path , channel, ".xml"); 
				pscan_init->gthr[i]->channel_num ++;
				sum ++;
				channel++;
				addflag[i] = 1;
			}
		}	
	}
	return (void *)pscan_init;
}

static mini_hash_node_t *offline_scan_hash_find(offline_scan_key_t *key, int thr_id)
{
	mini_hash_node_t *node = mini_hash_find_node(g_offline_scan_handle[thr_id], key, sizeof(offline_scan_key_t));
	if(!node)
	{
		offline_scan_value_t value;
		memset(&value, 0, sizeof(offline_scan_value_t));
		mini_hash_add_ex(g_offline_scan_handle[thr_id], key, sizeof(offline_scan_key_t), &value, sizeof(offline_scan_value_t), &node);
	}
	return node;
}


static int offline_scan_chxml(char *scanpath, offline_scan_value_t *pvalue)
{
	xmlcfg_t tc;            
	xmlcfg_list_t item_list;
	xmlcfg_list_t file_list;
	char xpath[255] = {0};
	int err = 0, i = 0, j = 0;
	char filename[300] = {0};
	long v = 0; 

	offline_scan_path_t *pathinfo_node, *pathinfo_end;
	
	if (xmlcfg_init_file(&tc, scanpath) != 0)              
	{                                                       
		printf("load %s fail [%s-%s-%d]\n", scanpath, __FILE__, __func__, __LINE__);                
		zlog_error(offline_scan_zlog, "load %s fail [%s-%s-%d]", scanpath, __FILE__, __func__, __LINE__); 
		return -1;                                         
	}                                                                     
	snprintf(xpath, 255, "/config/item");
	err = xmlcfg_get_list(&tc, xpath, &item_list);
	if(err)
	{
		printf("load %s->%s fail [%s-%s-%d]\n", scanpath, xpath, __FILE__, __func__, __LINE__);
		zlog_error(offline_scan_zlog, "load %s->%s fail [%s-%s-%d]", scanpath, xpath, __FILE__, __func__, __LINE__);
		exit(0);
	}
	for(i = 0; i < xmlcfg_list_length(&item_list); i++ )
	{
		snprintf(xpath, 255, "/config/item[%d]/tags/sess_id", i+1);    
		err = xmlcfg_get_str(&tc, xpath, (char *)pvalue->sessid, OFFLINE_SESSID_LEN - 1);
		if (err < 1)                                                   
		{                                                              
			printf("load %s->%s fail [%s-%s-%d]\n", scanpath, xpath, __FILE__, __func__, __LINE__);
			zlog_error(offline_scan_zlog, "load %s->%s fail [%s-%s-%d]", scanpath, xpath, __FILE__, __func__, __LINE__);
			exit(0);
		}                                                              
		pvalue->sessidlen = strlen((char *)pvalue->sessid);
		snprintf(xpath, 255, "/config/item[%d]/tags/sess_channel", i+1);
		err = xmlcfg_get_long(&tc, xpath, &v);	
		if(err)
		{
			printf("load %s->%s fail [%s-%s-%d]\n", scanpath, xpath, __FILE__, __func__, __LINE__);
			zlog_error(offline_scan_zlog, "load %s->%s fail [%s-%s-%d]", scanpath, xpath, __FILE__, __func__, __LINE__);
			exit(0);
		}
		pvalue->channel = v;
		snprintf(xpath, 255, "/config/item[%d]/tags/client_ip", i+1);    
		err = xmlcfg_get_str(&tc, xpath, (char *)pvalue->clientip, OFFLINE_CLIENTIP_LEN - 1);
		if (err < 1)                                                   
		{                                                              
			printf("load %s->%s fail [%s-%s-%d]\n", scanpath, xpath, __FILE__, __func__, __LINE__);
			zlog_error(offline_scan_zlog, "load %s->%s fail [%s-%s-%d]", scanpath, xpath, __FILE__, __func__, __LINE__);
			exit(0);
		}                                                              
		pvalue->clientiplen = strlen((char *)pvalue->clientip);
		err = xmlcfg_list_get_long(&item_list, i, "type", &v);
		if(err)                                               
		{                                                     
			printf("load %s->%s fail [%s-%s-%d]\n", scanpath, xpath, __FILE__, __func__, __LINE__);
			zlog_error(offline_scan_zlog, "load %s->%s fail [%s-%s-%d]", scanpath, xpath, __FILE__, __func__, __LINE__);
			exit(0);
		}                                                     
		pvalue->type = v;
		snprintf(xpath, 255, "/config/item[%d]/files/file", i + 1);
		err = xmlcfg_get_list(&tc, xpath, &file_list);
		if(err)
		{
			printf("load %s->%s fail [%s-%s-%d]\n", scanpath, xpath, __FILE__, __func__, __LINE__);
			zlog_error(offline_scan_zlog, "load %s->%s fail [%s-%s-%d]", scanpath, xpath, __FILE__, __func__, __LINE__);
			exit(0);
		}		
		for(j = 0; j < xmlcfg_list_length(&file_list); j++)
		{
			snprintf(xpath, 255, "/config/item[%d]/files/file[%d]", i + 1, j + 1);
			err = xmlcfg_get_str(&tc, xpath, filename, sizeof(filename));
			if(err < 1)
			{
				printf("load %s->%sfail [%s-%s-%d]\n", scanpath, xpath, __FILE__, __func__, __LINE__);
				zlog_error(offline_scan_zlog, "load %s->%s fail [%s-%s-%d]", scanpath, xpath, __FILE__, __func__, __LINE__);

			}
			else
			{
				if(j == 0)
				{
					pvalue->pathinfo = (offline_scan_path_t *)malloc(sizeof(offline_scan_path_t));
					snprintf(pvalue->pathinfo->path, OFFLINE_GSCAN_FILENAME_LEN, "%s", filename);
					pvalue->pathinfo->pathlen = strlen(pvalue->pathinfo->path);
					pathinfo_end = pvalue->pathinfo;
				}
				else
				{

					pathinfo_node = (offline_scan_path_t *)malloc(sizeof(offline_scan_path_t));
					snprintf(pathinfo_node->path, OFFLINE_GSCAN_FILENAME_LEN, "%s", filename);
					pathinfo_node->pathlen = strlen(pathinfo_node->path);
					pathinfo_end->pnext = pathinfo_node;
					pathinfo_end = pathinfo_node;

				}
				pvalue->filesum++;
			}
		}
		pathinfo_end->pnext = NULL;
		pvalue->cmpflag = 1;
	}

	err = xmlcfg_list_free(&file_list);     
	if(err)                                 
	{                                       
		printf("xmlcfg_list_free(%s) falied [%s-%s-%d]\n", scanpath, __FILE__, __func__, __LINE__);
		exit(0);                            
	}     
	err = xmlcfg_list_free(&item_list);     
	if(err)                                 
	{                                       
		printf("xmlcfg_list_free(%s) falied [%s-%s-%d]\n", scanpath, __FILE__, __func__, __LINE__);
		exit(0);                            
	}                                       
	err = xmlcfg_close(&tc);                
	if(err)                                 
	{                                       
		printf("xmlcfg_close (%s) falied [%s-%s-%d]\n", scanpath, __FILE__, __func__, __LINE__);    
		exit(0);                            
	}                                       
	return 0;
}

static void offline_scan_infch(offline_scan_value_t *pvalue, int thr_id)
{
	offline_dataproc_info_t dataproc;
	memset(&dataproc, 0, sizeof(offline_dataproc_info_t));
	if(pvalue->filedone < pvalue->filesum)
	{
		//printf("path-----------------------%s(thr_id=%d, channel=%d)\n", pvalue->pathinfo->path, thr_id, pvalue->channel);
		snprintf(dataproc.path, OFFLINE_PATH_LEN, "%s", pvalue->pathinfo->path);
		dataproc.path_len = pvalue->pathinfo->pathlen;
		dataproc.channel  = pvalue->channel;
		snprintf(dataproc.sessid, OFFLINE_SESSID_LEN, "%s", pvalue->sessid);
		dataproc.sessid_len = pvalue->sessidlen;
		snprintf(dataproc.clientip, OFFLINE_CLIENTIP_LEN, "%s", pvalue->clientip);
		dataproc.clientip_len = pvalue->clientiplen;
		dataproc.thr_id    = thr_id;
		dataproc.type      = pvalue->type;
		offline_link_proc(NULL, &dataproc, thr_id);	
		comm_rmdir_operation(dataproc.path);//文件删除	
		pvalue->filedone++;
		offline_scan_path_t *pathinfo = pvalue->pathinfo->pnext;
		free(pvalue->pathinfo);
		pvalue->pathinfo = pathinfo;	
	}
	else
		pvalue->cmpflag = 0;
	return ;
}
static int  offline_scan_chinfo(char *scanpath, int thr_id)
{
	offline_scan_key_t key;
	offline_scan_value_t *pvalue = NULL;
	memset(&key, 0, sizeof(offline_scan_key_t));
	snprintf(key.gscanpath, OFFLINE_GSCAN_PATH_LEN, "%s", scanpath);
	int ret = 0;
	mini_hash_node_t *node = offline_scan_hash_find(&key, thr_id);
	if(node)
	{
		pvalue = (offline_scan_value_t *)mini_hash_get_node_value((mini_hash_t *)g_offline_scan_handle[thr_id], node);
		assert(pvalue);
		if(pvalue->cmpflag == 0)
		{
			ret = offline_scan_chxml(scanpath, pvalue);	
			if(ret == 0)
			{
				offline_scan_infch(pvalue, thr_id); 
			}
		}
		else
		{
			offline_scan_infch(pvalue, thr_id); 
		}
		if(pvalue->cmpflag == 0)
		{
			comm_rmdir_operation(scanpath);		
		}
	}
	return 0;
}

static void *offline_scan_fetch(void *hander)
{
	offline_scan_gthr_t *pgthr = (offline_scan_gthr_t *)hander;
	pgthr->thr_id = __sync_fetch_and_add(&(offline_scan_thr_id),1);
	char thread_name[128] = {0};
	int cpu_id = 0, i = 0;
	cpu_set_t mask;                                                                             
	CPU_ZERO(&mask);
	cpu_id = pgthr->cpu_id;
	CPU_SET(cpu_id, &mask);
	int ret = sched_setaffinity(0, sizeof(cpu_set_t), &mask);
	if(ret == -1)
		printf("%s(%d):offline_scan, cpu_id=%d, cpu bind failed\n", __FILE__, __LINE__, cpu_id);
	else
		printf("%s(%d):offline_scan, cpu_id=%d, cpu bind succeed\n", __FILE__, __LINE__, cpu_id);
	snprintf(thread_name, sizeof(thread_name), "offline_scan_%d", pgthr->thr_id);
	prctl(PR_SET_NAME, thread_name);
	while(1)
	{
		for(i = 0; i < pgthr->channel_num; i++)
		{
			if(access(pgthr->gscan_filename[i], F_OK) != -1)
			{
				offline_scan_chinfo(pgthr->gscan_filename[i], pgthr->thr_id);
			}
		}		
		sleep(1);
	}
	return NULL;
}

void offline_scan_start(void *hander)
{
	offline_scan_init_t *pscan_init = (offline_scan_init_t *)hander;
	uint32_t i = 0;
	int ret = 0;
	pthread_t pid[OFFLINE_MAX_THR_NUM];
	for(i = 0 ; i < pscan_init->thr_num; i ++)
	{
		ret = pthread_create(&pid[i], NULL, offline_scan_fetch, (void *)pscan_init->gthr[i]);
		if(ret != 0)
		{
			printf("offline_scan_start error [%s-%s-%d]\n", __FILE__, __func__, __LINE__);	
			return ;
		}
	}
	return ;
}



