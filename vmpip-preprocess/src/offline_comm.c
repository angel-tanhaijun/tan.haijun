/*************************************************************************
	> File Name: offline_comm.c
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月03日 星期三 15时29分20秒
 ************************************************************************/

#include "offline.h"

#define Magic_Value                     0x00000601
#define m2_type_flag            (0x80)   //结束型M2消息
#define hy_exist_flag           (0x40)   //包含还原信息（即元消息）
#define rawpkt_exist_flag       (0x20)   //包含原始报文信息


static void   *offline_link_rbq_handle = NULL;
static void   *offline_link_send_handle = NULL;
static void   *offline_link_send_rbq_handle = NULL;
static void   *offline_link_send_pv_handle = NULL;
static void   *offline_dis_rbq_handle = NULL;

#pragma pack (1)
typedef struct{
	char      downpath[OFFLINE_MAX_PATH_LEN];
	uint32_t  downswitch;
	uint32_t  pcapmaxsize;
}offline_down_pcap_t;

struct pcap_pkthdr_32
{        
	uint32_t tv_sec;
	uint32_t tv_usec;
	uint32_t caplen;
	uint32_t len;
};   

#pragma pack (0)
static offline_down_pcap_t offline_down_pcap;

uint64_t ntoh64(uint64_t buff)
{
	return ((((buff) & (0xFF00000000000000ull)) >> 56) | \
			(((buff) & (0x00FF000000000000ull)) >> 40) | \
			(((buff) & (0x0000FF0000000000ull)) >> 24) | \
			(((buff) & (0x000000FF00000000ull)) >> 8)  | \
			(((buff) & (0x00000000FF000000ull)) << 8)  | \
			(((buff) & (0x0000000000FF0000ull)) << 24) | \
			(((buff) & (0x000000000000FF00ull)) << 40) | \
			(((buff) & (0x00000000000000FFull)) << 56));
}
uint32_t offline_comm_len_set(char *buff, uint32_t bufflen)
{
	char numbuff[215] = {0};
	memset(numbuff, 0, sizeof(numbuff));
	if(bufflen < 2)
		return OFFLINE_DATA_DEFAULT_MAX_LEN;
	if(buff[bufflen - 1] == 'M')
	{
		memcpy(numbuff, buff, bufflen - 1);
		return (atoi(numbuff) * 1024 * 1024);
	}
	else if(buff[bufflen - 1] == 'B' && buff[bufflen - 2] == 'K')
	{
		memcpy(numbuff, buff, bufflen - 2);
		return (atoi(numbuff) * 1024);
	}
	else if(buff[bufflen - 1] == 'T' && buff[bufflen - 2] == 'B')
	{
		memcpy(numbuff, buff, bufflen - 2);
		return (atoi(numbuff));
	}
	else
		return OFFLINE_DATA_DEFAULT_MAX_LEN;
}
void offline_down_pcap_info_set(offline_init_t *offinit)
{
	if(offinit == NULL)	
		return;
	snprintf(offline_down_pcap.downpath, OFFLINE_MAX_PATH_LEN, "%s", offinit->downpath);
	offline_down_pcap.downswitch  = offinit->downswitch;
	offline_down_pcap.pcapmaxsize = offinit->pcapsize;
	return;
}
int offline_get_file_size(char *filepath)
{
	struct stat statBuf;
	uint64_t size = 0;
	if(access(filepath, F_OK) == -1)
		return -1;
	stat(filepath, &statBuf);
	size = statBuf.st_size;
	return size;
}


static void offline_down_pcap_proc(uint8_t *ip, uint32_t iplen, char *downpath, uint32_t channel, int thr_id)
{
	char datatime[215] = {0};
	char path[2048] = {0};
	int filesize = 0;
	time_t ptime;
	struct tm *ptm = NULL;
	uint32_t pflag = 0;
	
	time(&ptime);
	ptm = localtime(&ptime);
	snprintf(datatime, 200, "%04d-%02d-%02d", ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday);

	if(ip == NULL || iplen <= 0 || downpath == NULL)
	{
		printf("offline_down_pcap_proc fail! channel[%d] thr_id[%d] [%s-%s-%d]\n", channel, thr_id, __FILE__, __func__, __LINE__);
		return;
	}
	if(access(downpath, F_OK)  == -1)
	{
		comm_mkdirs_operation(downpath);
	}
	snprintf(path, sizeof(path),"%s/%s-%d-%d%s", downpath, datatime, channel, thr_id,".pcap");
	while((filesize = offline_get_file_size(path)) != -1 && (filesize = offline_get_file_size(path)) > offline_down_pcap.pcapmaxsize)
	{
		pflag++;
		snprintf(path, sizeof(path), "%s/%s-%d-%d-%d%s", downpath, datatime, channel, thr_id,pflag, ".pcap");
	}
	FILE *fp = NULL;
	uint16_t protype = 0;
	pcap_header_t pcap_header; 
	if((access(path,0)) == -1)
	{
		if((fp = fopen(path,"w+")) != NULL)
		{
			pcap_header.magic = 0xa1b2c3d4;
			pcap_header.version_major = 0x0002;
			pcap_header.version_minor = 0x0004;
			pcap_header.thiszone = 0; 
			pcap_header.sigfigs = 0;
			pcap_header.snaplen = 65535;

			memcpy(&protype, ip + 12, sizeof(protype));
			if(ntohs(protype) == 0x0800)    
				pcap_header.linktype = 1;   
			else
				pcap_header.linktype = 101;
			fwrite((char *)&pcap_header,1,24,fp);
			fclose(fp);
		}   
	}
	if((fp = fopen(path,"ab+")) != NULL)
	{
		struct pcap_pkthdr_32 data_head;
		struct timeval tv;
		memset(&data_head,0,sizeof(struct pcap_pkthdr_32));
		gettimeofday(&tv,NULL);                             

		data_head.tv_sec  = (uint32_t)tv.tv_sec;
		data_head.tv_usec = (uint32_t)tv.tv_usec;
		data_head.caplen     = iplen;
		data_head.len        = iplen;
		fwrite(&data_head, 16, 1 ,fp);

		fwrite(ip, iplen, 1, fp);
		fclose(fp); 
	}
	return;
}
static void ip_data_recv_info_record(rbq_buf_t *rbq_buf, int thr_id, offline_dis_vender_t *pdis_vender)
{
	body_header_t *body_header = NULL, *body_headers = NULL;                   
	uint32_t    msg_cont_len = 0, msg_cont_lens = 0;                        
	uint32_t int_32 = 0;
	if(thr_id < 0 || rbq_buf == NULL || pdis_vender == NULL)                        
	{                                                    
		printf("ip_data_recv_info_record failure!\n");
		return ;                                         
	}                                                    
	offline_comm_begin_add_big_record(rbq_buf, thr_id, OFFLINE_CONNECTLOG_USER_VENDOR_TYPE, &msg_cont_len, &body_header);
	if(pdis_vender->userinfolen > 0 && pdis_vender->userinfo != NULL && pdis_vender->userinfotype != 0)
		offline_comm_add_one_sub_record(rbq_buf, thr_id, pdis_vender->userinfotype, (uint8_t *)pdis_vender->userinfo, pdis_vender->userinfolen);	
	offline_comm_begin_add_big_record(rbq_buf, thr_id, offline_connectlog_normal_vendor_type, &msg_cont_lens, &body_headers);
	int_32 = ntohl(pdis_vender->extra.hostIp);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_user_vendor_host_type, (uint8_t *)&int_32, sizeof(int_32));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_user_vendor_cap_timestamp_type, (uint8_t *)&pdis_vender->cap_timestamp, sizeof(pdis_vender->cap_timestamp));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_user_vendor_analysis_timestamp_type, (uint8_t *)&pdis_vender->analysis_timestamp, sizeof(pdis_vender->analysis_timestamp));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_user_vendor_session_id_type, (uint8_t *)pdis_vender->sessid, pdis_vender->sessid_len);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_user_vendor_filename_type, (uint8_t *)pdis_vender->path, pdis_vender->path_len);
	int_32 = ntohl(pdis_vender->channel);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_user_vendor_channel_type, (uint8_t *)&int_32, sizeof(int_32));
	offline_comm_end_add_big_record(rbq_buf, thr_id, msg_cont_lens, body_headers);
	
	offline_comm_end_add_big_record(rbq_buf, thr_id, msg_cont_len, body_header);
	
	
	offline_comm_begin_add_big_record(rbq_buf, thr_id, OFFLINE_CONNECTLOG_RX_MSG_TYPE, &msg_cont_len, &body_header);
	offline_comm_begin_add_big_record(rbq_buf, thr_id, offline_connectlog_data_info_type, &msg_cont_lens, &body_headers);

	int_32 = ntohl(pdis_vender->type);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_data_info_data_info_type, (uint8_t *)&int_32, sizeof(int_32)); 
	int_32 = ntohl(pdis_vender->IPOffset);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_data_info_IPoffset_type, (uint8_t *)&int_32, sizeof(int_32));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_data_info_data_type, (uint8_t *)pdis_vender->ip, pdis_vender->iplen);	

	offline_comm_end_add_big_record(rbq_buf, thr_id, msg_cont_lens, body_headers);
	offline_comm_end_add_big_record(rbq_buf, thr_id, msg_cont_len, body_header);
}

void ip_data_recv_info_entry(void *recv_handle, void *ele, int thr_id)
{
	offline_dis_vender_t *pdis_vender = (offline_dis_vender_t *)ele;
	rbq_buf_t *rbq_buf = NULL; 
	uint32_t  total_len = 0;
	total_len += OFFLINE_COMM_RETAIN_LEN;                                         
	total_len += OFFLINE_COMM_MSG_HEAD_LEN;                                       
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12;                                 
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12 + OFFLINE_COMM_ELE_LL_RETAIN_LEN;
	
	total_len += OFFLINE_COMM_BODY_HEAD_LEN;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + pdis_vender->path_len;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(pdis_vender->channel);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + pdis_vender->sessid_len;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(pdis_vender->cap_timestamp);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(pdis_vender->analysis_timestamp);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + pdis_vender->userinfolen;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(pdis_vender->extra.hostIp);

	total_len += OFFLINE_COMM_BODY_HEAD_LEN;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + pdis_vender->iplen;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(pdis_vender->type);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(pdis_vender->IPOffset);
	

	uint32_t msg_cont_len = 0;        
	body_header_t *body_header = NULL;

	rbq_buf = offline_comm_begin_store(recv_handle, thr_id, total_len, &msg_cont_len, &body_header);
	if(rbq_buf == NULL) 
	{                   
		return ;        
	}                   
	ip_data_recv_info_record(rbq_buf, thr_id, pdis_vender);
	offline_comm_end_store(recv_handle, rbq_buf, thr_id, msg_cont_len, body_header);
}



void offline_comm_read_link(char *conn_filename, offline_comm_send_rbq_t *send_rbq)
{
	xmlcfg_t tc;
	int err;
	char xpath[255];
	long v;
	printf("offline_comm_read_link load %s\n", conn_filename);
	if (xmlcfg_init_file(&tc, conn_filename) != 0)
	{
		printf("load %s fail\n", conn_filename);
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

	snprintf(xpath,255,"/conf/conn_debug_info");
	err = xmlcfg_get_long(&tc,xpath,&v);
	if(err)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}
	send_rbq->conn_debug_info = v & 0x1;
	xmlcfg_close(&tc);
	return ;
}
void offline_link_dis_init(offline_comm_send_rbq_t *dis_send_rbq)
{

	offline_dis_rbq_handle = rbq_malloc(OFFLINE_MAX_NUM(dis_send_rbq->write_thr_num, dis_send_rbq->send_thr_num), dis_send_rbq->send_qlen, dis_send_rbq->send_qsize, dis_send_rbq->write_thr_num, dis_send_rbq->send_thr_num, "offline_dis_rbq_handle");
	assert(offline_dis_rbq_handle != NULL);
	rbq_overcommit(offline_dis_rbq_handle, 50*1024*1024, 10*1024*1024);
	if(dis_send_rbq->block_mod == 1)
		rbq_set_get_buf_mode(offline_dis_rbq_handle, RBQ_GET_BUF_BLOCK); 
	return;
}

void offline_link_dis_rbq_getbuf(offline_link_vender_t *vender, uint8_t *ip, uint32_t iplen, uint32_t type, int thr_id)
{
	rbq_buf_t *rbq_buf = NULL;
	uint32_t total = sizeof(offline_dis_vender_t) + iplen + vender->userinfolen;
	
	offline_dis_vender_t dis_vender;
	memset(&dis_vender, 0, sizeof(offline_dis_vender_t));
	snprintf(dis_vender.path, OFFLINE_PATH_LEN, "%s", vender->path);
	dis_vender.path_len = vender->path_len;
	dis_vender.channel  = vender->channel;
	snprintf(dis_vender.sessid, OFFLINE_SESSID_LEN, "%s", vender->sessid);
	dis_vender.sessid_len           = vender->sessid_len;
	dis_vender.type                 = type;
	dis_vender.iplen                = iplen;
	dis_vender.cap_timestamp        = vender->cap_timestamp;
	dis_vender.analysis_timestamp   = vender->analysis_timestamp;
	dis_vender.IPOffset             = vender->IPOffset;
	dis_vender.extra.hostIp         = vender->extra.hostIp;
	dis_vender.extra.dataType       = vender->extra.dataType;
	dis_vender.userinfolen          = vender->userinfolen; 	
	dis_vender.userinfotype         = vender->userinfotype;
	

	while((rbq_buf = rbq_get_buf(offline_dis_rbq_handle, total, 1, thr_id)) == NULL)
	{
		usleep(10);
		continue;
	}
	assert(rbq_buf);
	rbq_buf->len        = total;
	dis_vender.ip       = rbq_buf->buf + sizeof(offline_dis_vender_t);
	dis_vender.userinfo = rbq_buf->buf + sizeof(offline_dis_vender_t) + iplen; 
	memcpy(rbq_buf->buf, &dis_vender, sizeof(offline_dis_vender_t));
	memcpy(rbq_buf->buf + sizeof(offline_dis_vender_t), ip, iplen);
	memcpy(rbq_buf->buf + sizeof(offline_dis_vender_t) + iplen, vender->userinfo, vender->userinfolen);
	rbq_put_data(offline_dis_rbq_handle, rbq_buf);

	if(offline_down_pcap.downswitch == OFFLINE_SWITCH_OPEN)
		offline_down_pcap_proc(ip, iplen, offline_down_pcap.downpath, vender->channel, thr_id);
}

void *offline_link_dis_rbq_getdata(int thr_id)
{
	if(offline_dis_rbq_handle == NULL)
		return NULL;
	rbq_buf_t *rbq_buf = rbq_get_data(offline_dis_rbq_handle, thr_id);
	if(rbq_buf == NULL)
		return NULL;
	offline_dis_vender_t *pdis_vender = (offline_dis_vender_t *)rbq_buf->buf;
	pdis_vender->rbq_buf = (void *)rbq_buf;

	return (void *)pdis_vender;
}

int offline_link_dis_rbq_putdata(void *ele, int thr_id)
{
	offline_dis_vender_t *pdis_vender = (offline_dis_vender_t *)ele;
	if(pdis_vender != NULL)
		rbq_put_buf(offline_dis_rbq_handle, (rbq_buf_t *)pdis_vender->rbq_buf);	
	return 0;
}

static uint32_t offline_link_dis_id = 0;
typedef struct{
	int thr_id;
}offline_link_dis_info_t;

static void *offline_link_dis_proc(void *parm)
{
	void *ele = NULL;
	offline_link_dis_info_t *pinfo = (offline_link_dis_info_t *)malloc(sizeof(offline_link_dis_info_t));
	pinfo->thr_id = __sync_fetch_and_add(&(offline_link_dis_id),1);
	char thread_name[128] = {0};
	int cpu_id = 0;
	cpu_set_t mask;                                                                             
	CPU_ZERO(&mask);
	cpu_id = pinfo->thr_id + 25;
	CPU_SET(cpu_id, &mask);
	int ret = sched_setaffinity(0, sizeof(cpu_set_t), &mask);
	if(ret == -1)
		printf("%s(%d):link_dis_proc, cpu_id=%d, cpu bind failed\n", __FILE__, __LINE__, cpu_id);
	else
		printf("%s(%d):link_dis_proc, cpu_id=%d, cpu bind succeed\n", __FILE__, __LINE__, cpu_id);
	snprintf(thread_name, sizeof(thread_name), "link_dis_proc_%d", pinfo->thr_id);
	prctl(PR_SET_NAME, thread_name);
	while(1)
	{
		ele = offline_link_dis_rbq_getdata(pinfo->thr_id);
		if(ele != NULL)
		{
			ip_data_recv_info_entry(offline_link_send_rbq_handle, ele, pinfo->thr_id); 
			offline_link_dis_rbq_putdata(ele, pinfo->thr_id);
		}
		else
			usleep(10); 
	}
	return NULL;
}


void offline_link_tcpsend_init(offline_comm_init_t *comm_init)
{
	int i = 0;
	pthread_t pid[OFFLINE_MAX_THR_NUM];
	offline_link_send_rbq_handle = rbq_malloc(OFFLINE_MAX_NUM(comm_init->m2_send_rbq.send_thr_num, comm_init->m2_send_rbq.send_thr_num), comm_init->m2_send_rbq.send_qlen, comm_init->m2_send_rbq.send_qsize, comm_init->m2_send_rbq.send_thr_num, comm_init->m2_send_rbq.send_thr_num, "offline_m2_rbq_handle");
	assert(offline_link_send_rbq_handle != NULL);
	rbq_overcommit(offline_link_send_rbq_handle, 50*1024*1024, 10*1024*1024);
	if(comm_init->m2_send_rbq.block_mod == 1)
		rbq_set_get_buf_mode(offline_link_send_rbq_handle, RBQ_GET_BUF_BLOCK);

	offline_link_rbq_handle = rbq_malloc(OFFLINE_MAX_NUM(comm_init->link_send_rbq.write_thr_num, comm_init->link_send_rbq.send_thr_num), comm_init->link_send_rbq.send_qlen, comm_init->link_send_rbq.send_qsize, comm_init->link_send_rbq.write_thr_num, comm_init->link_send_rbq.send_thr_num, "offline_link_rbq_handle");
	assert(offline_link_rbq_handle != NULL);
	rbq_overcommit(offline_link_rbq_handle, 50*1024*1024, 10*1024*1024);
	if(comm_init->link_send_rbq.block_mod == 1)
		rbq_set_get_buf_mode(offline_link_rbq_handle, RBQ_GET_BUF_BLOCK); 

	offline_link_send_pv_handle = rbq_malloc(OFFLINE_MAX_NUM(comm_init->pv_send_rbq.write_thr_num, comm_init->pv_send_rbq.send_thr_num), comm_init->pv_send_rbq.send_qlen, comm_init->pv_send_rbq.send_qsize, comm_init->pv_send_rbq.write_thr_num, comm_init->pv_send_rbq.send_thr_num, "offline_pv_rbq_handle");
	assert(offline_link_send_pv_handle != NULL);
	rbq_overcommit(offline_link_send_pv_handle, 50*1024*1024, 10*1024*1024);
	if(comm_init->pv_send_rbq.block_mod == 1)
		rbq_set_get_buf_mode(offline_link_send_pv_handle, RBQ_GET_BUF_BLOCK); 
	offline_link_send_handle = tcpsend_handle_init(comm_init->m2_send_rbq.send_thr_num, comm_init->m2_send_rbq.cpumap, "offline_link_send_handle");


	comm_init->link_send_rbq.group_param.work_mode = TCPSEND_MODE_NORMAL;
	comm_init->link_send_rbq.group_param.rbq_handle = offline_link_rbq_handle;
	comm_init->m2_send_rbq.group_param.work_mode = TCPSEND_MODE_NORMAL;
	comm_init->m2_send_rbq.group_param.rbq_handle = offline_link_send_rbq_handle;
	comm_init->pv_send_rbq.group_param.work_mode = TCPSEND_MODE_NORMAL;
	comm_init->pv_send_rbq.group_param.rbq_handle = offline_link_send_pv_handle;


	tcpsend_handle_add_group(offline_link_send_handle, &comm_init->link_send_rbq.group_param);
	tcpsend_handle_add_group(offline_link_send_handle, &comm_init->m2_send_rbq.group_param);
	tcpsend_handle_add_group(offline_link_send_handle, &comm_init->pv_send_rbq.group_param);

	tcpsend_handle_start(offline_link_send_handle);

	for(i = 0; i < comm_init->m2_send_rbq.send_thr_num; i++)
	{
		int ret = pthread_create(&pid[i], NULL, offline_link_dis_proc, NULL); 
		if(ret != 0)
		{
			printf("pthread_create offline_link_dis_proc fail\n");
			exit(0);
		}
	}
	return ;
}
rbq_buf_t *offline_comm_pv_begin_store(void *rbq_handle, const int thr_id, const uint64_t total_len)
{
	rbq_buf_t *rbq_buf = NULL;
	if(thr_id < 0 || total_len <= 0)
		    return NULL;
	while(1)
	{
		rbq_buf = rbq_get_buf(rbq_handle, total_len, 1, thr_id);
		if(rbq_buf != NULL)
			break;
		usleep(10);
	}
	assert(rbq_buf != NULL);
	return rbq_buf;
}
rbq_buf_t *offline_comm_begin_store(void *rbq_handle, const int thr_id, const uint64_t total_len, uint32_t *pmsg_cont_len, body_header_t **pbody_header)
{
	rbq_buf_t *rbq_buf = NULL;
	msg_header_t *msg_header = NULL;
	body_header_t *body_header = NULL;
	if(thr_id < 0 || total_len <= 0)
		    return NULL;
	while(1)
	{
		rbq_buf = rbq_get_buf(rbq_handle, total_len, 1, thr_id);
		if(rbq_buf != NULL)
			break;
		usleep(10);
	}
	assert(rbq_buf != NULL);

	msg_header = (msg_header_t *)(rbq_buf->buf);
	msg_header->magic_num = offline_my_htonl(Magic_Value);
	msg_header->checksum = 0;
	msg_header->msg_type = offline_my_htons(OFFLINE_CONNECTLOG_DATA_TYPE);
	msg_header->cont_len = 0;

	body_header = (body_header_t *)( rbq_buf->buf + sizeof(msg_header_t) + offline_my_ntohl(msg_header->cont_len) );
	body_header->type = offline_my_htonl(OFFLINE_CONNECTLOG_DEVICE_TYPE);
	body_header->len = 0;
	
	msg_header->cont_len = offline_my_htonl( offline_my_ntohl(msg_header->cont_len) + sizeof(body_header_t) );
	*pmsg_cont_len = offline_my_ntohl(msg_header->cont_len);
	*pbody_header = body_header;

	return rbq_buf;
}
void offline_comm_begin_add_big_record(rbq_buf_t *rbq_buf, const int thr_id, const uint32_t data_type, uint32_t *pmsg_cont_len, body_header_t **pbody_header)
{
	body_header_t *body_header = NULL;
	int tmp_len = 0;

	if(rbq_buf == NULL || thr_id < 0)	
		return;
	msg_header_t *msg_header = (msg_header_t *)(rbq_buf->buf);
	assert( offline_my_ntohl(msg_header->magic_num) == Magic_Value );

	tmp_len = sizeof(msg_header_t) + offline_my_ntohl(msg_header->cont_len) + sizeof(body_header_t);
	if(tmp_len > rbq_buf->max_size)
		    return ;

	body_header = (body_header_t *)( rbq_buf->buf + sizeof(msg_header_t) + offline_my_ntohl(msg_header->cont_len) );
	body_header->type = offline_my_htonl(data_type);
	body_header->len = 0;

	msg_header->cont_len = offline_my_htonl( offline_my_ntohl(msg_header->cont_len) + sizeof(body_header_t) );

	*pmsg_cont_len = offline_my_ntohl(msg_header->cont_len);
	*pbody_header = body_header;

	return;
}
void offline_comm_add_one_sub_record(rbq_buf_t *rbq_buf, const int thr_id, const uint32_t data_type, const uint8_t *data, const uint32_t data_len)
{
	body_header_t *body_header = NULL;
	uint8_t *buff = NULL;
	int tmp_len = 0;
	if(thr_id < 0 || data_len == 0)
		return;
	msg_header_t *msg_header = (msg_header_t *)(rbq_buf->buf);
	assert( ntohl(msg_header->magic_num) == Magic_Value );

	tmp_len = (sizeof(msg_header_t) + offline_my_ntohl(msg_header->cont_len)) + (sizeof(body_header_t) + data_len);
	if(tmp_len > rbq_buf->max_size)
		    return ;

	body_header = (body_header_t *)(rbq_buf->buf + sizeof(msg_header_t) + offline_my_ntohl(msg_header->cont_len));
	body_header->type = offline_my_htonl(data_type);
	body_header->len = offline_my_htonl(data_len);

	buff = (uint8_t *)(rbq_buf->buf + sizeof(msg_header_t) + offline_my_ntohl(msg_header->cont_len) + sizeof(body_header_t));
	memcpy(buff, data, data_len);

	msg_header->cont_len = offline_my_htonl( offline_my_ntohl(msg_header->cont_len) + sizeof(body_header_t) + data_len );
	return;
}
void offline_comm_end_add_big_record(rbq_buf_t *rbq_buf, const int thr_id,  const uint32_t msg_cont_len, body_header_t *body_header)
{
	int data_len = 0;
	if(rbq_buf == NULL || thr_id < 0)	
		return;
	msg_header_t *msg_header = (msg_header_t *)(rbq_buf->buf);
	assert( offline_my_ntohl(msg_header->magic_num) == Magic_Value );

	data_len = offline_my_ntohl(msg_header->cont_len) - msg_cont_len;
	body_header->len = offline_my_htonl(data_len);
	return;
}
void offline_comm_end_store(void *rbq_handle, rbq_buf_t *rbq_buf, int thr_id, uint32_t msg_cont_len, body_header_t *body_header)
{
	msg_header_t *msg_header = NULL;
	int data_len = 0;
	uint32_t magic = 0;
	uint32_t length = 0;
	uint32_t type = 0;
	uint16_t checksum = 0;
	if( rbq_buf == NULL || thr_id < 0)
		goto leave;
	msg_header = (msg_header_t *)(rbq_buf->buf);
	assert( offline_my_ntohl(msg_header->magic_num) == Magic_Value );
	type = (uint32_t)(offline_my_ntohs(msg_header->msg_type));
	magic = offline_my_ntohl(msg_header->magic_num);
	length = offline_my_ntohl(msg_header->cont_len);
	checksum = ( ((type << 16) | type) ^ magic ^ length );
	msg_header->checksum = offline_my_htons( checksum );
	data_len = offline_my_ntohl(msg_header->cont_len) - msg_cont_len;
	body_header->len = offline_my_htonl(data_len);
	rbq_buf->len = sizeof(msg_header_t) + offline_my_ntohl(msg_header->cont_len);
	rbq_buf->msg_num++;                                                  
	rbq_put_data(rbq_handle, rbq_buf);
leave:
	return;
}
void offline_comm_pv_end_store(void *rbq_handle, rbq_buf_t *rbq_buf, int thr_id)
{
	if( rbq_buf == NULL || thr_id < 0)
		goto leave;
	rbq_buf->msg_num++;                                                  
	rbq_put_data(rbq_handle, rbq_buf);
leave:
	return;
}
static uint32_t offline_comm_ele_vender_base_total_len(offline_link_vender_t *pvender)
{
	uint32_t total_len = 0;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(pvender->channel);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(pvender->cap_timestamp);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(pvender->analysis_timestamp);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + pvender->sessid_len;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + pvender->path_len;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + pvender->userinfolen;

	total_len += OFFLINE_COMM_BODY_HEAD_LEN;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(offline_connect_log_info_t);
	return total_len;
}

static void  offline_comm_add_vender_base_record(rbq_buf_t *rbq_buf, int thr_id, uint16_t pro_type, offline_link_vender_t *pvender)
{
	body_header_t *body_header = NULL;
	uint32_t    msg_cont_len = 0;
	if(thr_id < 0 || pvender == NULL)
	{   
		printf("offline_comm_add_vender_base_record fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		return ;
	}
	uint16_t tmp_pro_type = pro_type;
	offline_connect_log_info_t connect_log_info;
	memset(&connect_log_info, 0, sizeof(offline_connect_log_info_t));
	connect_log_info.log_type = ONLY_SELF_TYPE;
	connect_log_info.padl[2] |= hy_exist_flag;
	tmp_pro_type = offline_my_htons(tmp_pro_type);
	memcpy(connect_log_info.padl, &tmp_pro_type, sizeof(uint16_t));
	connect_log_info.conn_start_time = offline_my_hton64(jiffies);  
	connect_log_info.log_gen_time = offline_my_hton64(jiffies/1000);

	offline_comm_begin_add_big_record(rbq_buf, thr_id, OFFLINE_CONNECTLOG_BASE_INFO_TYPE, &msg_cont_len, &body_header);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_basic_sample_type, (uint8_t *)(&connect_log_info), sizeof(offline_connect_log_info_t));	
	offline_comm_end_add_big_record(rbq_buf, thr_id, msg_cont_len, body_header);

	uint32_t int_32 = 0;
	uint64_t int_64 = 0;
	body_header_t *body_header_vd = NULL;
	uint32_t    msg_cont_len_vd = 0;


	offline_comm_begin_add_big_record(rbq_buf, thr_id, OFFLINE_CONNECTLOG_USER_VENDOR_TYPE, &msg_cont_len, &body_header);
	if(pvender->userinfolen > 0)
		offline_comm_add_one_sub_record(rbq_buf, thr_id, pvender->userinfotype, (uint8_t *)pvender->userinfo, pvender->userinfolen); 
	offline_comm_begin_add_big_record(rbq_buf, thr_id, offline_connectlog_normal_vendor_type, &msg_cont_len_vd, &body_header_vd);
	int_32 = ntohl(pvender->channel);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_user_vendor_channel_type, (uint8_t *)&int_32, sizeof(uint32_t));	
	if(pvender->sessid_len > 0)
		offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_user_vendor_session_id_type, (uint8_t *)pvender->sessid, pvender->sessid_len);
	int_64 = ntoh64(pvender->cap_timestamp);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_user_vendor_cap_timestamp_type, (uint8_t *)&int_64, sizeof(uint64_t));
   int_64 = ntoh64(pvender->analysis_timestamp);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_user_vendor_analysis_timestamp_type, (uint8_t *)&int_64, sizeof(uint64_t));   
	if(pvender->path_len > 0)
		offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_user_vendor_filename_type, (uint8_t *)pvender->path, pvender->path_len);
	offline_comm_end_add_big_record(rbq_buf, thr_id, msg_cont_len_vd, body_header_vd);
	offline_comm_end_add_big_record(rbq_buf, thr_id, msg_cont_len, body_header);
}
static void offline_comm_add_frame_relay_record(rbq_buf_t *rbq_buf, int thr_id, ll_frame_relay_t *frame_relay, offline_link_vender_t *pvender)
{
	body_header_t *body_header = NULL;
	uint32_t    msg_cont_len = 0;
	if(thr_id < 0 || frame_relay == NULL)
	{
		printf("offline_comm_add_frame_relay_record failure!\n");
		return ;
	}
	offline_comm_add_vender_base_record(rbq_buf, thr_id, offline_pro_type_atm, pvender);
	offline_comm_begin_add_big_record(rbq_buf, thr_id, OFFLINE_CONNECTLOG_FRAME_REALY_TYPE, &msg_cont_len, &body_header);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_frame_relay_addr_type, (uint8_t *)(frame_relay->addr), sizeof(frame_relay->addr));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_frame_relay_control_type, (uint8_t *)&(frame_relay->control), sizeof(frame_relay->control));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_frame_relay_nlpid_type, (uint8_t *)&(frame_relay->nlpid), sizeof(uint8_t));
	offline_comm_end_add_big_record(rbq_buf, thr_id, msg_cont_len, body_header);

	return;
}
static void offline_comm_add_x25_record(rbq_buf_t *rbq_buf, int thr_id, ll_x25_t *x25, offline_link_vender_t *pvender)
{
	body_header_t *body_header = NULL;
	uint32_t    msg_cont_len = 0;
	if(thr_id < 0 || x25 == NULL)
	{
		printf("offline_comm_add_x25_record failure!\n");
		return ;
	}
	offline_comm_add_vender_base_record(rbq_buf, thr_id, offline_pro_type_x25, pvender);
	offline_comm_begin_add_big_record(rbq_buf, thr_id, OFFLINE_CONNECTLOG_X25_TYPE, &msg_cont_len, &body_header);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_x25_hdr_type, (uint8_t *)(x25->hdr), sizeof(x25->hdr));
	offline_comm_end_add_big_record(rbq_buf, thr_id, msg_cont_len, body_header);
	return;
}

static void offline_comm_add_dvbgs_record(rbq_buf_t *rbq_buf, int thr_id, ll_dvbgs_t *dvbgs, offline_link_vender_t *pvender)
{
	body_header_t *body_header = NULL;
	uint32_t    msg_cont_len = 0;
	if(thr_id < 0 || dvbgs == NULL)
	{
		printf("offline_comm_add_dvbgs_record failure!\n");
		return ;
	}
	offline_comm_add_vender_base_record(rbq_buf, thr_id, offline_pro_type_dvbts, pvender);
	offline_comm_begin_add_big_record(rbq_buf, thr_id, OFFLINE_CONNECTLOG_DVBGS_TYPE, &msg_cont_len, &body_header);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_dvbgs_signal_type_type,  (uint8_t *)&(dvbgs->signal_type), sizeof(dvbgs->signal_type));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_dvbgs_str_type_type, (uint8_t *)&(dvbgs->str_type), sizeof(dvbgs->str_type));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_dvbgs_str_mode_type, (uint8_t *)&(dvbgs->str_mode), sizeof(dvbgs->str_mode));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_dvbgs_str_id_type,  (uint8_t *)&(dvbgs->str_id), sizeof(dvbgs->str_id));
	offline_comm_end_add_big_record(rbq_buf, thr_id, msg_cont_len, body_header);

	return;
}
static void offline_comm_add_cisco_ppp_record(rbq_buf_t *rbq_buf, int thr_id, ll_cisco_ppp_t *cisco_ppp, offline_link_vender_t *pvender)
{
	body_header_t *body_header = NULL;
	uint32_t    msg_cont_len = 0;
	if(thr_id < 0 || cisco_ppp == NULL)
	{
		printf("offline_comm_add_cisco_ppp_record failure!\n");
		return ;
	}
	offline_comm_add_vender_base_record(rbq_buf, thr_id, offline_pro_type_cisco_ppp, pvender);
	offline_comm_begin_add_big_record(rbq_buf, thr_id, OFFLINE_CONNECTLOG_CISCO_PPP_TYPE, &msg_cont_len, &body_header);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_cisco_ppp_addr_type, (uint8_t *)&(cisco_ppp->addr), sizeof(uint8_t));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_cisco_ppp_control_type, (uint8_t *)&(cisco_ppp->control), sizeof(uint8_t));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_cisco_ppp_ether_type_type, (uint8_t *)&(cisco_ppp->ether_type), sizeof(uint16_t));
	offline_comm_end_add_big_record(rbq_buf, thr_id, msg_cont_len, body_header);

	return;
}
static void offline_comm_add_ppp_record(rbq_buf_t *rbq_buf, int thr_id, ll_ppp_t *ppp, offline_link_vender_t *pvender)
{
	body_header_t *body_header = NULL;
	uint32_t    msg_cont_len = 0;
	if(thr_id < 0 || ppp == NULL)
	{
		printf("offline_comm_add_ppp_record failure!\n");
		return;
	}
	offline_comm_add_vender_base_record(rbq_buf, thr_id, offline_pro_type_ppp, pvender);
	offline_comm_begin_add_big_record(rbq_buf, thr_id, OFFLINE_CONNECTLOG_PPP_TYPE, &msg_cont_len, &body_header);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_ppp_addr_type, (uint8_t *)&(ppp->addr), sizeof(uint8_t));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_ppp_control_type, (uint8_t *)&(ppp->control), sizeof(uint8_t));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_ppp_proto_type, (uint8_t *)&(ppp->proto), sizeof(uint16_t));
	offline_comm_end_add_big_record(rbq_buf, thr_id, msg_cont_len, body_header);

	return;
}
static void offline_comm_add_sppp_record(rbq_buf_t *rbq_buf, int thr_id, ll_sppp_t *sppp, offline_link_vender_t *pvender)
{
	body_header_t *body_header = NULL;
	uint32_t    msg_cont_len = 0;
	if(thr_id < 0 || sppp == NULL)
	{
		printf("offline_comm_add_sppp_record failure!\n");
		return;
	}
	offline_comm_add_vender_base_record(rbq_buf, thr_id, offline_pro_type_sppp, pvender);
	offline_comm_begin_add_big_record(rbq_buf, thr_id, OFFLINE_CONNECTLOG_SPPP_TYPE, &msg_cont_len, &body_header);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_sppp_line_name_type, (uint8_t *)(sppp->line_name), sizeof(sppp->line_name));  
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_sppp_line_dir_type,  (uint8_t *)&(sppp->line_dir), sizeof(sppp->line_dir));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_sppp_line_bw_type,   (uint8_t *)&(sppp->line_bw), sizeof(sppp->line_bw));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_sppp_load_type_type,  (uint8_t *)&(sppp->load_type), sizeof(sppp->load_type));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_sppp_timestamp_type,  (uint8_t *)(sppp->timestamp), sizeof(sppp->timestamp));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_sppp_src_addr_type,  (uint8_t *)&(sppp->src_addr), sizeof(sppp->src_addr));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_sppp_dst_addr_type,  (uint8_t *)&(sppp->dst_addr), sizeof(sppp->dst_addr));
	offline_comm_end_add_big_record(rbq_buf, thr_id, msg_cont_len, body_header);

	return;
}

static void offline_comm_add_dvbts_record(rbq_buf_t *rbq_buf, int thr_id, ll_dvbts_t *dvbts, offline_link_vender_t *pvender)
{
	body_header_t *body_header = NULL;
	uint32_t    msg_cont_len = 0;
	if(thr_id < 0 || dvbts == NULL)
	{
		printf("offline_comm_add_dvbts_record failure!\n");
		return ;
	}
	offline_comm_add_vender_base_record(rbq_buf, thr_id, offline_pro_type_dvbts, pvender);
	offline_comm_begin_add_big_record(rbq_buf, thr_id, OFFLINE_CONNECTLOG_DVBTS_TYPE, &msg_cont_len, &body_header);

	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_dvbts_pdumac_type,  (uint8_t *)(dvbts->pdumac), sizeof(dvbts->pdumac));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_dvbts_mpe_hdr_type, (uint8_t *)(dvbts->mpe_hdr), sizeof(dvbts->mpe_hdr));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_dvbts_str_type_type,  (uint8_t *)&(dvbts->str_type), sizeof(dvbts->str_type));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_dvbts_str_mode_type, (uint8_t *)&(dvbts->str_mode), sizeof(dvbts->str_mode));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_dvbts_isi_type,  (uint8_t *)&(dvbts->isi), sizeof(dvbts->isi));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_dvbts_pid_type, (uint8_t *)&(dvbts->pid), sizeof(dvbts->pid));

	offline_comm_end_add_big_record(rbq_buf, thr_id, msg_cont_len, body_header);

	return;
}

static void offline_comm_add_atm_record(rbq_buf_t *rbq_buf, int thr_id, ll_atm_t *atm, offline_link_vender_t *pvender)
{
	body_header_t *body_header = NULL;
	uint32_t    msg_cont_len = 0;
	if(thr_id < 0 || atm == NULL)
	{
		printf("offline_comm_add_atm_record failure!\n");
		return ;
	}
	offline_comm_add_vender_base_record(rbq_buf, thr_id, offline_pro_type_atm, pvender);
	offline_comm_begin_add_big_record(rbq_buf, thr_id, OFFLINE_CONNECTLOG_ATM_TYPE, &msg_cont_len, &body_header);

	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_atm_vpi_type,  (uint8_t *)&(atm->vpi), sizeof(atm->vpi));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_atm_vci_type, (uint8_t *)&(atm->vci), sizeof(atm->vci));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_atm_pti_type,  (uint8_t *)&(atm->pti), sizeof(atm->pti));
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_atm_all_type_type, (uint8_t *)&(atm->all_type), sizeof(atm->all_type));

	offline_comm_end_add_big_record(rbq_buf, thr_id, msg_cont_len, body_header);

	return;
}
static void offline_comm_ele_frame_relay_info_entry(ll_frame_relay_t *frame_relay, offline_link_vender_t *pvender, int thr_id)
{
	rbq_buf_t *rbq_buf = NULL;
	uint32_t  total_len = 0;
	total_len += OFFLINE_COMM_RETAIN_LEN;
	total_len += OFFLINE_COMM_MSG_HEAD_LEN;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12 + OFFLINE_COMM_ELE_LL_RETAIN_LEN;

	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(frame_relay->addr);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(frame_relay->control);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(frame_relay->nlpid);
	total_len += offline_comm_ele_vender_base_total_len(pvender);
	uint32_t msg_cont_len = 0;
	body_header_t *body_header = NULL;
	rbq_buf = offline_comm_begin_store(offline_link_rbq_handle, thr_id, total_len, &msg_cont_len, &body_header);
	if(rbq_buf == NULL)
	{
		return ;
	}
	offline_comm_add_frame_relay_record(rbq_buf, thr_id, frame_relay, pvender);
	offline_comm_end_store(offline_link_rbq_handle, rbq_buf, thr_id, msg_cont_len, body_header);
}
static void offline_comm_ele_x25_info_entry(ll_x25_t *x25, offline_link_vender_t *pvender, int thr_id)
{
	rbq_buf_t *rbq_buf = NULL;
	uint32_t  total_len = 0;
	total_len += OFFLINE_COMM_RETAIN_LEN;
	total_len += OFFLINE_COMM_MSG_HEAD_LEN;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12 + OFFLINE_COMM_ELE_LL_RETAIN_LEN;

	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(x25->hdr);
	total_len += offline_comm_ele_vender_base_total_len(pvender);
	uint32_t msg_cont_len = 0;
	body_header_t *body_header = NULL;
	rbq_buf = offline_comm_begin_store(offline_link_rbq_handle, thr_id, total_len, &msg_cont_len, &body_header);
	if(rbq_buf == NULL)
	{
		return ;
	}
	offline_comm_add_x25_record(rbq_buf, thr_id, x25, pvender);
	offline_comm_end_store(offline_link_rbq_handle, rbq_buf, thr_id, msg_cont_len, body_header);
}
static void offline_comm_ele_dvbts_info_entry(ll_dvbts_t *dvbts, offline_link_vender_t *pvender, int thr_id)
{
	rbq_buf_t *rbq_buf = NULL;
	uint32_t  total_len = 0;
	total_len += OFFLINE_COMM_RETAIN_LEN;
	total_len += OFFLINE_COMM_MSG_HEAD_LEN;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12 + OFFLINE_COMM_ELE_LL_RETAIN_LEN;

	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(dvbts->pdumac);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(dvbts->mpe_hdr);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(dvbts->str_type);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(dvbts->str_mode);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(dvbts->isi);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(dvbts->pid);

	total_len += offline_comm_ele_vender_base_total_len(pvender);
	uint32_t msg_cont_len = 0;
	body_header_t *body_header = NULL;
	rbq_buf = offline_comm_begin_store(offline_link_rbq_handle, thr_id, total_len, &msg_cont_len, &body_header);
	if(rbq_buf == NULL)
	{
		return ;
	}
	offline_comm_add_dvbts_record(rbq_buf, thr_id, dvbts, pvender);
	offline_comm_end_store(offline_link_rbq_handle, rbq_buf, thr_id, msg_cont_len, body_header);
}
static void offline_comm_ele_dvbgs_info_entry(ll_dvbgs_t *dvbgs, offline_link_vender_t *pvender, int thr_id)
{
	rbq_buf_t *rbq_buf = NULL;
	uint32_t  total_len = 0;
	total_len += OFFLINE_COMM_RETAIN_LEN;
	total_len += OFFLINE_COMM_MSG_HEAD_LEN;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12 + OFFLINE_COMM_ELE_LL_RETAIN_LEN;

	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(dvbgs->signal_type);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(dvbgs->str_type);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(dvbgs->str_mode);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(dvbgs->str_id);

	total_len += offline_comm_ele_vender_base_total_len(pvender);
	uint32_t msg_cont_len = 0;
	body_header_t *body_header = NULL;
	rbq_buf = offline_comm_begin_store(offline_link_rbq_handle, thr_id, total_len, &msg_cont_len, &body_header);
	if(rbq_buf == NULL)
	{
		return ;
	}
	offline_comm_add_dvbgs_record(rbq_buf, thr_id, dvbgs, pvender);
	offline_comm_end_store(offline_link_rbq_handle, rbq_buf, thr_id, msg_cont_len, body_header);
}
static void offline_comm_ele_cisco_ppp_info_entry(ll_cisco_ppp_t *cisco_ppp, offline_link_vender_t *pvender, int thr_id)
{
	rbq_buf_t *rbq_buf = NULL;
	uint32_t  total_len = 0;
	total_len += OFFLINE_COMM_RETAIN_LEN;
	total_len += OFFLINE_COMM_MSG_HEAD_LEN;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12 + OFFLINE_COMM_ELE_LL_RETAIN_LEN;

	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(cisco_ppp->addr);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(cisco_ppp->control);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(cisco_ppp->ether_type);

	total_len += offline_comm_ele_vender_base_total_len(pvender);
	uint32_t msg_cont_len = 0;
	body_header_t *body_header = NULL;
	rbq_buf = offline_comm_begin_store(offline_link_rbq_handle, thr_id, total_len, &msg_cont_len, &body_header);
	if(rbq_buf == NULL)
	{
		return ;
	}
	offline_comm_add_cisco_ppp_record(rbq_buf, thr_id, cisco_ppp, pvender);
	offline_comm_end_store(offline_link_rbq_handle, rbq_buf, thr_id, msg_cont_len, body_header);
}
static void offline_comm_ele_ppp_info_entry(ll_ppp_t *ppp, offline_link_vender_t *pvender, int thr_id)
{
	rbq_buf_t *rbq_buf = NULL;
	uint32_t  total_len = 0;
	total_len += OFFLINE_COMM_RETAIN_LEN;
	total_len += OFFLINE_COMM_MSG_HEAD_LEN;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12 + OFFLINE_COMM_ELE_LL_RETAIN_LEN;

	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(ppp->addr);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(ppp->control);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(ppp->proto);

	total_len += offline_comm_ele_vender_base_total_len(pvender);
	uint32_t msg_cont_len = 0;
	body_header_t *body_header = NULL;
	rbq_buf = offline_comm_begin_store(offline_link_rbq_handle, thr_id, total_len, &msg_cont_len, &body_header);
	if(rbq_buf == NULL)
	{
		return ;
	}
	offline_comm_add_ppp_record(rbq_buf, thr_id, ppp, pvender);
	offline_comm_end_store(offline_link_rbq_handle, rbq_buf, thr_id, msg_cont_len, body_header);
}
static void offline_comm_ele_sppp_info_entry(ll_sppp_t *sppp, offline_link_vender_t *pvender, int thr_id)
{
	rbq_buf_t *rbq_buf = NULL;
	uint32_t  total_len = 0;
	total_len += OFFLINE_COMM_RETAIN_LEN;
	total_len += OFFLINE_COMM_MSG_HEAD_LEN;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12 + OFFLINE_COMM_ELE_LL_RETAIN_LEN;

	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(sppp->line_name);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(sppp->line_dir);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(sppp->line_bw);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(sppp->load_type);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(sppp->timestamp);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(sppp->src_addr);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(sppp->dst_addr);

	total_len += offline_comm_ele_vender_base_total_len(pvender);
	uint32_t msg_cont_len = 0;
	body_header_t *body_header = NULL;
	rbq_buf = offline_comm_begin_store(offline_link_rbq_handle, thr_id, total_len, &msg_cont_len, &body_header);
	if(rbq_buf == NULL)
	{
		return ;
	}
	offline_comm_add_sppp_record(rbq_buf, thr_id, sppp, pvender);
	offline_comm_end_store(offline_link_rbq_handle, rbq_buf, thr_id, msg_cont_len, body_header);
}

static void offline_comm_ele_atm_info_entry(ll_atm_t *atm, offline_link_vender_t *pvender, int thr_id)
{
	rbq_buf_t *rbq_buf = NULL;
	uint32_t  total_len = 0;
	total_len += OFFLINE_COMM_RETAIN_LEN;
	total_len += OFFLINE_COMM_MSG_HEAD_LEN;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12 + OFFLINE_COMM_ELE_LL_RETAIN_LEN;

	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(atm->vpi);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(atm->vci);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(atm->pti);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(atm->all_type);
	total_len += offline_comm_ele_vender_base_total_len(pvender);
	uint32_t msg_cont_len = 0;
	body_header_t *body_header = NULL;
	rbq_buf = offline_comm_begin_store(offline_link_rbq_handle, thr_id, total_len, &msg_cont_len, &body_header);
	if(rbq_buf == NULL)
	{
		return ;
	}
	offline_comm_add_atm_record(rbq_buf, thr_id, atm, pvender);
	offline_comm_end_store(offline_link_rbq_handle, rbq_buf, thr_id, msg_cont_len, body_header);
}
static void offline_comm_add_iphc_record(rbq_buf_t *rbq_buf, int thr_id, fbl2_iphc_result_t *iphc, offline_link_vender_t *pvender)
{
	body_header_t *body_header = NULL;
	uint32_t    msg_cont_len = 0;
	uint32_t int_32 = 0;
	if(thr_id < 0 || iphc == NULL)
	{
		printf("offline_comm_add_iphc_record failure!\n");
		return ;
	}
	offline_comm_add_vender_base_record(rbq_buf, thr_id, offline_pro_type_iphc, pvender);
	offline_comm_begin_add_big_record(rbq_buf, thr_id, OFFLINE_CONNECTLOG_IPHC_TYPE, &msg_cont_len, &body_header);
	int_32 = ntohl(iphc->cid);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_iphc_cid_type, (uint8_t *)&int_32, sizeof(uint32_t));
	int_32 = ntohl(iphc->compralg);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_iphc_compralg_type, (uint8_t *)&int_32, sizeof(uint32_t));
	int_32 = ntohl(iphc->frame_type);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_iphc_frame_type_type, (uint8_t *)&int_32, sizeof(uint32_t));
	int_32 = ntohl(iphc->seq_num);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, offline_connectlog_iphc_seq_num_type, (uint8_t *)&int_32, sizeof(uint32_t));
	offline_comm_end_add_big_record(rbq_buf, thr_id, msg_cont_len, body_header);

	return;
}

void offline_comm_ele_iphc_info_entry(fbl2_iphc_result_t *iphc, offline_link_vender_t *pvender, int thr_id)
{
	rbq_buf_t *rbq_buf = NULL;
	uint32_t  total_len = 0;
	total_len += OFFLINE_COMM_RETAIN_LEN;
	total_len += OFFLINE_COMM_MSG_HEAD_LEN;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12 + OFFLINE_COMM_ELE_LL_RETAIN_LEN;

	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(iphc->cid);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(iphc->compralg);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(iphc->frame_type);
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + sizeof(iphc->seq_num);
	total_len += offline_comm_ele_vender_base_total_len(pvender);
	uint32_t msg_cont_len = 0;
	body_header_t *body_header = NULL;
	rbq_buf = offline_comm_begin_store(offline_link_rbq_handle, thr_id, total_len, &msg_cont_len, &body_header);
	if(rbq_buf == NULL)
	{
		return ;
	}
	offline_comm_add_iphc_record(rbq_buf, thr_id, iphc, pvender);
	offline_comm_end_store(offline_link_rbq_handle, rbq_buf, thr_id, msg_cont_len, body_header);
}

static void offline_comm_add_fd_record(rbq_buf_t *rbq_buf, int thr_id, online_fd_t *fd, uint16_t pro_type, uint8_t *data, uint32_t datalen, offline_link_vender_t *pvender)
{
	body_header_t *body_header = NULL;
	uint32_t    msg_cont_len = 0;
	if(thr_id < 0 || fd == NULL)
	{
		printf("offline_comm_add_fd_record failure!\n");
		return ;
	}
	offline_comm_add_vender_base_record(rbq_buf, thr_id, pro_type, pvender);
	offline_comm_begin_add_big_record(rbq_buf, thr_id, fd->m2BigType, &msg_cont_len, &body_header);
	offline_comm_add_one_sub_record(rbq_buf, thr_id, fd->m2AddType, (uint8_t *)data, datalen);
	offline_comm_end_add_big_record(rbq_buf, thr_id, msg_cont_len, body_header);
	return;
}
void offline_comm_ele_pv_entry(online_pv_t *pv, uint8_t *data, uint32_t datalen, int thr_id)
{
	rbq_buf_t *rbq_buf = NULL;
	uint32_t  total_len = 0;
	total_len += datalen;
	
	rbq_buf = offline_comm_pv_begin_store(offline_link_send_pv_handle, thr_id, total_len);
	if(rbq_buf == NULL)
	{                  
		return ;       
	}         
	rbq_buf->len = datalen;
	memcpy(rbq_buf->buf, data, datalen);	
	offline_comm_pv_end_store(offline_link_send_pv_handle, rbq_buf, thr_id);
	return;
}

void offline_comm_ele_fd_entry(online_fd_t *fd, uint8_t *data, uint32_t datalen, offline_link_vender_t *pvender, uint16_t pro_type, int thr_id)
{
	rbq_buf_t *rbq_buf = NULL;
	uint32_t  total_len = 0;
	total_len += OFFLINE_COMM_RETAIN_LEN;
	total_len += OFFLINE_COMM_MSG_HEAD_LEN;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12;
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + 12 + OFFLINE_COMM_ELE_LL_RETAIN_LEN;
	
	total_len += OFFLINE_COMM_BODY_HEAD_LEN + datalen;
	total_len += offline_comm_ele_vender_base_total_len(pvender);
	uint32_t msg_cont_len = 0;        
	body_header_t *body_header = NULL;
	rbq_buf = offline_comm_begin_store(offline_link_rbq_handle, thr_id, total_len, &msg_cont_len, &body_header);
	if(rbq_buf == NULL)
	{                  
		return ;       
	}                  
	offline_comm_add_fd_record(rbq_buf, thr_id, fd, pro_type, data, datalen, pvender);
	offline_comm_end_store(offline_link_rbq_handle, rbq_buf, thr_id, msg_cont_len, body_header);
}

void offline_comm_ele_ll_info_entry(uint32_t type, uint8_t *tags, offline_link_vender_t *pvender, int thr_id)
{
	ll_cisco_ppp_t   * cisco_ppp    = NULL;
	ll_ppp_t         * ppp          = NULL;
	ll_frame_relay_t * frame_relay  = NULL;
	ll_x25_t         * x25          = NULL;
	ll_dvbts_t       * dvbts        = NULL;
	ll_dvbgs_t       * dvbgs        = NULL;
	ll_atm_t         * atm          = NULL;
	ll_sppp_t        * sppp         = NULL;
	
	switch(type)
	{
		case LL_TYPE_ATM:
			atm = (ll_atm_t *)tags;
			offline_comm_ele_atm_info_entry(atm, pvender, thr_id);
			break;
		case LL_TYPE_FRAME_RELAY:
			frame_relay = (ll_frame_relay_t *)tags;
			offline_comm_ele_frame_relay_info_entry(frame_relay, pvender, thr_id);
			break;
		case LL_TYPE_X25:
			x25 = (ll_x25_t *)tags;
			offline_comm_ele_x25_info_entry(x25, pvender, thr_id);	
			break;
		case LL_TYPE_DVBTS:
			dvbts = (ll_dvbts_t *)tags;
			offline_comm_ele_dvbts_info_entry(dvbts, pvender, thr_id);
			break;
		case LL_TYPE_DVBGS:
			dvbgs = (ll_dvbgs_t *)tags;
			offline_comm_ele_dvbgs_info_entry(dvbgs, pvender, thr_id);
			break;
		case LL_TYPE_CISCO_PPP:
			cisco_ppp = (ll_cisco_ppp_t *)tags;
			offline_comm_ele_cisco_ppp_info_entry(cisco_ppp, pvender, thr_id);
			break;
		case LL_TYPE_PPP:
			ppp = (ll_ppp_t *)tags;
			offline_comm_ele_ppp_info_entry(ppp, pvender, thr_id);
			break;	
		case LL_TYPE_SPPP_IP:
		case LL_TYPE_SPPP_CDP:
		case LL_TYPE_SPPP_LCP:
		case LL_TYPE_SPPP_CHAP:
		case LL_TYPE_SPPP_IPCP:
			sppp = (ll_sppp_t *)tags;
			offline_comm_ele_sppp_info_entry(sppp, pvender, thr_id);	
			break;
		default:

			break;
	}
	return;
}


