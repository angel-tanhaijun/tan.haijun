/*************************************************************************
	> File Name: offline.c
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月01日 星期一 09时55分11秒
 ************************************************************************/

#include "offline.h"
static char *libinfo __attribute__((unused))  = "\n@VERSION@:offline_proc, 3.0.0, "VERSION"\n" ;


static offline_init_t offinit;
static uint32_t offline_max_thr_num = 0;


void offline_status_get(offline_vshell_count_t *poffline_count, uint32_t channel, char *sessid, char *file_type, char *filename, char *err_info, uint32_t proc_type, uint32_t status_type, offline_status_ex_t *status_ex, int thr_id)
{
	if(offinit.rep_switch == 0)
		return;

	if(status_type == OFFLINE_STATUS_NOTF_MESS_TYPE)
		if((jiffies - poffline_count->djiffiesf) < (offinit.rep_timep * 1000))
			return;
	poffline_count->djiffiesf = jiffies;
	offline_status_t status;
	memset(&status, 0, sizeof(offline_status_t));	
	status.rep_switch  = offinit.rep_switch;
	status.channel     = channel;
	status.status_type = status_type;
	status.proc_type   = proc_type;

	if(sessid != NULL)
		snprintf(status.sessid, OFFLINE_SESSID_LEN, "%s", sessid); 
	if(file_type != NULL)
		snprintf(status.file_type, OFFLINE_MAX_BUFF_LEN, "%s", file_type);
	if(filename != NULL)
		snprintf(status.file_name, OFFLINE_MAX_BUFF_LEN, "%s", filename);
	if(err_info != NULL)
		snprintf(status.err_info, OFFLINE_MAX_BUFF_LEN, "%s", err_info);
	if(status_ex != NULL)
		snprintf(status.clientip, OFFLINE_CLIENTIP_LEN, "%s", status_ex->clientip);

	snprintf(status.rep_path, OFFLINE_MAX_PATH_LEN, "%s", offinit.rep_path);
	memcpy(&status.offline_count, poffline_count, sizeof(offline_vshell_count_t));	
	offline_status_getp2(&status, thr_id);
	return;
}

static void *offline_vshell_thread(void *ele)                    
{
	char thread_name[128] = {0};
	int cpu_id = 0;
	cpu_set_t mask;                                                                             
	CPU_ZERO(&mask);
	cpu_id = 20;
	CPU_SET(cpu_id, &mask);
	int ret = sched_setaffinity(0, sizeof(cpu_set_t), &mask);
	if(ret == -1)
		printf("%s(%d):vshell, cpu_id=%d, cpu bind failed\n", __FILE__, __LINE__, cpu_id);
	else
		printf("%s(%d):vshell, cpu_id=%d, cpu bind succeed\n", __FILE__, __LINE__, cpu_id);
	snprintf(thread_name, sizeof(thread_name), "vshell");
	prctl(PR_SET_NAME, thread_name);	
	vshell_start("0.0.0.0", offinit.vshell_port);
	return NULL;
}

void *offline_init(char *offline_cfg)
{
	xmlcfg_t tc;
	int err;
	char xpath[255];
	long v;
	char buff[215] = {0};	
	pthread_t vshell_id;
	
	printf("offline_init load %s\n", offline_cfg);
	if (xmlcfg_init_file(&tc, offline_cfg) != 0)
	{
		printf("load %s fail\n", offline_cfg);
		exit(0);
	}

	snprintf(xpath,255,"/conf/offline_mode");
	err = xmlcfg_get_long(&tc,xpath,&v);
	if(err)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}
	offinit.offline_mode = v;

	snprintf(xpath,255,"/conf/vshell_port");
	err = xmlcfg_get_long(&tc,xpath,&v);
	if(err)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}
	offinit.vshell_port = v;
	err = pthread_create(&vshell_id, NULL, offline_vshell_thread, NULL);
	if(err != 0)
	{
		printf("create offline_vshell_thread fail\n");
		return 0;
	}

	snprintf(xpath,255,"/conf/scan/scan_path");
	err = xmlcfg_get_str(&tc, xpath, offinit.scan_path, OFFLINE_MAX_PATH_LEN);
	if(err < 1)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}                                               

	snprintf(xpath,255,"/conf/scan/scan_thr_num");
	err = xmlcfg_get_long(&tc,xpath,&v);
	if(err)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}                                               
	offinit.thr_num = v;

	snprintf(xpath,255,"/conf/stat_rep/rep_switch");
	err = xmlcfg_get_long(&tc,xpath,&v);
	if(err)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}                                               
	offinit.rep_switch = v;

	snprintf(xpath,255,"/conf/stat_rep/rep_timep");
	err = xmlcfg_get_long(&tc,xpath,&v);
	if(err)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}                                               
	offinit.rep_timep = v;

	snprintf(xpath,255,"/conf/stat_rep/rep_timec");
	err = xmlcfg_get_long(&tc,xpath,&v);
	if(err)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}                                               
	offinit.rep_timec = v;


	snprintf(xpath,255,"/conf/stat_rep/rep_path");
	err = xmlcfg_get_str(&tc, xpath, offinit.rep_path, OFFLINE_MAX_PATH_LEN);
	if(err < 1)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}

	snprintf(xpath,255,"/conf/link_conn_path");
	err = xmlcfg_get_str(&tc, xpath, offinit.link_conn_path, OFFLINE_MAX_PATH_LEN);
	if(err < 1)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}

	snprintf(xpath,255,"/conf/m2_conn_path");
	err = xmlcfg_get_str(&tc, xpath, offinit.m2_conn_path, OFFLINE_MAX_PATH_LEN);
	if(err < 1)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}

	snprintf(xpath,255,"/conf/pv_conn_path");
	err = xmlcfg_get_str(&tc, xpath, offinit.pv_conn_path, OFFLINE_MAX_PATH_LEN);
	if(err < 1)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}

	snprintf(xpath,255,"/conf/dis_conn_path");
	err = xmlcfg_get_str(&tc, xpath, offinit.dis_conn_path, OFFLINE_MAX_PATH_LEN);
	if(err < 1)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}
	snprintf(xpath,255,"/conf/diy_lib/diy_lib_switch");
	err = xmlcfg_get_long(&tc,xpath,&v);
	if(err)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}                                               
	offinit.diy_lib_switch = v;
	if(offinit.diy_lib_switch == OFFLINE_SWITCH_OPEN)
	{
		snprintf(xpath,255,"/conf/diy_lib/diy_lib_path");
		err = xmlcfg_get_str(&tc, xpath, offinit.diy_lib_path, OFFLINE_MAX_PATH_LEN);
		if(err < 1)
		{
			printf("load %s fail\n",xpath);
			exit(0);
		}
	}
	snprintf(xpath,255,"/conf/online/online_conn_switch");
	err = xmlcfg_get_long(&tc,xpath,&v);
	if(err)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}                                               
	offinit.online_conn_swicth = v;
	
	snprintf(xpath,255,"/conf/mddw/mddw_dyn_switch");
	err = xmlcfg_get_long(&tc,xpath,&v);
	if(err)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}                                               
	offinit.mddw_dyn_switch = v;

	snprintf(xpath,255,"/conf/down_pcap/down_pcap_switch");
	err = xmlcfg_get_long(&tc,xpath,&v);
	if(err)
	{
		printf("load %s fail, default is 0\n",xpath);
		offinit.downswitch = 0;
	}                                               
	offinit.downswitch = v;
	
	snprintf(xpath,255,"/conf/down_pcap/down_pcap_path");
	err = xmlcfg_get_str(&tc, xpath, offinit.downpath, OFFLINE_MAX_PATH_LEN);
	if(err < 1)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}

	snprintf(xpath,255,"/conf/down_network/down_network_switch");
	err = xmlcfg_get_long(&tc,xpath,&v);
	if(err)
	{
		printf("load %s fail, default is 0\n",xpath);
		offinit.downlnwswitch = 0;
	}                                               
	offinit.downlnwswitch = v;
	
	snprintf(xpath,255,"/conf/down_network/down_network_path");
	err = xmlcfg_get_str(&tc, xpath, offinit.downlnwpath, OFFLINE_MAX_PATH_LEN);
	if(err < 1)
	{
		printf("load %s fail\n",xpath);
		exit(0);
	}

	snprintf(xpath,255,"/conf/link/max_cache_len");
	err = xmlcfg_get_str(&tc, xpath, buff, sizeof(buff));
	if(err < 1)
	{
		printf("load %s fail! default is 5M\n",xpath);
		offinit.max_cache_len = OFFLINE_DATA_DEFAULT_MAX_LEN;
	}
	else
	{
		offinit.max_cache_len = offline_comm_len_set(buff, strlen(buff));
	}

	snprintf(xpath,255,"/conf/down_pcap/pcap_max_size");
	err = xmlcfg_get_str(&tc, xpath, buff, sizeof(buff));
	if(err < 1)
	{
		printf("load %s fail! default is 5M\n",xpath);
		offinit.pcapsize = OFFLINE_DATA_DEFAULT_MAX_LEN;
	}
	else
	{
		offinit.pcapsize = offline_comm_len_set(buff, strlen(buff));
	}

	snprintf(xpath,255,"/conf/down_network/network_max_size");
	err = xmlcfg_get_str(&tc, xpath, buff, sizeof(buff));
	if(err < 1)
	{
		printf("load %s fail! default is 5M\n",xpath);
		offinit.lnwsize = OFFLINE_DATA_DEFAULT_MAX_LEN;
	}
	else
	{
		offinit.lnwsize = offline_comm_len_set(buff, strlen(buff));
	}

	if(offinit.online_conn_swicth == OFFLINE_SWITCH_OPEN)
	{
		snprintf(xpath,255,"/conf/online/online_conn_path");
		err = xmlcfg_get_str(&tc, xpath, offinit.online_conn_path, OFFLINE_MAX_PATH_LEN);
		if(err < 1)
		{
			printf("load %s fail\n",xpath);
			exit(0);
		}
	}
	if(offinit.mddw_dyn_switch == OFFLINE_SWITCH_OPEN)
	{
		snprintf(xpath,255,"/conf/mddw/mddw_dyn_path");
		err = xmlcfg_get_str(&tc, xpath, offinit.mddw_dyn_path, OFFLINE_MAX_PATH_LEN);
		if(err < 1)
		{
			printf("load %s fail\n",xpath);
			exit(0);
		}
	}
	xmlcfg_close(&tc);



	offline_down_pcap_info_set(&offinit); //落数据包
	offline_down_network_info_set(&offinit); //落数据包

	online_ginfo_t *goninfo  = (online_ginfo_t *)online_init(&offinit);
	if(offinit.online_conn_swicth == OFFLINE_SWITCH_CLOSE)
		offinit.ex_thr_num       = 0;
	else
		offinit.ex_thr_num       = goninfo->exthrnum;

	mddw_push_t mddw_push;
	memset(&mddw_push, 0, sizeof(mddw_push_t));
	online_mddw_load_t *online_mddw = NULL;
	if(offinit.mddw_dyn_switch == OFFLINE_SWITCH_OPEN)
	{
		online_mddw = (online_mddw_load_t *)online_mddw_load(offinit.mddw_dyn_path);
		if(online_mddw == NULL)
		{
			printf("online_mddw_load fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
			exit(0);
		}
		err = online_mddw->mddw_push_info(&mddw_push);
		if(err != 0)
		{
			printf("mddw_push_info fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
			exit(0);
		}	
		offinit.ex_thr_num += mddw_push.thr_num;	
	}
	offline_max_thr_num = offinit.thr_num + offinit.ex_thr_num;
	
	offline_status_init(offinit.thr_num + 1 + offinit.ex_thr_num); //1
	void *hand = offline_scan_init(&offinit, offinit.thr_num + 1, OFFLINE_MAX_CHANNEL_NUM);
	if(hand != NULL)
		offline_scan_start(hand);
	if(offinit.mddw_dyn_switch == OFFLINE_SWITCH_OPEN)
	{
		online_mddw_init(online_mddw, offinit.thr_num + 1 + offinit.ex_thr_num - mddw_push.thr_num, offinit.thr_num + offinit.ex_thr_num + 1);
	}
	if(offinit.online_conn_swicth == OFFLINE_SWITCH_OPEN)
	{
		online_info_t *poninfo = goninfo->oninfo;
		while(poninfo!= NULL)
		{
			online_dyn_load(poninfo, poninfo->dyn_thrid);
			poninfo = (online_info_t *)poninfo->next;
		}
	}
	return NULL;
}

uint32_t offline_get_max_thr_num()
{
	return offline_max_thr_num;
}

int main(int argc, char *argv[])
{
	printf("--------------start-------------------\n");
	int ret;
	ret = zlog_init("../sys_conf/log_fmt.conf");
	if(ret)
	{
		printf("zlog init failed\n");
		return -1;
	}
	vshell_init();
	init_jiffies_thread();

	offline_init("../sys_conf/offline_cfg.xml");
	while(1)
	{
		sleep(10);
	}
	return 0;
}

