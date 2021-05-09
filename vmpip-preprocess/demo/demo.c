/*************************************************************************
	> File Name: demo.c
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月01日 星期一 15时50分20秒
 ************************************************************************/
#include <pthread.h>
#include "offline.h"


static void *vshell_thread(void *param)                    
{                                                          
	vshell_start("0.0.0.0", 41452);    
	return NULL;                                           
}                                                          

static void *ip_get(void *param)                    
{                                                          
	while(1)
	{
		offline_dis_vender_t *dis_vender = offline_link_dis_rbq_getdata(0);
		if(dis_vender != NULL)
		{
//			printf("path[%s] iplen[%d]\n", dis_vender->path, dis_vender->iplen);	
			offline_link_dis_rbq_putdata(dis_vender, 0);
		}
		usleep(10);
	}	
	
	return NULL;                                           
}                                                          


int main(int argc, char *argv[])
{
	int ret;                                    
	ret = zlog_init("../sys_conf/log_fmt.conf");
	if(ret)                                     
	{                                           
		printf("zlog init failed\n");           
		return -1;                              
	}                                           
	vshell_init();
	init_jiffies_thread();
	pthread_t vshell_id, get_id;
	ret = pthread_create(&vshell_id, NULL, vshell_thread, NULL);
	if(ret!=0)                                                           
	{                                                                    
		printf("create vshell_thread fail\n");                           
		return 0;                                                        
	}                                                                    
	void *hand = offline_scan_init("./test", "../sys_conf/link_conn.xml", "../sys_conf/dis_conn.xml", 4, 32);
	offline_scan_start(hand);
	
	ret = pthread_create(&get_id, NULL, ip_get, NULL);
	if(ret!=0)
	{
		printf("create vshell_thread fail\n");
		return 0;
	}                                         
	while(1)
	{
		sleep(1);
	}
	return 0;
}


