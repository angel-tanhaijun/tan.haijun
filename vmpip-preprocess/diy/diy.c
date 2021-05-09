/*************************************************************************
	> File Name: diy.c
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月19日 星期五 11时30分02秒
 ************************************************************************/

#include <stdio.h>
#include <stdint.h>

#define datatype_ip             0x01  //ip数据，开头为0x45                 
#define datatype_eth            0x08  //以太数据，开头带有14个字节的以太头 
#define datatype_not_ip         0x20  //非ip数据                           

static char *libinfo __attribute__((unused))  = "\n@VERSION@:diy, 1.0.0, "VERSION"\n" ;
typedef int offline_diy_entry_helper(void *session, uint8_t *data, uint32_t datalen, uint32_t datatype, uint8_t *userinfo, uint32_t userinfolen, uint32_t userinfotype, void *ele, int thr_id, void  **user_data);                                                     


typedef struct{                             
	offline_diy_entry_helper *diy_entry;
}diy_helper_t;                          

static diy_helper_t udiy_helper;

static int do_diy_helper(void *session, uint8_t *data,uint32_t datalen, uint32_t datatype, uint8_t *userinfo, uint32_t userinfolen, uint32_t userinfotype, void *ele, int thr_id, void **user_data)
{
	if(data == NULL || datalen <= 0 || thr_id < 0)
		return -1;
	udiy_helper.diy_entry(session, data, datalen, datatype, userinfo, userinfolen, userinfotype, ele, thr_id, user_data);
	return 0;
}
int offline_diy_gain(void *session,char *filename, uint32_t filetype, void *ele, int thr_id, void **user_data)
{

	uint8_t  *data = "hello world!";
	uint32_t datalen = strlen("hello world!");

	do_diy_helper(session, data, datalen, datatype_ip, NULL, 0, 0, ele, thr_id, user_data);
	return;
}

int offline_diy_register(diy_helper_t *diy_helper)
{
	if(diy_helper == NULL)
		return -1;
	memcpy(&udiy_helper, diy_helper, sizeof(diy_helper_t));
	return 0;
}

int offline_diy_init(int thr_num)
{


	return 0;
}
