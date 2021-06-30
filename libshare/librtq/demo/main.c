/*************************************************************************
	> File Name: main.c
	> Author: tan.haijun
	> Mail: tan.haijun@163.com 
	> Created Time: Mon 28 Jun 2021 06:47:48 PM PDT
 ************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "rtq.h"

static void *rtq_hand = NULL;

static uint32_t thr_wadd_id = 0;
static uint32_t thr_radd_id = 0;

typedef struct{
	char buf[256];
	uint32_t add_num;
}buf_add_t;

void *write_buf(void *ele)
{
	int thr_id = __sync_fetch_and_add(&(thr_wadd_id),1);
	uint32_t add_num = 0;

	while(1)
	{
		rtq_buf_t *rtq_buf = rtq_get_buf(rtq_hand, sizeof(buf_add_t), thr_id);
		if(rtq_buf == NULL)
			continue;
		buf_add_t add;
		snprintf(add.buf, 256, "%s_%d_%d", "hello word!", add_num, thr_id);
		add.add_num = add_num;
		add_num++;
		memcpy(rtq_buf->buf, &add, sizeof(buf_add_t));
		rtq_buf->len  = sizeof(buf_add_t);
		rtq_put_data(rtq_hand, rtq_buf);
		sleep(1);
	}

}

void *read_buf(void *ele)
{
	int thr_id = __sync_fetch_and_add(&(thr_radd_id),1);

	while(1)
	{
		rtq_buf_t *rtq_buf = rtq_get_data(rtq_hand, thr_id);
		if(rtq_buf == NULL)
			continue;
		buf_add_t *add = (buf_add_t *)rtq_buf->buf;
//		printf("%s_%d\n", add->buf, thr_id);
		rtq_put_buf(rtq_hand, rtq_buf);
	}

}

int main()
{
	rtq_hand = rtq_malloc(11, 500, 500, 3, 2, "rtq");
	if(rtq_hand == NULL)
		return 0;
	int i = 0;
	pthread_t wpid[64];
	for(i = 0;i < 3; i++)
		pthread_create(&wpid[i], NULL, write_buf, NULL);
		
	
	pthread_t rpid[64];
	for(i = 0;i < 2; i++)
		pthread_create(&rpid[i], NULL, read_buf, NULL);

	while(1)
		sleep(1);
	
	return 0;

}
