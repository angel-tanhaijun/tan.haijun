/*************************************************************************
	> File Name: rtq.h
	> Author: tan.haijun
	> Mail: tan.haijun@163.com 
	> Created Time: Mon 28 Jun 2021 12:04:53 AM PDT
 ************************************************************************/
#ifndef _RTQ_H_
#define _RTQ_H_


#define RTQ_GET_BUF_BLOCK   1

#pragma pack(1)



typedef struct{
	uint8_t  *buf;
	uint32_t len;
	uint32_t msgNum;
	uint32_t maxBufLen;
	int      thrId;
}rtq_buf_t;



#pragma pack(0)

void *rtq_malloc(uint32_t qNum, uint32_t qLen, uint32_t qSize, uint32_t iWriteThrNum, uint32_t iReadThrNum, char *rtqName);

rtq_buf_t *rtq_get_buf(void *rtqHand, uint32_t bufLen, int thrId);

int rtq_put_data(void *rtqHand, rtq_buf_t *rtqBuf);

rtq_buf_t *rtq_get_data(void *rtqHand, int thrId);

int rtq_put_buf(void *rtqHand, rtq_buf_t *rtqBuf);


#endif
