/*************************************************************************
	> File Name: rtq.c
	> Author: tan.haijun
	> Mail: tan.haijun@163.com 
	> Created Time: Mon 28 Jun 2021 12:04:44 AM PDT
 ************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>
#include "rtq.h"


#define RTQ_CHECK_QUEUE_NULL(iWritePos, iReadPos)           ((iWritePos == iReadPos)?0:-1)
#define RTQ_CHECK_QUEUE_FULL(iWritePos, iReadPos, qSize)    ((((iWritePos + 1) % qSize) == iReadPos)?0:-1) 
#define RTQ_POS_ADD(pos, qSize)                             ((pos + 1) % qSize)
#define RTQ_CHECK_QUEUE_NUM(iWriteThrNum, iReadThrNum)      ((iWriteThrNum > iReadThrNum)?iWriteThrNum:iReadThrNum)
#define RTQ_BUF_EXEC_LEN                                    (200)


#pragma pack(1)




typedef struct{
	rtq_buf_t        **queue;
	uint32_t         iWritePos;
	uint32_t         iReadPos;
	uint32_t         qSize;
	uint32_t         qLen;
}rtq_queue_t;


typedef struct{
	uint32_t  **queueGh;
	uint32_t  queuePos; 
	uint32_t  queueGhNum;
}rtq_thr_info_t;

typedef struct{
	uint32_t       iWriteThrNum;
	rtq_thr_info_t **iWriteThrInfo;
	uint32_t       iReadThrNum;
	rtq_thr_info_t **iReadThrInfo;
	uint32_t       **qNumArr;
	uint32_t       qNum;
	rtq_queue_t    **queueArr;
	uint64_t       maxQLen;  
}rtq_hand_t;


#pragma pack(0)



static int rtq_queue_init(rtq_queue_t *rtqQueue, uint32_t qLen, uint32_t qSize)
{
	rtqQueue->iWritePos = 0;
	rtqQueue->iReadPos  = 0;
	rtqQueue->qLen      = qLen;
	//rtqQueue->qSize     = qSize;
	rtqQueue->queue = malloc(sizeof(rtq_buf_t *) * qSize); 
	assert(rtqQueue->queue != NULL);
	while(rtqQueue->qSize < qSize)
	{
		rtqQueue->queue[rtqQueue->qSize]              = malloc(sizeof(rtq_buf_t));
		assert(rtqQueue->queue[rtqQueue->qSize] != NULL);
		rtqQueue->queue[rtqQueue->qSize]->buf         = malloc(qLen + RTQ_BUF_EXEC_LEN);
		assert(rtqQueue->queue[rtqQueue->qSize]->buf != NULL);
		rtqQueue->queue[rtqQueue->qSize]->len         = 0;
		rtqQueue->queue[rtqQueue->qSize]->msgNum      = 0;
		rtqQueue->queue[rtqQueue->qSize]->maxBufLen   = qLen + RTQ_BUF_EXEC_LEN;
		rtqQueue->qSize++;
	}
	return 0;
}

static rtq_buf_t *rtq_queue_get_buf(rtq_queue_t *rtqQueue, uint32_t bufLen, uint8_t mode)
{
	if(RTQ_CHECK_QUEUE_FULL(rtqQueue->iWritePos, rtqQueue->iReadPos, rtqQueue->qSize) == 0)
	{
		if(mode == RTQ_GET_BUF_BLOCK)
		{
			while(RTQ_CHECK_QUEUE_FULL(rtqQueue->iWritePos, rtqQueue->iReadPos, rtqQueue->qSize) == 0)
				usleep(50);
		}
		else
			return NULL;
	}
	if(bufLen > rtqQueue->queue[rtqQueue->iWritePos]->maxBufLen)
	{
		rtqQueue->queue[rtqQueue->iWritePos]->buf         = realloc(rtqQueue->queue[rtqQueue->iWritePos]->buf, bufLen);
		rtqQueue->queue[rtqQueue->iWritePos]->maxBufLen   = bufLen;
	}
	return rtqQueue->queue[rtqQueue->iWritePos];
}
static int rtq_queue_put_data(rtq_queue_t *rtqQueue)
{
	rtqQueue->iWritePos = RTQ_POS_ADD(rtqQueue->iWritePos, rtqQueue->qSize);
	return 0;
}
static rtq_buf_t *rtq_queue_get_data(rtq_queue_t *rtqQueue)
{
	if(RTQ_CHECK_QUEUE_NULL(rtqQueue->iWritePos, rtqQueue->iReadPos) == 0)
		return NULL;
	else
		return rtqQueue->queue[rtqQueue->iReadPos];
}

static rtq_buf_t *rtq_queue_put_buf(rtq_queue_t *rtqQueue)
{
	rtqQueue->iReadPos = RTQ_POS_ADD(rtqQueue->iReadPos, rtqQueue->qSize);
	return 0;
}


void *rtq_malloc(uint32_t qNum, uint32_t qLen, uint32_t qSize, uint32_t iWriteThrNum, uint32_t iReadThrNum, char *rtqName)
{
	if(qNum <= 0 || qLen <= 0 || qSize <= 2 || iWriteThrNum <= 0 || iReadThrNum <= 0)
		return NULL;
	if(qNum < RTQ_CHECK_QUEUE_NUM(iWriteThrNum, iReadThrNum))
		return NULL;
	rtq_hand_t *hand = malloc(sizeof(rtq_hand_t));	
	assert(hand != NULL);
	memset(hand, 0, sizeof(rtq_hand_t));

	hand->qNumArr        = malloc(sizeof(uint32_t *) * qNum);
	hand->queueArr       = malloc(sizeof(rtq_queue_t *) * qNum);
	while(hand->qNum < qNum)
	{
		hand->qNumArr[hand->qNum]  = malloc(sizeof(uint32_t));
		*hand->qNumArr[hand->qNum] = hand->qNum;
		hand->queueArr[hand->qNum] = malloc(sizeof(rtq_queue_t));
		rtq_queue_init(hand->queueArr[hand->qNum], qLen, qSize);
		hand->qNum++;
	}

	hand->iWriteThrInfo = malloc(sizeof(rtq_thr_info_t *) * iWriteThrNum);
	assert(hand->iWriteThrInfo);
	uint32_t iWriteQueueR   = qNum%iWriteThrNum;
	uint32_t iWriteQueueD   = qNum/iWriteThrNum;
	uint32_t iWriteQueueN   = 0;
	uint32_t iWriteAddQueue = 0;

	while(hand->iWriteThrNum < iWriteThrNum)
	{
		hand->iWriteThrInfo[hand->iWriteThrNum] = malloc(sizeof(rtq_thr_info_t));
		
		hand->iWriteThrInfo[hand->iWriteThrNum]->queueGhNum = iWriteQueueD;
		if(iWriteQueueN < iWriteQueueR)
		{
			hand->iWriteThrInfo[hand->iWriteThrNum]->queueGhNum += 1;  		
			iWriteQueueN += 1;
		}
		hand->iWriteThrInfo[hand->iWriteThrNum]->queueGh  = malloc(sizeof(uint32_t *) * hand->iWriteThrInfo[hand->iWriteThrNum]->queueGhNum);
		hand->iWriteThrInfo[hand->iWriteThrNum]->queueGh  = hand->qNumArr + iWriteAddQueue;
		hand->iWriteThrInfo[hand->iWriteThrNum]->queuePos = 0;
		
		iWriteAddQueue += hand->iWriteThrInfo[hand->iWriteThrNum]->queueGhNum;
		hand->iWriteThrNum ++;
	}

	hand->iReadThrInfo = malloc(sizeof(rtq_thr_info_t *) * iReadThrNum);
	assert(hand->iReadThrInfo);
	uint32_t iReadQueueR   = qNum%iReadThrNum;
	uint32_t iReadQueueD   = qNum/iReadThrNum;
	uint32_t iReadQueueN   = 0;
	uint32_t iReadAddQueue = 0;

	while(hand->iReadThrNum < iReadThrNum)
	{
		hand->iReadThrInfo[hand->iReadThrNum] = malloc(sizeof(rtq_thr_info_t));
		
		hand->iReadThrInfo[hand->iReadThrNum]->queueGhNum = iReadQueueD;
		if(iReadQueueN < iReadQueueR)
		{
			hand->iReadThrInfo[hand->iReadThrNum]->queueGhNum += 1;
			iReadQueueN += 1;
		}
		hand->iReadThrInfo[hand->iReadThrNum]->queueGh  = malloc(sizeof(uint32_t *) * hand->iReadThrInfo[hand->iReadThrNum]->queueGhNum);
		hand->iReadThrInfo[hand->iReadThrNum]->queueGh  = hand->qNumArr + iReadAddQueue;
		hand->iReadThrInfo[hand->iReadThrNum]->queuePos = 0;

		iReadAddQueue += hand->iReadThrInfo[hand->iReadThrNum]->queueGhNum;
		hand->iReadThrNum ++;
	}
	return (void *)hand;
}


rtq_buf_t *rtq_get_buf(void *rtqHand, uint32_t bufLen, int thrId)
{
	if(rtqHand == NULL || bufLen <= 0 || thrId < 0)
		return NULL;
	rtq_hand_t *hand = (rtq_hand_t *)rtqHand;	
	
	uint32_t queueNum = *hand->iWriteThrInfo[thrId]->queueGh[hand->iWriteThrInfo[thrId]->queuePos];
	rtq_buf_t *rtqBuf = rtq_queue_get_buf(hand->queueArr[queueNum], bufLen, 0);
	if(rtqBuf != NULL)
		rtqBuf->thrId = thrId;
	return rtqBuf;		
}

int rtq_put_data(void *rtqHand, rtq_buf_t *rtqBuf)
{
	if(rtqHand == NULL || rtqBuf == NULL)
		return NULL;                               
	rtq_hand_t *hand = (rtq_hand_t *)rtqHand;      
	int thrId = rtqBuf->thrId;

	uint32_t queueNum = *hand->iWriteThrInfo[thrId]->queueGh[hand->iWriteThrInfo[thrId]->queuePos];
	hand->iWriteThrInfo[thrId]->queuePos = RTQ_POS_ADD(hand->iWriteThrInfo[thrId]->queuePos, hand->iWriteThrInfo[thrId]->queueGhNum);
	return rtq_queue_put_data(hand->queueArr[queueNum]);
}

rtq_buf_t *rtq_get_data(void *rtqHand, int thrId)
{
	if(rtqHand == NULL || thrId < 0)                                              
		return NULL;                                                                             
	rtq_hand_t *hand = (rtq_hand_t *)rtqHand;                                                    

	uint32_t queueNum = *hand->iReadThrInfo[thrId]->queueGh[hand->iReadThrInfo[thrId]->queuePos];
	rtq_buf_t *rtqBuf = rtq_queue_get_data(hand->queueArr[queueNum]);
	if(rtqBuf != NULL)        
		rtqBuf->thrId = thrId;
	return rtqBuf;            
}
int rtq_put_buf(void *rtqHand, rtq_buf_t *rtqBuf)
{
	if(rtqHand == NULL || rtqBuf == NULL)       
		    return NULL;                            
	rtq_hand_t *hand = (rtq_hand_t *)rtqHand;   
	int thrId = rtqBuf->thrId;                  

	uint32_t queueNum = *hand->iReadThrInfo[thrId]->queueGh[hand->iReadThrInfo[thrId]->queuePos];
	hand->iReadThrInfo[thrId]->queuePos = RTQ_POS_ADD(hand->iReadThrInfo[thrId]->queuePos, hand->iReadThrInfo[thrId]->queueGhNum);
	
	return rtq_queue_put_buf(hand->queueArr[queueNum]);
}
