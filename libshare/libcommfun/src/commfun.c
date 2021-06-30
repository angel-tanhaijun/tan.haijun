/*************************************************************************
	> File Name: commfun.c
	> Author: tan.haijun
	> Mail: tan.haijun@163.com 
	> Created Time: Mon 07 Jun 2021 06:54:15 PM PDT
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <assert.h>

#include "commfun.h"

const uint8_t *CommGetData(CommTvBuff_t *tvb, const int offset, const uint32_t length)
{
	if( tvb->dataLen < (offset + length) || offset < 0)
	{
		printf("%s[%d]: offset of length error\n", __FILE__, __LINE__);
		exit(1);
	}
	return (tvb->data + offset);
}

void CommGetUint24(CommTvBuff_t *tvb, const int offset, uint8_t *dstAddr)
{
	const uint8_t *ptr = CommGetData(tvb, offset, 3);
	int i = 0;
	for(i = 1; i < 4; i++)
		dstAddr[i] = ptr[i - 1]; 
	return; 
}

uint8_t CommGetUint8(CommTvBuff_t *tvb, const int offset)
{
	const uint8_t *ptr;
	ptr = CommGetData(tvb, offset, 1);
	return *ptr;
}

uint16_t CommGetUint16(CommTvBuff_t *tvb, const int offset)
{
	const uint16_t *ptr;
	ptr = CommGetData(tvb, offset, 2);
	return *ptr;
}

uint32_t CommGetUint32(CommTvBuff_t *tvb, const int offset)
{
	const uint32_t *ptr;
	ptr = CommGetData(tvb, offset, 4);
	return *ptr;
}

uint64_t CommGetUint64(CommTvBuff_t *tvb, const int offset)
{
	const uint64_t *ptr;
	ptr = CommGetData(tvb, offset, 8);
	return *ptr;
}


int CommLenRemain(CommTvBuff_t *tvb, const int offset)
{
	return (tvb->dataLen - offset);
}


int CommPushData(void *session, uint8_t *data, uint32_t dataLen, void *ele)
{


	return 0;
}

