/*************************************************************************
	> File Name: commfun.h
	> Author: tan.haijun
	> Mail: tan.haijun@163.com 
	> Created Time: Mon 07 Jun 2021 06:54:25 PM PDT
 ************************************************************************/

#ifndef _COMM_FUN_H_
#define _COMM_FUN_H_


#pragma pack (1)

typedef struct{
	uint8_t *data;
	uint32_t dataLen;
}CommTvBuff_t;

#pragma pack (0)


const uint8_t *CommGetData(CommTvBuff_t *tvb, const int offset, const uint32_t length);

/*获取一个字节*/
uint8_t CommGetUint8(CommTvBuff_t *tvb, const int offset);

/*获取两个字节*/
uint16_t CommGetUint16(CommTvBuff_t *tvb, const int offset);
/*获取三个字节*/
void CommGetUint24(CommTvBuff_t *tvb, const int offset, uint8_t *dstAddr);

/*获取四个字节*/
uint32_t CommGetUint32(CommTvBuff_t *tvb, const int offset);

/*返回剩余数据长度*/
int CommLenRemain(CommTvBuff_t *tvb, const int offset);

int CommPushData(void *session, uint8_t *data, uint32_t dataLen, void *ele);

#endif 
