/*************************************************************************
	> File Name: udpclient.h
	> Author: tan.haijun
	> Mail: tan.haijun@163.com 
	> Created Time: Mon 07 Jun 2021 01:36:38 AM PDT
 ************************************************************************/

#ifndef _UDP_CLIENT_H_
#define _UDP_CLIENT_H_


#pragma pack (1)




#pragma pack (0)

/*
	函数功能：udp客户端注册初始化
	参数：
		serverIp：对端ip
		serverPort：对端port
	返回值：
		NULL失败，非空成功
*/
void *UdpClientInit(char *serverIp, uint16_t serverPort);

/*
	函数功能：udp发送数据
	参数：
		hand：UdpClientInit的返回值
		data：要发送的数据
		dataLen：发送的数据长度
		ele：当前填NULL
	返回值：
		0表示成功，非0表示失败
*/
int UdpClientSend(void *hand, uint8_t *data, uint32_t dataLen, void *ele);


#endif

