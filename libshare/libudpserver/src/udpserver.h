/*************************************************************************
	> File Name: udpserver.h
	> Author: tan.haijun
	> Mail: tan.haijun@163.com 
	> Created Time: Sun 06 Jun 2021 10:21:09 PM PDT
 ************************************************************************/
#ifndef _UDP_SERVER_H_
#define _UDP_SERVER_H_


#define _GNU_SOURCE


#pragma pack (1)



#pragma pack (0)
	
typedef int UdpServerCallBack(void *session, uint8_t *data, uint32_t dataLen, void *ele);

typedef struct{
	UdpServerCallBack *uSCB;
}UdpServerHelper_t;

/*
	函数功能：udp服务端接收模块初始化 
	参数：
		listenPortNum：监听的端口总数
	返回值：
		NULL和非NULL
*/
void *UdpServerInit(uint32_t listenPortNum);
/*
	函数功能：udp服务端端口监控注册
	参数：
		hand：UdpServerInit返回的参数
		port：需要监控的端口
		udpServerHelper：注册的数据出口回调函数
		ele：用户信息，当前传NULL
	返回值：
		0表示成功，非0失败
*/
int UdpServerAddPort(void *hand, uint16_t port, UdpServerHelper_t *udpServerHelper, void *ele);
/*
	函数功能：udp服务端监控开始
	参数：
		hand：UdpServerInit返回的参数
	返回值:
		0表示成功，非0表示失败
*/
int UdpServerStart(void *hand);

#endif
