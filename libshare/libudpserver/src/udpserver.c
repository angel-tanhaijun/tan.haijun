/*************************************************************************
	> File Name: server.c
	> Author: tan.haijun
	> Mail: tan.haijun@163.com 
	> Created Time: Wed 02 Jun 2021 08:01:00 PM PDT
	> 此库的功能是udp多端口监听服务
 ************************************************************************/



#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <pthread.h>

#include "udpserver.h"


#define UDP_SERVER_MAX_RECV_BUF_LEN     (0xFFFF + 0xFF)

#pragma pack (1)


typedef struct{
	int      sockFd;	
	uint16_t port;
	UdpServerHelper_t udpServerHelper;
	uint32_t MaxRecvBufLen;
	int      recvBufLen;
	uint8_t  *recvBuf;
}udpServerInit_t;

typedef struct{
	int listenPortNum;
	int listenPortNumYet;
	int maxSockFd;
	fd_set   fds;
	void     *initSpace;
}udpServerHand_t;

#pragma pack (0)


void *UdpServerInit(uint32_t listenPortNum)
{
	if(listenPortNum <= 0)
	{
		printf("%s[%d]: listenPortNum is error\n",  __FILE__, __LINE__);
		return NULL;
	}
	udpServerHand_t *uSH = malloc(sizeof(udpServerHand_t));	
	if(uSH == NULL)
	{
		printf("%s[%d]: malloc() fail\n", __FILE__, __LINE__);
		exit(1);
	}
	uSH->listenPortNum    = listenPortNum;
	uSH->listenPortNumYet = 0;
	uSH->initSpace     = malloc(sizeof(udpServerInit_t) * listenPortNum);
	memset(uSH->initSpace, 0, sizeof(udpServerInit_t) * listenPortNum);
	FD_ZERO(&uSH->fds);
	return (void *)uSH;
}

int UdpServerAddPort(void *hand, uint16_t port, UdpServerHelper_t *udpServerHelper, void *ele)
{
	if(hand == NULL || port <= 0 || udpServerHelper == NULL)
	{
		 printf("%s[%d]: hand or port or udpServerHelper is error\n", __FILE__, __LINE__);
		 return -1;
	}
	udpServerHand_t *uSH = (udpServerHand_t *)hand;
	if(uSH->listenPortNumYet >= uSH->listenPortNum)
	{
		printf("%s[%d]: listenPortNum is outside\n", __FILE__, __LINE__);
		return -1;
	}
	udpServerInit_t *uSI = (udpServerInit_t *)(uSH->initSpace + sizeof(udpServerInit_t) * uSH->listenPortNumYet);
	if((uSI->sockFd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		printf("%s[%d]: socket fail\n", __FILE__, __LINE__);
		return -1;
	}
	struct sockaddr_in server;
	bzero(&server, sizeof(server));
	server.sin_family      = AF_INET;               
	server.sin_port        = htons(port); 
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	uSI->port              = port;
	if(bind(uSI->sockFd, (struct sockaddr *)&server, sizeof(server)) == -1)
	{
		printf("%s[%d]: bind fail\n", __FILE__, __LINE__); 
		return -1;                                           
	}
	uSI->MaxRecvBufLen = UDP_SERVER_MAX_RECV_BUF_LEN;
	uSI->recvBuf       = (uint8_t *)malloc(UDP_SERVER_MAX_RECV_BUF_LEN);
	if(uSI->recvBuf == NULL)
	{
		printf("%s[%d]: malloc fail\n", __FILE__, __LINE__);
		return -1;                                          
	}
	FD_SET(uSI->sockFd, &uSH->fds);		
	uSH->maxSockFd = (uSH->maxSockFd > uSI->sockFd)?uSH->maxSockFd:uSI->sockFd;
	memset(uSI->recvBuf, 0, UDP_SERVER_MAX_RECV_BUF_LEN);
	uSI->recvBufLen    = 0;
	uSI->udpServerHelper.uSCB = udpServerHelper->uSCB;
	uSH->listenPortNumYet++;
	return 0;
}

static void *UdpServerRun(void *ele)
{
	udpServerHand_t *uSH = (udpServerHand_t *)ele;
	int ret = 0, i = 0, len = 0;
	struct timeval tim;
	while(1)
	{
		fd_set fds = uSH->fds;	
		tim.tv_sec  = 1;
		tim.tv_usec = 0;
		ret = select(uSH->maxSockFd+1, &fds, NULL, NULL, &tim);
		if(ret < 0)
		{
			printf("%s[%d]: select fail\n", __FILE__, __LINE__);
			continue;
		}
		else if(ret == 0)
		{
			continue;
		}
		for(i = 0; i < uSH->listenPortNumYet; i++)
		{
			udpServerInit_t *uSI = (udpServerInit_t *)(uSH->initSpace + sizeof(udpServerInit_t) * i);
			if(FD_ISSET(uSI->sockFd, &fds))
			{
				uSI->recvBufLen = read(uSI->sockFd, uSI->recvBuf, uSI->MaxRecvBufLen);
				if(uSI->udpServerHelper.uSCB != NULL)
					uSI->udpServerHelper.uSCB(NULL, uSI->recvBuf, uSI->recvBufLen, NULL);
			}
		}
	}
}

int UdpServerStart(void *hand)
{
	if(hand == NULL)
	{
		 printf("%s[%d]: hand is error\n", __FILE__, __LINE__);
		 return -1;
	}
	pthread_t pid;
	int ret = pthread_create(&pid, NULL, UdpServerRun, hand);
	if(ret != 0)
	{
		printf("%s[%d]: pthread_create fail\n", __FILE__, __LINE__);
		exit(-1);
	}
	return 0;
}

#if 0
static int DoUdpServerCallBack(void *session, uint8_t *data, uint32_t dataLen, void *ele)
{
	printf("recv dataLen:%d\n", dataLen);
	return 0;
}
int main()
{
	void *hand = UdpServerInit(4);
	UdpServerHelper_t udpServerHelper;
	udpServerHelper.uSCB = DoUdpServerCallBack; 
	UdpServerAddPort(hand, 61403, &udpServerHelper, NULL);
	//UdpServerAddPort(hand, 61402, &udpServerHelper, NULL);
	//UdpServerAddPort(hand, 161, &udpServerHelper, NULL);	
	UdpServerStart(hand);
	while(1)
		sleep(10);
	return 0;
}
#endif
