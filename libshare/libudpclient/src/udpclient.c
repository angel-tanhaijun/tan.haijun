/*************************************************************************
	> File Name: client.c
	> Author: tan.haijun
	> Mail: tan.haijun@163.com 
	> Created Time: Wed 02 Jun 2021 08:34:57 PM PDT
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "udpclient.h"

#define UDP_CLIENT_MAX_IP_BUF_LEN   30

#pragma pack (1) 
                 


typedef struct{
	int       sockFd;
	uint16_t  serverPort;
	char      serverIp[UDP_CLIENT_MAX_IP_BUF_LEN];
	struct    sockaddr_in server;
}udpClientInit_t;
                 
#pragma pack (0) 



void *UdpClientInit(char *serverIp, uint16_t serverPort)
{
	if(serverIp == NULL || serverPort <= 0)
	{
		printf("%s[%d]: serverIp or serverPort error\n", __FILE__, __LINE__);	
		return NULL;
	}
	struct hostent *he = NULL;
	if((he = gethostbyname(serverIp)) == NULL)
	{
		printf("%s[%d]: gethostbyname error\n", __FILE__, __LINE__);
		return NULL;
	}
	udpClientInit_t *uCI = (udpClientInit_t *)malloc(sizeof(udpClientInit_t));
	if(uCI == NULL)
	{
		printf("%s[%d]: malloc() fail\n", __FILE__, __LINE__);
		exit(1);
	}
	if((uCI->sockFd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		printf("%s[%d]: socket() fail\n", __FILE__, __LINE__);
		exit(1);
	}
	snprintf(uCI->serverIp, UDP_CLIENT_MAX_IP_BUF_LEN, "%s", serverIp);
	uCI->serverPort        = serverPort;
	bzero(&uCI->server, sizeof(uCI->server));                    
	uCI->server.sin_family = AF_INET;                       
	uCI->server.sin_port   = htons(serverPort);        
	uCI->server.sin_addr   = *((struct in_addr*)he->h_addr);
	return (void *)uCI;
}

int UdpClientSend(void *hand, uint8_t *data, uint32_t dataLen, void *ele)
{
	if(hand == NULL || data == NULL || dataLen <= 0)
	{
		printf("%s[%d]: hand or data or dataLen error", __FILE__, __LINE__);
		return -1;
	}
	udpClientInit_t *uCI = (udpClientInit_t *)hand;
	int ret = sendto(uCI->sockFd, data, dataLen, 0, (struct sockaddr *)&uCI->server, sizeof(uCI->server));
	if(ret < 0)
	{
		perror("sendto() fail\n");
		return -1;
	}
	return 0;
}
#if 0
int main(int argc, char *argv[])
{
	void *hand = UdpClientInit("192.168.220.130", 61403);	
	while(1)
	{
		UdpClientSend(hand, "hello word", strlen("hello word"), NULL);
		printf("UdpClientSend hello word\n");
		sleep(1);
	}
	return 0;
}
#endif
