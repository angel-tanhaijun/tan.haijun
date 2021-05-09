/*************************************************************************
	> File Name: dyn.c
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月20日 星期六 18时26分04秒
 ************************************************************************/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <assert.h>
#include "utils.h"
#include "dyn.h"
#include "xmlcfg.h"
#include "mddw.h"
#include "tcpclient_v2.h"
#define     DYN_MAX_USER_NUM        4

#define datatype_ip             0x01
#define datatype_eth            0x08
#define datatype_not_ip         0x20
static char *libinfo __attribute__((unused))  = "\n@VERSION@:dvb_dyn, 1.0.0, "VERSION"\n" ;
#pragma pack (1)
typedef struct{
	uint32_t flag; //同步字:0xDF5FCF04
	uint8_t  version; //协议版本号（如：0x11表示V1.1）高4位为主版本号，低4位为副版本号
	uint32_t devipaddr;//设备源IP地址
	uint8_t  slotnum; //槽位号（0-2）
	uint8_t  channel; //通道号
	uint8_t  pktnum; //包编号:通道内帧循环计数
	uint8_t  pktflag; //包结束标志: 0x00: 完整包 0x01: 起始包 0x02: 中间包 0x03: 结束包
	uint16_t sliceid; //包序号:其他模式：数据包拆包序号附录M（宽带模式）：（slice_id）
	uint16_t pktlen;  //包长度:数据的字节长度，不包含128字节突发头
	uint8_t  effbit;  //包最后字节有效bit:最后一个数据中有效bit个数（主要针对TPC，有效bit不是字节的整数倍）
	uint8_t  pkttype; //包数据类型: B[3:0]:数据类型(0：译码数据 1：解调数据 2：ddc数据 3：adc数据 4：TS流 5：BBF帧) B[6:4]：(0：TDMA 1：DVBS1 2：DVBS2 3：DVBS2X 4：DSNG 5：附录M（宽带模式） 6：SCPC) B[7]:保留 
}manage_header_t;

typedef struct{
	uint16_t fid;//设备功能号: B[15:8]：厂家号(0x80);B[7:0]：功能号（即：信号规格）(0x00)	
	uint8_t  wsdever;//小站设备版本号:对方小站的软件版本号
	uint8_t  nettptype;//网络拓扑类型:网状网、星状网、混合组网
	uint16_t srcgropnum;//源群号:源群号（包含子网号，由CPU配置或者帧计划引导）
	uint16_t dstgropnum;//目的群号
	uint16_t wssrcid; //小站源ID号
	uint16_t wsdstid; //小站目的ID号
	uint16_t satid; //卫星ID号
	uint16_t satrepid; //卫星转发器ID
	uint32_t satpathway;//卫星轨位
	uint64_t reserved; //保留
}net_info_t;

typedef struct{
	uint8_t  carrynum;//载波编号:子网内，载波编号
	uint32_t uplinkfre;//上行频率:由CPU配置，单位Hz（卫星频点）
	uint32_t downlinkfre;//下行频率:由CPU配置，单位Hz（卫星频点）
	uint32_t modrate;//调制速率:由CPU配置，单位sps
	uint8_t  lockins;//锁定指示:bit[5:4]: 2'b00表示解调器未锁定；2'b01表示解调器重新锁定; 2'b11表示解调器锁定;bit[1:0]: 2'b00表示流未锁定；2'b01表示流重新锁定; 2'b11表示流锁定;
	uint8_t  modcod;//编码码率/MODCOD:DVB标准： DVBS1 B[7:6]：保留 B[5]: Viterbi BPSK mode B[4:2]: PunctRate[2:0], Viterbi Puncture Rate 000: 1/2 001: 2/3 010: 3/4 011: 5/6 100: 6/7 101: 7/8 B[1:0]:保留 DVB标准： DVBS2/DVBS2X B[7]: 保留 B[6:2]: MODCOD B[1:0]: TYPE
	uint16_t phyfracount;/*物理帧计数:
	物理帧计数
	Token, 2 bytes:
	bit 15: origin of the signal:
	0: demod natural path, such as, demod1 to LDPCin 1 to pktdelin 1
	1: demod switched path
	bit 14: modcodrq_synctag: see DSTATUS2/modcodrq_synctag
	bit 13: demod_untracked
	1: not locked or not yet locked
	0: demodulator locking
	bit 12: delete PL frame
	1: this frame has been deleted (see MODCODLST or DummyPL frame)
	0: the frame is output from the demodulator (towards the LDPC)
	bits 11..0: PLFRAME_counter (token): A count of all the frames, irrespectively of whether or
	not they are tagged for deletion
	*/
	uint8_t signal;/*信号指示:
	Sigs Pcount: Signals and packet counting
	Byte 1:
	bit 7: Generic Continuous Stream mode
	bit 6: DVB-S2 mode
	bit 5: rsparity, presence of Reed-Solomon parity
	bit 4: longpkt_mode, long packets detected
	bit 3: syncd_up_dfl, SYNCD different to 0xffff and greater than DFL (if not zero)
	bit 2: bad_dfl, DFL is too big for MODCOD&TYPE received
	bit 1: first_lock, the Packet Delineator outputs data
	bit 0: frame_lock, the Packet Delineator is locked
	*/
	uint32_t lockfre;//锁定频率:由CPU配置，单位Hz（锁定频点）
	uint8_t  carrylock;//载波锁定:载波锁定标志：1锁定；0未锁定	
	uint32_t unknown1;
	uint32_t unknown2;
	uint8_t  unknown3[6];
	uint32_t unknown4;
	uint64_t reversed;//保留
}phy_layer_t;



typedef struct{
	uint16_t fraerrcount; //每帧错误统计:DVBS2: LDPC错误；DVBS1/Legacy DTV: Viterbi错误；
	uint8_t  bcherrind;/*BCH错误指示
	BCH errs, 1 byte: BCH information from the frame: Not used in DVBS1/Legacy DTV
	bit 7: bch_error_flag, the BCH has market this frame as uncorrectable
	bit 6: previous_deleted, the last frame was deleted due to BBHeader error
	bit 5: bbheader_error, CRC8 check result on BBHeader
	bits 4..0: bch_errnbr, number of BCH errors
	*/ 
	uint8_t  bbffracrccheck;//BBF帧头CRC校验:1：表示校验错误，0：表示校验正确
	uint8_t  rserrind;/*RS错误指示:
	RS diags: Reed-Solomon decoder diagnostic if RS parity is present
	bit 7: -
	bit 6: deletions, deletions present in the packet
	bit 5: rserr, Reed-Solomon decoder error flag
	bits 4..0: rserr_nbr[4:0], number of RS errors detected in this packet
	*/
	uint16_t unknown1;
	uint8_t  unknown2;
	uint8_t  unknown3;
	uint8_t  reversed[8];
}data_indicate_t;


typedef struct{
	uint8_t timectl;/*时间控制:
	B[2:0]:
	0x0: 自定义时间戳（默认）
	0x1：内部GPS时间戳
	0x2：外部时统时间戳
	0x3: B码时间戳
	0x4：网络授时时间戳
	0x5：NCR时间戳
	B[3]:润秒，0：表示不润秒；1表示润秒
	B[7:4]:时间精准度
	0x0：正常工作状态，时钟同步正常；
	0x1：时钟同步异常，时间准确度优于 1ns；
	0x2：时钟同步异常，时间准确度优于 10ns；
	0x3：时钟同步异常，时间准确度优于 100ns；
	0x4：时钟同步异常，时间准确度优于 1us；
	0x5：时钟同步异常，时间准确度优于 10us；
	0x6：时钟同步异常，时间准确度优于 100us；
	0x7：时钟同步异常，时间准确度优于 1ms；
	0x8：时钟同步异常，时间准确度优于 10ms；
	0x9：时钟同步异常，时间准确度优于 100ms；
	0xA：时钟同步异常，时间准确度优于 1s；
	0xB：时钟同步异常，时间准确度优于 10s；
	0xC～0xE：保留位，无效；
	0xF：时钟严重故障，时间信号不可信。
	*/
	uint8_t time[14];
}time_control_t;

typedef struct{
	net_info_t      netinfo;
	phy_layer_t	    phylay;
	data_indicate_t dataind; 	
	time_control_t  time;	
}load_header_t;

#pragma pack (0)

static mddw_gsc_info_t m_mddw_gsc;

static online_helper_t g_online_helper[DYN_MAX_USER_NUM];
static int g_online_helper_num = 0;
static int fixthr_id[DYN_MAX_USER_NUM];
static int g_online_num = 0;


static int do_onlineld_helper(online_fc_t *fc, uint8_t *data, uint32_t datalen, uint32_t channel)                      
{   

	void *user_data[DYN_MAX_USER_NUM];                                                           
	int no = 0;     
	int iret = -1; 
	if(fc == NULL || data == NULL || datalen <= 0)
		goto exit;
	iret = g_online_helper[no].onlineld_entry(NULL, fc, data, datalen, channel, fixthr_id[no], NULL); 
exit:    
	return iret;
}


static void DVB_PROC(manage_header_t *manage_header, load_header_t *load_header, uint8_t *data, uint32_t datalen)
{
	online_fc_t fc;
	memset(&fc, 0, sizeof(online_fc_t));
	snprintf(fc.sessId, sizeof(fc.sessId), "%s%u", "ott", manage_header->channel);
	fc.userInfoType = 0x10005095;
	uint32_t total_len = 0;
	uint32_t type = 0;
	uint32_t len = 0;
	total_len += 8 + sizeof(manage_header_t);
	total_len += 8 + sizeof(load_header_t);
#if 1	
	fc.userInfo = (uint8_t *)malloc(total_len);
	fc.userInfoLen = total_len;
	type = 0x10005096;
	type = ntohl(type);
	len = sizeof(manage_header_t);
	len = ntohl(len);
	memcpy(fc.userInfo, &type, 4);
	memcpy(fc.userInfo + 4, &len, 4);
	memcpy(fc.userInfo + 8, manage_header, sizeof(manage_header_t));

	type = 0x10005097;
	type = ntohl(type);
	len = sizeof(load_header_t);
	len = ntohl(len);
	memcpy(fc.userInfo + (8 + sizeof(manage_header_t)), &type, 4);
	memcpy(fc.userInfo + (12 + sizeof(manage_header_t)), &len, 4);
	memcpy(fc.userInfo + (16 + sizeof(manage_header_t)), load_header, sizeof(load_header_t));
		
#endif
	do_onlineld_helper(&fc, data, datalen, manage_header->channel);
	free((char *)fc.userInfo);
}

static void DO_DVB_FUNC(uint8_t *data, uint32_t datalen)
{
	
}

static void *pcap_info_get(void *ele)
{
	FILE *fp = NULL;
	fp = fopen("/home/tan.haijun/workbench/other/data_forgery/dvb/dvb.dat", "r+");
	if(fp == NULL)
		return NULL;
	uint8_t *buff = NULL;
	manage_header_t manage_header;	
	while(fread(&manage_header, sizeof(manage_header_t), 1, fp) > 0)
	{
		buff = (uint8_t *)malloc(sizeof(manage_header_t) + sizeof(load_header_t) + ntohs(manage_header.pktlen));
		memcpy(buff, &manage_header, sizeof(manage_header_t));
		fread(buff + sizeof(manage_header_t), (ntohs(manage_header.pktlen) + sizeof(load_header_t)), 1, fp);
		DO_DVB_FUNC(buff, sizeof(manage_header_t) + sizeof(load_header_t) + ntohs(manage_header.pktlen));
		free(buff);	
	}
	fclose(fp);
	return NULL;
}	
static int tcp_client_check(void *ele, char *header, int headerLen, void **user_data)
{
	manage_header_t *manage_header = (manage_header_t *)header;
	if(ntohl(manage_header->flag) != 0xDF5FCF04)
	{
		printf("tcp_client_check manage_header.flag[%x] is not 0xDF5FCF04\n", ntohl(manage_header->flag));
		return -1;
	}	
	return (sizeof(load_header_t) + ntohs(manage_header->pktlen)); //返回值为接下来应获取的数据长度，除去头部长度以后
}

static int tcp_client_call(void *ele, char *data, int dataLen, void **user_data)
{
	int i = 0;
	tcpclient_scoket_info_t *fdSocketInfo = (tcpclient_scoket_info_t *)ele;
	uint8_t  *movedata = (uint8_t *)data;
	uint32_t movelen = 0;
	manage_header_t manage_header;
	load_header_t   load_header;
	uint8_t pkttype = 0;;
	while(movelen < dataLen)
	{
		manage_header = *(manage_header_t *)movedata;
		//memcpy(&manage_header, movedata, sizeof(manage_header_t));
		for(i = 0; i < m_mddw_gsc.mddw_sc_num; i++)
		{
			if(fdSocketInfo->serverPort == m_mddw_gsc.mddw_sc[i].port && strcmp(fdSocketInfo->serverIp, m_mddw_gsc.mddw_sc[i].ip) == 0)
			{
				if(m_mddw_gsc.mddw_sc[i].channel != manage_header.channel)
				{
					printf("tcp_client_call serverPort:%d; serverIp:%s; port:%d; ip:%s; manage_header.channel:%d; mddw_sc[%d].channel:%d;\n", fdSocketInfo->serverPort, fdSocketInfo->serverIp, m_mddw_gsc.mddw_sc[i].port, m_mddw_gsc.mddw_sc[i].ip, manage_header.channel, i, m_mddw_gsc.mddw_sc[i].channel);
					return 0;
				}
			}		
		}
		if(ntohl(manage_header.flag) == 0xDF5FCF04)
		{
			if((ntohs(manage_header.pktlen) + sizeof(load_header_t) + sizeof(manage_header_t)) > (dataLen - movelen))
			{
				movelen = dataLen;
				continue;
			}
			pkttype = manage_header.pkttype & 0x2;
			if(pkttype == 1 || pkttype == 2 || pkttype == 3)
			{
				load_header = *(load_header_t *)(movedata + sizeof(manage_header_t));

				//	memcpy(&load_header, movedata + sizeof(manage_header_t), sizeof(load_header_t));
				DVB_PROC(&manage_header, &load_header, movedata + sizeof(manage_header_t) + sizeof(load_header_t), ntohs(manage_header.pktlen));	
			}
			movelen += ntohs(manage_header.pktlen) + sizeof(load_header_t) + sizeof(manage_header_t);
			movedata = movedata + ntohs(manage_header.pktlen) + sizeof(load_header_t) + sizeof(manage_header_t);
		}
		else
		{
			movelen++;
			movedata++;
		}	
	}
}
int online_register(online_helper_t *online_helper)
{
	if(online_helper == NULL)
		return -1;
	if(g_online_helper_num > DYN_MAX_USER_NUM - 1) 
		return -1;
	memcpy(&(g_online_helper[g_online_helper_num]), online_helper, sizeof(online_helper_t));

	g_online_helper_num++;
	return 0;
}
int online_mddw_init(int thr_id, mddw_gsc_info_t *mddw_gsc)
{
	int i = 0;
	fixthr_id[g_online_num]  = thr_id; //只能用初始化时使用的通道和线程号
	tcpclient_check_t tcpclient_check;
	g_online_num++;
	memcpy(&m_mddw_gsc, mddw_gsc, sizeof(mddw_gsc_info_t));

	tcpclient_hander_t *hander = (tcpclient_hander_t *)malloc(sizeof(tcpclient_hander_t));
	memset(hander, 0, sizeof(tcpclient_hander_t));
	tcpclient_check.headerLen = 19; 
	tcpclient_check.bufMaxLen = 1024 * 1024 * 10;
	tcpclient_add_rules(hander, &tcpclient_check);		
	tcpclient_init(hander,  mddw_gsc->mddw_sc_num, 29);
	for(i = 0; i < mddw_gsc->mddw_sc_num; i++)
	{
		tcpclient_add_socket(hander, mddw_gsc->mddw_sc[i].port, mddw_gsc->mddw_sc[i].ip);
	}
	tcpclient_helper_t tcpclient_helper;
	tcpclient_helper.check_helper = tcp_client_check;
	tcpclient_helper.tcpclient_recv = tcp_client_call; 
	tcpclient_register(hander, &tcpclient_helper);
	tcpclient_recv_start(hander);
	return 0;
}
