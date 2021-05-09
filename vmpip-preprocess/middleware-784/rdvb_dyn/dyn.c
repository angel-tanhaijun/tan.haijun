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
#include "mddw.h"
#include "tcpserver.h"
#include "rbque.h"
#include "udpserver.h"

#define     DYN_MAX_USER_NUM        4

#define datatype_ip             0x01
#define datatype_eth            0x08
#define datatype_not_ip         0x20
#define pcapName "/home/tan.haijun/workbench/nca/pcap/sip/sip/sdp.pcap"
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



void *udpserver_rbq_handle = NULL;
static mddw_gsc_info_t m_mddw_gsc;
static online_helper_t g_online_helper[DYN_MAX_USER_NUM];
static int g_online_helper_num = 0;
static int fixthr_id[DYN_MAX_USER_NUM];
static int g_online_num = 0;

static int do_onlineld_helper(online_fc_t *fc, uint8_t *data, uint32_t datalen, uint32_t channel, int thr_id)                      
{   

	void *user_data[DYN_MAX_USER_NUM];                                                           
	int no = 0;     
	int iret = -1; 
	if(fc == NULL || data == NULL || datalen <= 0)
		goto exit;
	iret = g_online_helper[no].onlineld_entry(NULL, fc, data, datalen, channel, thr_id, NULL); 
exit:    
	return iret;
}


static void DVB_PROC(manage_header_t *manage_header, load_header_t *load_header, uint8_t *data, uint32_t datalen, mddw_sc_t *mddw, int thr_id)
{
	online_fc_t fc;
	memset(&fc, 0, sizeof(online_fc_t));
	snprintf(fc.sessId, sizeof(fc.sessId), "%s%u", "ott", manage_header->channel);
	fc.userInfoType = 0x10005004;
	uint32_t total_len = 0, total2_len = 0, add_len = 0;
	uint32_t type = 0;
	uint32_t len = 0;
	total_len += 8;

//	total_len += 8 + sizeof(manage_header_t);
//	total_len += 8 + sizeof(load_header_t);
	total_len += 8 + sizeof(mddw_sc_t);
	total2_len = total_len - 8;
	fc.userInfo = (uint8_t *)malloc(total_len);
	fc.userInfoLen = total_len;
	type = 0x100050a0;
	type = ntohl(type);
	len = total2_len;
	len = ntohl(len);
	memcpy(fc.userInfo, &type, 4);
	memcpy(fc.userInfo + 4, &len, 4);

#if 0	
	type = 0x100050a3;
	type = ntohl(type);
	len = sizeof(manage_header_t);
	len = ntohl(len);
	memcpy(fc.userInfo + add_len, &type, 4);
	memcpy(fc.userInfo + 4 + add_len, &len, 4);
	memcpy(fc.userInfo + 8 + add_len, manage_header, sizeof(manage_header_t));

	type = 0x100050a2;
	type = ntohl(type);
	len = sizeof(load_header_t);
	len = ntohl(len);
	memcpy(fc.userInfo + (8 + sizeof(manage_header_t) + add_len), &type, 4);
	memcpy(fc.userInfo + (12 + sizeof(manage_header_t) + add_len), &len, 4);
	memcpy(fc.userInfo + (16 + sizeof(manage_header_t) + add_len), load_header, sizeof(load_header_t));
		
	type = 0x100050a1;
	len  = sizeof(mddw_sc_t);
	type = ntohl(type);
	len  = ntohl(len);
	memcpy(fc.userInfo + (sizeof(uint32_t)*4 + sizeof(manage_header_t) + sizeof(load_header_t) + add_len), &type, sizeof(uint32_t));
	memcpy(fc.userInfo + (sizeof(uint32_t)*5 + sizeof(manage_header_t) + sizeof(load_header_t) + add_len), &len, sizeof(uint32_t));
	memcpy(fc.userInfo + (sizeof(uint32_t)*6 + sizeof(manage_header_t) + sizeof(load_header_t) + add_len), mddw, sizeof(mddw_sc_t));	
#endif
	type = 0x100050a1;
	len  = sizeof(mddw_sc_t);
	type = ntohl(type);
	len  = ntohl(len);
	memcpy(fc.userInfo + (sizeof(uint32_t)*2 + add_len), &type, sizeof(uint32_t));
	memcpy(fc.userInfo + (sizeof(uint32_t)*3 + add_len), &len, sizeof(uint32_t));
	memcpy(fc.userInfo + (sizeof(uint32_t)*4 + add_len), mddw, sizeof(mddw_sc_t));
	
	do_onlineld_helper(&fc, data, datalen, manage_header->channel, thr_id);
	free((char *)fc.userInfo);
}

static void DO_DVB_FUNC(uint8_t *data, uint32_t datalen, mddw_sc_t *mddw, int thr_id)
{
	uint8_t  *movedata = data;
	uint32_t movelen = 0;
	manage_header_t manage_header;
	load_header_t   load_header;
	uint8_t pkttype = 0;;
	while(movelen < datalen)
	{
		manage_header = *(manage_header_t *)movedata;
		//memcpy(&manage_header, movedata, sizeof(manage_header_t));
		if((manage_header.flag) == 0xDF5FCF04)
		{
			if(((manage_header.pktlen) + sizeof(load_header_t) + sizeof(manage_header_t)) > (datalen - movelen))
			{
				movelen = datalen;
				continue;
			}
			pkttype = manage_header.pkttype & 0x2;
			//if(pkttype == 1 || pkttype == 2 || pkttype == 3)
			{
				load_header = *(load_header_t *)(movedata + sizeof(manage_header_t));
			//	memcpy(&load_header, movedata + sizeof(manage_header_t), sizeof(load_header_t));
				DVB_PROC(&manage_header, &load_header, movedata + sizeof(manage_header_t) + sizeof(load_header_t), (manage_header.pktlen), mddw, thr_id);	
			}
			movelen += (manage_header.pktlen) + sizeof(load_header_t) + sizeof(manage_header_t);
			movedata = movedata + (manage_header.pktlen) + sizeof(load_header_t) + sizeof(manage_header_t);
		}
		else
		{
			movelen++;
			movedata++;
		}	
	}	
}


static uint8_t *chbuff[64];
static uint32_t chbuffmaxlen = 0x3000;
static uint32_t chbufflen[64];


static int online_data_proc(uint8_t *adapt_info, uint8_t *data, uint32_t datalen, int thr_id)
{
	int i = 0;
	uint8_t *movedata = data;
	uint32_t movelen  = 0;
	uint32_t headerType = 0;
	uint16_t port = 0;
	memcpy(&port, adapt_info, sizeof(uint16_t));
	mddw_sc_t mddw;                     
	memset(&mddw, 0, sizeof(mddw_sc_t));
	while(movelen < datalen)
	{
		
		if(chbufflen[thr_id] >= sizeof(manage_header_t))
		{
			if((headerType = *(uint32_t *)chbuff[thr_id]) == 0xDF5FCF04)
			{
				manage_header_t manage_header = *(manage_header_t *)chbuff[thr_id];
				if((((manage_header.pktlen) + sizeof(manage_header_t) + sizeof(load_header_t)) - chbufflen[thr_id]) <= (datalen - movelen))
				{
					memcpy(chbuff[thr_id] + chbufflen[thr_id], movedata, (((manage_header.pktlen) + sizeof(manage_header_t) + sizeof(load_header_t)) - chbufflen[thr_id]));
					for(i = 0; i < m_mddw_gsc.mddw_sc_num; i++)
					{
						if(port == m_mddw_gsc.mddw_sc[i].port)
						{
							mddw.Stat_ID = m_mddw_gsc.mddw_sc[i].Stat_ID;                       
							memcpy(mddw.Stat_Sig_Type, m_mddw_gsc.mddw_sc[i].Stat_Sig_Type, 16);
							mddw.Stat_Freq = m_mddw_gsc.mddw_sc[i].Stat_Freq;                   
							mddw.Stat_Width = m_mddw_gsc.mddw_sc[i].Stat_Width;                 
							memcpy(mddw.Stat_Band, m_mddw_gsc.mddw_sc[i].Stat_Band, 2);         
							memcpy(mddw.Stat_Pol, m_mddw_gsc.mddw_sc[i].Stat_Pol, 1);           
							#if 0
							if(m_mddw_gsc.mddw_sc[i].channel != manage_header.channel)
							{
								printf("online_data_proc ClinetPort:%d; port:%d; ip:%s; manage_header.channel:%d; mddw_sc[%d].channel:%d;\n", port, m_mddw_gsc.mddw_sc[i].port, m_mddw_gsc.mddw_sc[i].ip, manage_header.channel, i, m_mddw_gsc.mddw_sc[i].channel);
							
								return 0;
						
							}
							#endif
					
						}		
					}
					DO_DVB_FUNC(chbuff[thr_id], (manage_header.pktlen) + sizeof(manage_header_t) + sizeof(load_header_t), &mddw, thr_id);
					movelen += ((manage_header.pktlen) + sizeof(manage_header_t) + sizeof(load_header_t)) - chbufflen[thr_id];
					movedata = movedata + (((manage_header.pktlen) + sizeof(manage_header_t) + sizeof(load_header_t)) - chbufflen[thr_id]);
				
					chbufflen[thr_id] = 0;
				}
				else
				{
					memcpy(chbuff[thr_id] + chbufflen[thr_id], movedata, datalen - movelen);
					chbufflen[thr_id] += (datalen - movelen);
					movelen += (datalen - movelen);
					movedata = movedata + (datalen - movelen);
			
				}
			}
			else
			{
				printf("headerType is %x not 0xDF5FCF04\n", (headerType));
				return 0;
			}
		}
		else
		{
			if((datalen - movelen) < (sizeof(manage_header_t) - chbufflen[thr_id]))
			{
				memcpy(chbuff[thr_id] + chbufflen[thr_id], movedata, datalen - movelen);
				chbufflen[thr_id] += (datalen - movelen);
				movelen += (datalen - movelen);
				movedata = movedata + (datalen - movelen);
			}
			else
			{
				memcpy(chbuff[thr_id] + chbufflen[thr_id], movedata, (sizeof(manage_header_t) - chbufflen[thr_id]));
				movelen += (sizeof(manage_header_t) - chbufflen[thr_id]);
				movedata = movedata + (sizeof(manage_header_t) - chbufflen[thr_id]);
				chbufflen[thr_id] += (sizeof(manage_header_t) - chbufflen[thr_id]);
			}
		}
	}	
	return NULL;
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
static uint32_t qsize = 2000;
static uint32_t malloc_size = 10*1024*1024;
static int parse_rdvb_head(uint8_t *head,uint32_t head_len,uint32_t *body_len)
{
	*body_len = qsize;
	if(head_len + *body_len > malloc_size)
	{
		printf("IP recv  data too_len\n");
		return MSG_TOO_LONG;
	}
	return MSG_OK;	
}
typedef struct{
	int use_id;
	int thr_id;
}online_rbq_init_t;


static void *online_rbq_get(void *ele)
{
	online_rbq_init_t *rbq_in = (online_rbq_init_t *)ele;
	rbq_buf_t *rbq_buf = NULL;
	while(1)
	{
		rbq_buf = rbq_get_data(udpserver_rbq_handle, rbq_in->thr_id);
		if(rbq_buf == NULL)
		{
			usleep(10);
			continue; 	
		}
		online_data_proc(rbq_buf->ext, rbq_buf->buf, rbq_buf->len, rbq_in->use_id);

		rbq_put_buf(udpserver_rbq_handle, rbq_buf);

	}
	return NULL;
}
static int online_rbq_init(int thr_id, int use_id)
{
	chbuff[use_id] = (uint8_t *)malloc(chbuffmaxlen);
	chbufflen[use_id] = 0;
#if 1
	online_rbq_init_t *rbq_in = (online_rbq_init_t *)malloc(sizeof(online_rbq_init_t));
	rbq_in->thr_id = thr_id;
	rbq_in->use_id = use_id;
	pthread_t pthid;
	int ret = pthread_create(&pthid ,NULL, online_rbq_get, (void *)rbq_in);
	if(ret != 0)
	{
		printf("pthread_create fail\n");
		exit(0);
	}
	return 0;
#endif
}
static int udpserver_qlen = 1024, udpserver_qsize = 1024 * 10, udpserver_total_mem = 1024 * 1024 * 50, udpserver_malloc_size = 1024 * 1024 * 20;

static void *udpserver_rbq_init(int moniServerSum)
{
	udpserver_rbq_handle = rbq_malloc(moniServerSum, udpserver_qlen, udpserver_qsize, moniServerSum, moniServerSum, "udpserver_rbq");
	assert(udpserver_rbq_handle != NULL);
	rbq_overcommit(udpserver_rbq_handle, udpserver_total_mem, udpserver_malloc_size);
	return NULL;
}   


static tcpserver_param_t serv_param;
static int check_helper(void *ele, char *data, int dataLen, void **user_data)
{
	manage_header_t *manage_header = (manage_header_t *)data;
	if((manage_header->flag) != 0xDF5FCF04)
	{
		printf("tcp_client_check manage_header.flag[%x] is not 0xDF5FCF04\n", (manage_header->flag));
		return UDPSERVER_ERR;
	}	
	return UDPSERVER_OK; 
}
#if 0
static int udpserver_recv(void *ele, char *data, int dataLen, void **user_data) 
{
	online_data_proc((uint8_t *)ele, (uint8_t *)data, dataLen);
	return 0;
}
#endif
int online_mddw_init(mddw_dyn_init_t *mddw_dyn_init, mddw_gsc_info_t *mddw_gsc)
{
	memcpy(&m_mddw_gsc, mddw_gsc, sizeof(mddw_gsc_info_t));
	int i = 0;
	udpserver_rbq_init(mddw_gsc->mddw_sc_num);
	udpserver_init_t udpserver;
	memset(&udpserver, 0, sizeof(udpserver_init_t));
	udpserver.moniServerSum = mddw_gsc->mddw_sc_num;
	for(i = 0; i < mddw_gsc->mddw_sc_num; i++)
		udpserver.cpuId[i] = i + 10;
	udpserver.udpserver_check;	
	udpserver.udpserver_check.bufMaxLen = 1024*10;
	udpserver.maxPackLen   = 1024 * 1204 * 10;
	udpserver.packSwitch   = 1;
	udpserver.packPushTime = 10;
	udpserver.udpserver_helper.check_helper = check_helper;
	void *hand = udpserver_init(udpserver_rbq_handle, &udpserver);
	for(i = 0; i < mddw_gsc->mddw_sc_num; i++)
		udpserver_add_socket(hand, mddw_gsc->mddw_sc[i].port);
	udpserver_recv_start(hand);
	for(i = 0; i < mddw_gsc->mddw_sc_num; i ++)
		online_rbq_init(i, mddw_dyn_init->thr_id[i]);

#if 0	
	serv_param.head_len = sizeof(manage_header_t);
	serv_param.recv_timeout = 10000;
	serv_param.parse_head   = parse_rdvb_head;
	serv_param.thr_num      = 1;
	serv_param.rbq_handle   = recv_rbq_handle;
	serv_param.part_num     = 10;
	serv_param.unit_size    = 100;	
	for(i = 0; i < serv_param.thr_num; i++)
		serv_param.cpumap[i] = 20;
	serv_param.listen_num = mddw_gsc->mddw_sc_num;
	for(i = 0; i < serv_param.listen_num ; i++)
		serv_param.listen_port_arr[i] = mddw_gsc->mddw_sc[i].port;
	if(tcpserver_init(&serv_param)==0)
	{
		printf("tcpserver_init fail\n");
		return -1;
	}   
	tcpserver_start();
#endif
	return 0;
}

int online_mddw_push(mddw_dyn_push_t *mddw_dyn_push)
{
	mddw_dyn_push->thrnum = 16;
	return 0;
}
