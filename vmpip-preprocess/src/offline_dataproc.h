/*************************************************************************
	> File Name: offline_dataproc.h
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月01日 星期一 10时19分40秒
 ************************************************************************/

#ifndef __OFFLINE_DATAPROC_H__
#define __OFFLINE_DATAPROC_H__
#include "offline.h"

#define  OFFLINE_MAX_NAME_LEN      200
#define OFFLINE_PATH_LEN    (512)    
#define OFFLINE_SESSID_LEN  (200)
#define OFFLINE_CLIENTIP_LEN  (200)
#define OFFLINE_PCAP_HEADER_T_LEN   (sizeof(pcap_header_t))
#define OFFLINE_IP_TYPE        (0x0800)


#define OFFLINE_LINK_PCAP_TYPE       (1)
#define OFFLINE_LINK_NETWORK_TYPE    (2)
#define OFFLINE_LINK_IPCAT_TYPE      (3)
#define OFFLINE_LINK_IPHC_TYPE       (4)


//数据包文件头linktype值
#define LINKTYPE_RAW_IP         101  //裸ip数据
#define LINKTYPE_HDLC           104  //hdlc数据
#define LINKTYPE_JUNIPER_ATM1   137  //juniper_atm1数据
#define LINKTYPE_ETHERNET       1    //以太数据
#define LINKTYPE_PPP            50   //ppp数据
#define LINKTYPE_LCC            113  //lcc数据

#define datatype_ip             0x01
#define datatype_dvbts          0x02
#define datatype_ciscoppp       0x03
#define datatype_ppp            0x04
#define datatype_x25            0x05
#define datatype_fram           0x06
#define datatype_atm            0x07
#define datatype_eth            0x08
#define datatype_llc            0x09
#define datatype_eth_or_llc     0x0a
#define datatype_status         0x0b
#define datatype_hdlc           0x0c
#define datatype_juniper_atm1   0x0d
#define datatype_raw_ip         0x0e
#define datatype_dvbgs          0x0f
#define datatype_sppp           0x10
#define datatype_lcc            0x11
#define datatype_ts_hdlc        0x11
#define datatype_not_ip         0x20
#define datatype_ll_unknow      0xff

#define OFFLINE_ETHERNET_T_LEN    (sizeof(offline_ethernet_t))
#define OFFLINE_LLC_T_LEN    (sizeof(uint8_t) * 3)
#define OFFLINE_HDLC_T_LEN   (sizeof(uint8_t) * 2 + sizeof(uint16_t))
#define OFFLINE_PPP_IP_TYPE      (0x0021)
#define OFFLINE_PPP_T_LEN        (sizeof(uint8_t) * 2 + sizeof(uint16_t))
#define OFFLINE_LCC_T_LEN        (sizeof(uint16_t) * 4 + sizeof(uint8_t) * 8)


#define JUNIPER_PCAP_MAGIC          0x4d4743
#define JUNIPER_FLAG_PKT_OUT        0x00     /* Outgoing packet */
#define JUNIPER_FLAG_PKT_IN         0x01     /* Incoming packet */
#define JUNIPER_FLAG_NO_L2          0x02     /* L2 header stripped */
#define JUNIPER_FLAG_EXT            0x80     /* extensions present */
#define JUNIPER_HDR_SNAP   0xaaaa03
#define JUNIPER_HDR_NLPID  0xfefe03 
#define JUNIPER_HDR_LLC_UI 0x03 
#define JUNIPER_HDR_PPP    0xff03


#pragma pack (1) 


typedef struct{
	uint8_t   *userinfo;   
	uint32_t  userinfolen;
	uint32_t  userinfotype;
	uint64_t  capTimeStamp;     
	uint64_t  analysisTimeStamp;
	online_extra_t extra;
}offline_carry_info_t;

typedef struct{
	char     path[OFFLINE_PATH_LEN];
	uint32_t path_len;
	uint32_t channel;
	char     sessid[OFFLINE_SESSID_LEN];	
	uint32_t sessid_len;
	char     clientip[OFFLINE_CLIENTIP_LEN];
	uint32_t clientip_len;
	int      thr_id;
	uint32_t linktype;
	uint32_t type;
	offline_carry_info_t offline_carry;
}offline_dataproc_info_t;

typedef struct{
	void *hand;
}offline_dataproc_extra_t;

typedef struct      
{                   
	uint32_t magic; 
	uint16_t version_major;
	uint16_t version_minor;
	uint32_t thiszone; 
 	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t linktype;
}pcap_header_t;            
typedef struct{
	void          *decoder_ctx; //处理上下文                
	ll_decoder_t  *decoder;                         
	uint8_t       *data; //缓存空间
	uint32_t       datalen; //记录缓存长度
	uint32_t       maxlen; //最大缓存长度
	uint32_t       nodistime; //记录未出数据次数，用来重置decoder_ctx
}offline_link_network_t;

typedef struct{
	pcap_t        *pcap;
	uint32_t      flagp;
}offline_link_pcap_t;

typedef struct{
	void          *handle;
	uint32_t      flagh;
}offline_link_ipcat_t;

typedef struct{
	FILE          *fp;
	uint32_t      flagf;
}offline_link_iphc_t;


typedef struct{
	offline_link_network_t *pnetwork;
	offline_link_pcap_t    *ppcap;
	offline_link_ipcat_t   *pipcat;
	offline_link_iphc_t    *piphc;
	int      thr_id;
	uint32_t linktype;
	char      *data;
	uint32_t  datalen;
	char     clientip[OFFLINE_CLIENTIP_LEN];
	uint32_t clientip_len;
	//以下为需发送内容
	char     path[OFFLINE_PATH_LEN];
	uint32_t path_len;
	uint32_t channel;
	char     sessid[OFFLINE_SESSID_LEN];	
	uint32_t sessid_len;
	uint64_t cap_timestamp;
	uint64_t analysis_timestamp;
	uint32_t datatype;
	uint32_t srcdatatype;
	uint32_t IPOffset;
	uint8_t  *userinfo;
	uint32_t  userinfolen;
	uint32_t  userinfotype;
	online_extra_t extra;
}offline_link_vender_t;

typedef struct{
	void     *rbq_buf;
	char     path[OFFLINE_PATH_LEN];   
   	uint32_t path_len;        
	uint32_t channel;     
	char     sessid[OFFLINE_SESSID_LEN];
	uint32_t sessid_len;                
	uint64_t cap_timestamp;
	uint64_t analysis_timestamp;
	uint8_t  *ip;
	uint32_t  iplen;
	uint32_t  type;
	uint32_t  IPOffset;
	uint8_t   *userinfo;
	uint32_t  userinfolen;
	uint32_t  userinfotype;
	online_extra_t extra;
}offline_dis_vender_t;


typedef struct _ll_eth_t{
	uint8_t  dmac_addr[6];
	uint8_t  smac_addr[6];
	uint16_t typeorlen;
}offline_ethernet_t;

typedef struct{
	uint8_t  DSAP;         
	uint8_t  SSAP;         
	uint8_t  Control_field;
	uint8_t  *data;
	uint32_t datalen;
}offline_LLC_t;

typedef struct{
	uint8_t  Address;
	uint8_t  Control;
	uint16_t Protocol;
	uint8_t  *data;
	uint32_t datalen;
}offline_hdlc_t;

enum {
	JUNIPER_PROTO_UNKNOWN = 0,
	JUNIPER_PROTO_IP = 2,
	JUNIPER_PROTO_MPLS_IP = 3,
	JUNIPER_PROTO_IP_MPLS = 4,
	JUNIPER_PROTO_MPLS = 5,
	JUNIPER_PROTO_IP6 = 6,
	JUNIPER_PROTO_MPLS_IP6 = 7,
	JUNIPER_PROTO_IP6_MPLS = 8,
	JUNIPER_PROTO_CLNP = 10,
	JUNIPER_PROTO_CLNP_MPLS = 32,
	JUNIPER_PROTO_MPLS_CLNP = 33,
	JUNIPER_PROTO_PPP = 200,
	JUNIPER_PROTO_ISO = 201,
	JUNIPER_PROTO_LLC = 202,
	JUNIPER_PROTO_LLC_SNAP = 203,
	JUNIPER_PROTO_ETHER = 204,
	JUNIPER_PROTO_OAM = 205,
	JUNIPER_PROTO_Q933 = 206,
	JUNIPER_PROTO_FRELAY = 207,
	JUNIPER_PROTO_CHDLC = 208
};             

typedef struct{
	uint8_t magic_number[3];
	uint8_t flags;
	uint32_t cookie1;	
	uint32_t proto;
	uint8_t  next_proto;
	char  *load;
	uint32_t loadlen;
}offline_juniper_atm1_t;

typedef struct{
	uint8_t  Address;
	uint8_t  Control;
	uint16_t Protocol;
	uint8_t  *data;
	uint32_t datalen;
}offline_ppp_t;

typedef struct{
	uint16_t Packet_type;	
	uint16_t Link_layer_address_type;
	uint16_t Link_layer_address_length;
	uint8_t  Source[8];
	uint16_t Protocol;
}offline_lcc_t;

#pragma pack (0) 
void *offline_link_dis_rbq_getdata(int thr_id);
int offline_link_dis_rbq_putdata(void *ele, int thr_id);
void  *offline_vshell_init(int thr_num);
void online_start(online_dyn_load_t *dyn_load);
int *online_mddw_start(online_helper_t *online_helper);

#endif




