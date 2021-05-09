#ifndef __LIB_LLA_H__
#define __LIB_LLA_H__

#include <stdint.h>

#define LL_RECOGNIZE_UNKNOWN	0 //未知，需要传入更多的数据
#define LL_RECOGNIZE_YES		1 //识别
#define LL_RECOGNIZE_NO			2 //不识别

#define LL_TYPE_UNKNOWN			0
#define LL_TYPE_CISCO_PPP		1
#define LL_TYPE_PPP				2
#define LL_TYPE_FRAME_RELAY		3
#define LL_TYPE_X25				4
#define	LL_TYPE_DVBTS			5
#define	LL_TYPE_HXCIP			6 
#define	LL_TYPE_HXDVBTS			7
#define	LL_TYPE_ATM				8
#define LL_TYPE_WAV				9
#define LL_TYPE_HDLC            10
#define LL_TYPE_DVBGS			11
#define LL_TYPE_HDLC_GSE		12

#define	LL_TYPE_SPPP_IP			14
#define	LL_TYPE_SPPP_CDP		15
#define	LL_TYPE_SPPP_LCP		16
#define	LL_TYPE_SPPP_CHAP		17
#define	LL_TYPE_SPPP_IPCP		18
#define LL_TYPE_TS_HDLC			19
#define LL_TYPE_SX8_GS			20


#define	LL_NAME_DVBTS		"dvb_ts"
#define	LL_NAME_HXDVBTS		"hx_dvb_ts"
#define	LL_NAME_CISCOPPP 	"cisco_ppp"
#define	LL_NAME_FR 			"frame_relay"
#define	LL_NAME_PPP 		"ppp"
#define	LL_NAME_X25 		"x_25_ex"
#define	LL_NAME_HXCIP		"hxcip"
#define	LL_NAME_ATM			"atm"
#define LL_NAME_WAV		    "wav"
#define LL_NAME_HDLC        "hdlc"
#define LL_NAME_DVBGS		"dvbgs"
#define LL_NAME_HDLC_GSE	"dvbgs_hdlc"  //HDLC封装的GSE包
#define	LL_NAME_SPPPS		"sppps"
#define LL_NAME_TS_HDLC		"ts_hdlc"
#define LL_NAME_SX8_GS		"sx8_dvbgs"



typedef struct _ll_cisco_ppp_t {
	uint8_t 	addr;
	uint8_t		control;
	uint16_t	ether_type;
}ll_cisco_ppp_t;

typedef struct _ll_ppp_t {
	uint8_t 	addr;
	uint8_t		control;
	uint16_t	proto;
}ll_ppp_t;

typedef struct _ll_frame_relay_t {
	uint8_t		addr[2]; /**数据链路链接标识**/
	uint8_t		control; /**帧类型**/
	uint8_t		nlpid; /**网络层协议标识**/
}ll_frame_relay_t;

typedef struct _ll_x25_t {
	uint8_t		hdr[6];
}ll_x25_t;

#if 0 
typedef struct _ll_dvbts_t{
	uint8_t	pdumac[6];
	uint8_t	mpe_hdr[12];
}ll_dvbts_t;
#endif 

typedef struct _ll_dvbts_t{
	uint8_t	pdumac[6];
	uint8_t	mpe_hdr[12];
	uint8_t	str_type; /**流类型：0默认值**/
	uint8_t	str_mode; /**流模式：0默认值**/
	uint8_t	isi; /**流标识：DVB-S2默认值**/
	uint16_t pid; /**包标示**/
}ll_dvbts_t;

typedef struct _ll_dvbgs_t
{
	uint8_t		signal_type; /*信号类型，DVB-S 0X00 DVB-S2 0X01，DVB-S2X 0X02，默认0x01*/
	uint8_t		str_type;    /*流类型 0：TS 1：GS， 默认1*/
	uint8_t		str_mode;    /*流模式 0 单流，1：多流*/
	uint8_t		str_id;      /*DVB-S2类型为多流模式时，输入流标识*/
}ll_dvbgs_t;

typedef struct
{
	uint8_t  	vpi;  		//虚通道标志
	uint16_t	vci;		//虚通路标志
	uint8_t 	pti ;		//净荷类型指示
	uint8_t	 	all_type;	//ATM适配层类型指示
	
}ll_atm_t;

/**SPPP信息**/
typedef struct _ll_sppp_t
{
	uint8_t		line_name[8];/**线路名称**/
	uint16_t	line_dir;/**线路方向**/
	uint32_t	line_bw;/**线路带宽**/
	uint16_t	load_type;/**载荷类型**/
	uint8_t		timestamp[12];/**时间戳**/
	uint16_t	src_addr;/**源站址**/
	uint16_t	dst_addr;/**目的站址**/
}ll_sppp_t;


typedef struct _ll_stats_t
{
	uint64_t	empty_frame;
	uint64_t	err_frame;
	uint64_t	ok_frame;
	uint64_t	ip_pkts;
	uint64_t 	other_pkts;
	char		buf[4*1024];
}ll_stats_t;

typedef struct _ll_outbuf_t
{
	uint16_t	ip_len;
	uint16_t	tag_len;
	uint32_t 	type;
	uint8_t		ip[8000];
	uint8_t		tags[184];
	int			compression_type;
}ll_outbuf_t;



typedef int (*ll_ip_helper)(ll_outbuf_t *out_buf, void *custom_ctx);
typedef int (*ll_raw_helper)(void *raw, int len, void *custom_ctx);
typedef int (*ll_decoder_recognize_helper)(void *ctx, uint8_t *input, uint32_t len);
typedef int (*ll_decoder_decode_helper)(void *ctx, uint8_t *input, uint32_t len, ll_ip_helper func,  void *custom_ctx, ll_raw_helper raw_func);
typedef int (*ll_decoder_diag_helper)(void *ctx, ll_stats_t *stats);
typedef int (*ll_decoder_free_helper)(void *ctx);
typedef void *(*ll_decoder_ctx_alloc_helper)(void);


typedef struct _ll_decoder_tag_
{
	char						name[32];
	ll_raw_helper				raw_helper;
	ll_ip_helper				ip_helper; //输出IP头
	ll_decoder_ctx_alloc_helper	ctx_alloc_helper; //alloc 每个线程的私有结构
	ll_decoder_recognize_helper	recognize_helper; //识别
	ll_decoder_decode_helper	decoder_helper; //解码
	ll_decoder_diag_helper		diag_helper; //诊断
	ll_decoder_free_helper 		free_helper; //释放
}ll_decoder_t;


/**每个类型的decoder都需要实现一个ll_decoder_init函数，函数名称固定**/
typedef ll_decoder_t * (*ll_decoder_init_helper)();



/**全局初始化，初始化一次**/
int ll_open();

void ll_free_decoder(void);

/**通过此方法获取decoder后，需要再调用ctx_alloc_helper来得到私有结构**/
ll_decoder_t *ll_find_decoder_by_name(char *name);

/**重置decoder，传入上次的decoder_ctx**/
ll_decoder_t *ll_reset_decoder_by_name(ll_decoder_t *handler, void **decoder_ctx, char *name);

/**通过此方法获取decoder，将私有结构decoder_ctx传入，之后不需要再调用ctx_alloc_helper, thread_id取值为0-63**/
ll_decoder_t *ll_find_decoder_by_data(uint8_t *input, int len, void **decoder_ctx, uint8_t thread_id);


#endif //__LIB_LLA_H__



