/*************************************************************************
	> File Name: offline_dataproc.c
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月01日 星期一 10时17分13秒
 ************************************************************************/

#include "offline.h"

#define  OFFLINE_NODIS_TIME        10
#define  OFFLINE_GLINK_NAME_LEN    20
#define  OFFLINE_FRAME_BUF_SIZE    (64)
#define  OFFLINE_MAGIC_IPHC_NUM    0xff5fcf04
#define  OFFLINE_HEADER_IPHC_LEN   sizeof(header_iphc_t)
#define  OFFLINE_NORMAL_IP_DATA_TYPE        (1)


#pragma pack (1)
typedef struct{
	uint32_t magic;
	/*
	 *      *        26      * rlen为帧长度，包含头部
	 *           *               27      */
	uint16_t rlen;
	/* uint8_t  res2[29]; */
}header_iphc_t;


typedef struct{
	uint32_t data_type; //0x1 ip, 0x2 nip, 0x3 unknown

	uint32_t llc_start; //默认0xffff
	uint32_t llc_len;

	uint32_t mac_start; //默认0xffff
	uint32_t mac_len;

	uint32_t ip_start;
	uint32_t ip_len;
}ll_pkt_info_t; //28Bytes //后面跟的就是数据部分        

typedef struct{
	char glink_name[OFFLINE_GLINK_NAME_LEN];
}offline_link_key_t;

typedef struct{
	char      downpath[OFFLINE_MAX_PATH_LEN];
	uint32_t  downswitch;
	uint32_t  networkmaxsize;
}offline_down_network_t;

typedef struct{
	offline_link_network_t network; 
	offline_link_pcap_t    pcap;
	offline_link_ipcat_t   ipcat;
	offline_link_iphc_t    iphc;
}offline_link_value_t;
#pragma pack (0)
static zlog_category_t *offline_link_zlog = NULL;
static mini_hash_t *g_offline_link_handle[OFFLINE_MAX_THR_NUM];
static uint32_t offline_link_network_mcl = 0;
static offline_vshell_gcount_t offline_gcount;
static offline_diy_helper_t   offline_diy;
static offline_down_network_t offline_down_network;

static void offline_vshell_count(void *session,int argc, char **argv, char *raw)
{
	uint32_t i = 0;
	uint64_t totalinpkts   = 0;
	uint64_t totaloutpkts  = 0;
	uint64_t totalerrpkts  = 0;
	uint64_t totalinbytes  = 0;
	uint64_t totaloutbytes = 0;
	uint64_t totalerrbytes = 0;

	vshell_printf(session, "%-10s%-15s%-15s%-15s%-15s%-15s%-15s%-10s\r\n", "channel", "inpkts", "outpkts", "errpkts", "inbytes", "outbytes", "errbytes", "thr_id");		
	for(i = 0; i < (OFFLINE_MAX_CHANNEL_NUM); i++)
	{
		if(offline_gcount.offline_count[i].countflag == 1)
		{
			
		
			vshell_printf(session, "%-10d%-15lu%-15lu%-15lu%-15lu%-15lu%-15lu%-10d\r\n", i, 
					offline_gcount.offline_count[i].inpkts,
					offline_gcount.offline_count[i].outpkts,
					offline_gcount.offline_count[i].errpkts,
					offline_gcount.offline_count[i].inbytes,
					offline_gcount.offline_count[i].outbytes,
					offline_gcount.offline_count[i].errbytes,
					offline_gcount.offline_count[i].thr_id);
			totalinpkts   += offline_gcount.offline_count[i].inpkts;
			totaloutpkts  += offline_gcount.offline_count[i].outpkts;
			totalerrpkts  += offline_gcount.offline_count[i].errpkts;
			totalinbytes  += offline_gcount.offline_count[i].inbytes;
			totaloutbytes += offline_gcount.offline_count[i].outbytes;
			totalerrbytes += offline_gcount.offline_count[i].errbytes;
		}
	
	}
	vshell_printf(session, "%-10s%-15lu%-15lu%-15lu%-15lu%-15lu%-15lu\r\n", "total", totalinpkts, totaloutpkts, totalerrpkts, totalinbytes, totaloutbytes, totalerrbytes); 

}
static void offline_vshell_speed(void *session,int argc, char **argv, char *raw)
{
	uint32_t i = 0;
	uint64_t spinpkts   = 0;
	uint64_t spoutpkts  = 0;
	uint64_t sperrpkts  = 0;
	uint64_t spinbytes  = 0;
	uint64_t spoutbytes = 0;
	uint64_t sperrbytes = 0;	

	uint64_t totalspinpkts   = 0;
	uint64_t totalspoutpkts  = 0;
	uint64_t totalsperrpkts  = 0;
	uint64_t totalspinbytes  = 0;
	uint64_t totalspoutbytes = 0;
	uint64_t totalsperrbytes = 0;


	vshell_printf(session, "%-10s%-15s%-15s%-15s%-15s%-15s%-15s%-10s\r\n", "channel", "speedinpkts", "speedoutpkts", "speederrpkts", "speedinbytes", "speedoutbytes", "speederrbytes", "thr_id");
	for(i = 0; i < (OFFLINE_MAX_CHANNEL_NUM); i++)
	{
		if(offline_gcount.offline_count[i].countflag == 1)
		{
			spinpkts    = ((offline_gcount.offline_count[i].inpkts - offline_gcount.offline_count[i].linpkts) * 1000)/(jiffies - offline_gcount.offline_count[i].ljiffies);
			spoutpkts   = ((offline_gcount.offline_count[i].outpkts - offline_gcount.offline_count[i].loutpkts) * 1000)/(jiffies - offline_gcount.offline_count[i].ljiffies);
			sperrpkts   = ((offline_gcount.offline_count[i].errpkts - offline_gcount.offline_count[i].lerrpkts) * 1000)/(jiffies - offline_gcount.offline_count[i].ljiffies);
			spinbytes   = ((offline_gcount.offline_count[i].inbytes - offline_gcount.offline_count[i].linbytes) * 1000)/(jiffies - offline_gcount.offline_count[i].ljiffies);
			spoutbytes  = ((offline_gcount.offline_count[i].outbytes - offline_gcount.offline_count[i].loutbytes) * 1000)/(jiffies - offline_gcount.offline_count[i].ljiffies);
			sperrbytes  = ((offline_gcount.offline_count[i].errbytes - offline_gcount.offline_count[i].lerrbytes) * 1000)/(jiffies - offline_gcount.offline_count[i].ljiffies);
			vshell_printf(session, "%-10d%-15lu%-15lu%-15lu%-15lu%-15lu%-15lu%-10d\r\n", i, spinpkts, spoutpkts, sperrpkts, spinbytes, spoutbytes, sperrbytes, offline_gcount.offline_count[i].thr_id);	
			totalspinpkts   += spinpkts;
			totalspoutpkts  += spoutpkts;
			totalsperrpkts  += sperrpkts;
			totalspinbytes  += spinbytes;
			totalspoutbytes += spoutbytes;
			totalsperrbytes += sperrbytes;
			offline_gcount.offline_count[i].ljiffies    = jiffies;
			offline_gcount.offline_count[i].linpkts     = offline_gcount.offline_count[i].inpkts;
			offline_gcount.offline_count[i].loutpkts    = offline_gcount.offline_count[i].outpkts;
			offline_gcount.offline_count[i].lerrpkts    = offline_gcount.offline_count[i].errpkts;
			offline_gcount.offline_count[i].linbytes    = offline_gcount.offline_count[i].inbytes;
			offline_gcount.offline_count[i].loutbytes  	= offline_gcount.offline_count[i].outbytes;
			offline_gcount.offline_count[i].lerrbytes   = offline_gcount.offline_count[i].errbytes;
		}
	}
	vshell_printf(session, "%-10s%-15lu%-15lu%-15lu%-15lu%-15lu%-15lu\r\n", "total", totalspinpkts, totalspoutpkts, totalsperrpkts, totalspinbytes, totalspoutbytes, totalsperrbytes); 

}
static void offline_vshell_file(void *session,int argc, char **argv, char *raw)
{
	uint32_t i = 0;
	vshell_printf(session, "%-10s%-25s%-10s\r\n", "channel", "filename", "thr_id");
	for(i = 0; i < (OFFLINE_MAX_CHANNEL_NUM); i++)            
	{                                                       
		if(offline_gcount.offline_count[i].countflag == 1)  
		{                                                   
			vshell_printf(session, "%-10d%-25s%-10d\r\n", i, offline_gcount.offline_count[i].nowfilename, offline_gcount.offline_count[i].thr_id);
		}
	}
}

static void offline_vshell_cmd_proc(int type, char *path, int channel)
{
	offline_dataproc_info_t dataproc;                     
	memset(&dataproc, 0, sizeof(offline_dataproc_info_t));
	snprintf(dataproc.path, OFFLINE_PATH_LEN, "%s", path);
	dataproc.path_len = strlen(path);
	dataproc.channel  = channel;
	snprintf(dataproc.sessid, OFFLINE_SESSID_LEN, "%s%d", "ott", dataproc.channel);
	dataproc.sessid_len = strlen(dataproc.sessid);
	snprintf(dataproc.clientip, OFFLINE_CLIENTIP_LEN, "%s", "0.0.0.0");
	dataproc.clientip_len = strlen(dataproc.clientip);
	dataproc.thr_id    = offline_get_max_thr_num();
	dataproc.type      = type;
	offline_link_proc(NULL, &dataproc, offline_get_max_thr_num());	
}

static void offline_vshell_cmd_dir(int type, char *path, int channel)
{
	struct stat s_buf;
	stat(path, &s_buf);	
	if(S_ISDIR(s_buf.st_mode))
	{
		DIR *dp = NULL;
		dp = opendir(path);
		struct dirent   *dirt = NULL;
		char pathx[512] = {0};
		while(dirt = readdir(dp))
		{
			if(strcmp(dirt->d_name, ".") != 0 && strcmp(dirt->d_name, "..") != 0)
			{
				snprintf(pathx, 512, "%s/%s", path, dirt->d_name);
				struct stat n_buf;
				stat(pathx, &n_buf);
				if(S_ISDIR(n_buf.st_mode))
					offline_vshell_cmd_dir(type, pathx, channel);
				else if(S_ISREG(n_buf.st_mode))
					offline_vshell_cmd_proc(type, pathx, channel);
			}
		}
	}
	else if(S_ISREG(s_buf.st_mode))
	{
		offline_vshell_cmd_proc(type, path, channel);
	}
}


static void offline_vshell_cmd(void *session,int argc, char **argv, char *raw)
{
	if(argc == 3 || argc == 4)
	{
		if(argc == 3)
			offline_vshell_cmd_dir(atoi(argv[1]), argv[2], 0);
		else if(argc == 4)
			offline_vshell_cmd_dir(atoi(argv[1]), argv[2], atoi(argv[3]));
	}
	else
	{
		vshell_printf(session, "%-50s\r\n", "cmd for example：offline_count cmd type path channel");
		vshell_printf(session, "%-50s\r\n", "type(1：pcap数据包读取；2：链路数据处理；3：IP数据探测；4：IPHC数据处理)");
		vshell_printf(session, "%-50s\r\n", "path(处理的文件路径或者目录)");
		vshell_printf(session, "%-50s\r\n", "channel(指定处理数据的通道，可有可无，默认为0通道)");
		vshell_printf(session, "%-50s\r\n", "cmd for example no chanel：offline_count cmd 1 ./test.pcap");
		vshell_printf(session, "%-50s\r\n", "cmd for example：offline_count cmd 1 ./test.pcap 3");
	}
}

void  *offline_vshell_init(int thr_num)
{
	uint32_t i = 0;
	void *comdoffline = NULL;

	printf("offline_vshell_init start[%s-%s-%d]\n", __FILE__, __func__, __LINE__);
	memset(&offline_gcount, 0 ,sizeof(offline_vshell_gcount_t));		
	
	for(i = 0; i < (OFFLINE_MAX_CHANNEL_NUM); i++)
	{
		offline_gcount.offline_count[i].ljiffies = jiffies;
	}

	comdoffline = vshell_register_cmd(cmd_root,"offline_count", "offline", NULL);
	vshell_register_cmd(comdoffline, "count", "show count", offline_vshell_count);
	vshell_register_cmd(comdoffline, "speed", "show speed", offline_vshell_speed);
	vshell_register_cmd(comdoffline, "file", "show file", offline_vshell_file);
	vshell_register_cmd(comdoffline, "cmd", "data proc", offline_vshell_cmd);
	printf("offline_vshell_init end[%s-%s-%d]\n", __FILE__, __func__, __LINE__);

	return NULL;
}

static int onlineip_fb_entry(void *session, online_fb_t *fb, uint8_t *data, uint32_t datalen, uint32_t datatype, uint32_t channel, int thr_id, void **user_data)
{
	if(fb == NULL || data == NULL || datalen <= 0 || thr_id > OFFLINE_MAX_THR_NUM)
		return -1;
	uint32_t ckchannel = channel;
	if(channel >= OFFLINE_MAX_CHANNEL_NUM)
		ckchannel = OFFLINE_MAX_CHANNEL_NUM - 1;

	offline_gcount.offline_count[ckchannel].countflag = 1;
	offline_gcount.offline_count[ckchannel].thr_id    = thr_id;


	offline_link_vender_t vender;
	memset(&vender, 0, sizeof(offline_link_vender_t));
	snprintf(vender.sessid, OFFLINE_SESSID_LEN, "%s", fb->sessId);	
	vender.data                = (char *)data;
	vender.datalen             = datalen;
	vender.sessid_len          = fb->sessIdLen;
	vender.cap_timestamp       = fb->capTimeStamp;
	vender.analysis_timestamp  = fb->analysisTimeStamp;
	vender.channel             = channel;
	vender.IPOffset            = fb->IPOffset;	
	vender.userinfo            = fb->userInfo;
	vender.userinfolen         = fb->userInfoLen;
	vender.userinfotype        = fb->userInfoType;
	vender.extra.hostIp        = fb->extra.hostIp;
	vender.extra.dataType      = fb->extra.dataType;	

	
	offline_gcount.offline_count[ckchannel].inpkts   += 1;
	offline_gcount.offline_count[ckchannel].inbytes  += datalen;

	offline_gcount.offline_count[ckchannel].inpktsf   += 1;
	offline_gcount.offline_count[ckchannel].inbytesf  += datalen;



	offline_link_dis_rbq_getbuf(&vender, data, datalen, datatype, thr_id);	


	offline_gcount.offline_count[ckchannel].outpkts   += 1;
	offline_gcount.offline_count[ckchannel].outbytes  += datalen; 


	offline_gcount.offline_count[ckchannel].outpktsf   += 1;    
	offline_gcount.offline_count[ckchannel].outbytesf  += datalen;
	
	offline_status_get(&offline_gcount.offline_count[ckchannel], ckchannel, vender.sessid, "ONLINE", NULL, NULL, 0, OFFLINE_STATUS_NOTF_MESS_TYPE, NULL, thr_id);	
	
	return 0;
}


static void offline_link_vender_fill(offline_dataproc_info_t *pdataproc, offline_link_vender_t *pvender)
{
	memset(pvender, 0, sizeof(offline_link_vender_t));
	snprintf(pvender->path, OFFLINE_PATH_LEN, "%s", pdataproc->path);
	pvender->path_len = pdataproc->path_len;
	snprintf(pvender->sessid, OFFLINE_SESSID_LEN, "%s", pdataproc->sessid);
	pvender->sessid_len = pdataproc->sessid_len;	
	snprintf(pvender->clientip, OFFLINE_CLIENTIP_LEN, "%s", pdataproc->clientip);
	pvender->clientip_len = pdataproc->clientip_len;
	pvender->channel  = pdataproc->channel;
	pvender->thr_id   = pdataproc->thr_id;
	pvender->linktype = pdataproc->linktype;
	pvender->userinfo = pdataproc->offline_carry.userinfo;
	pvender->userinfolen        = pdataproc->offline_carry.userinfolen;
	pvender->userinfotype       = pdataproc->offline_carry.userinfotype;
	pvender->cap_timestamp      = pdataproc->offline_carry.capTimeStamp;
	pvender->analysis_timestamp = pdataproc->offline_carry.analysisTimeStamp;
	pvender->extra.hostIp       = pdataproc->offline_carry.extra.hostIp;
	pvender->extra.dataType     = pdataproc->offline_carry.extra.dataType;
	return;
}

static mini_hash_node_t *offline_link_hash_find(offline_link_key_t *key, uint32_t type, int thr_id)
{
	mini_hash_node_t *node = mini_hash_find_node(g_offline_link_handle[thr_id], key, sizeof(offline_link_key_t));
	if(!node)
	{
		offline_link_value_t value;
		memset(&value, 0, sizeof(offline_link_value_t));
		switch(type)
		{
			case OFFLINE_LINK_NETWORK_TYPE:
				value.network.data = malloc(offline_link_network_mcl);
				assert(value.network.data);
				value.network.decoder_ctx = NULL;
				value.network.decoder     = NULL;
				value.network.maxlen      = offline_link_network_mcl;
				value.network.datalen     = 0;
				value.network.nodistime   = 0;
				break;
			case OFFLINE_LINK_PCAP_TYPE:
				value.pcap.pcap   = NULL;
				value.pcap.flagp  = 0; 
				break;
			case OFFLINE_LINK_IPCAT_TYPE:
				value.ipcat.handle = NULL;
				value.ipcat.flagh  = 0;
				break;
			case OFFLINE_LINK_IPHC_TYPE:
				value.iphc.fp    = NULL;
				value.iphc.flagf = 0;
				break;
		}
		mini_hash_add_ex(g_offline_link_handle[thr_id], key, sizeof(offline_link_key_t), &value, sizeof(offline_link_value_t), &node);
	}
	return node;
}
static uint8_t ip_heuristic_guess(uint8_t ip_header_byte) 
{

	switch(ip_header_byte) {
		case 0x45:
		case 0x46:
		case 0x47:
		case 0x48:
		case 0x49:
		case 0x4a:
		case 0x4b:
		case 0x4c:
		case 0x4d:
		case 0x4e:
		case 0x4f:
			return JUNIPER_PROTO_IP;
		case 0x60:
		case 0x61:
		case 0x62:
		case 0x63:
		case 0x64:
		case 0x65:
		case 0x66:
		case 0x67:
		case 0x68:
		case 0x69:
		case 0x6a:
		case 0x6b:
		case 0x6c:
		case 0x6d:
		case 0x6e:
		case 0x6f:
			return JUNIPER_PROTO_IP6;
		default:                                      
			return JUNIPER_PROTO_UNKNOWN; /* did not find a ip header */
	}
}
static int offline_juniper_atm1_proc(char *pkt, uint32_t len, offline_juniper_atm1_t *juniper_atm1, int thr_id)
{

	uint32_t magic_number = 0;
	uint32_t offset = 0;	
	uint8_t atm1_header_len = 0;
	uint16_t ext_total_len = 0, hdr_len = 0, ethtype = 0;
	juniper_atm1->next_proto = JUNIPER_PROTO_UNKNOWN;
	if(len < sizeof(uint32_t))	
		return -1;
	memcpy(juniper_atm1->magic_number, pkt + offset, sizeof(juniper_atm1->magic_number));
	memcpy(&magic_number, juniper_atm1->magic_number, sizeof(juniper_atm1->magic_number));
	magic_number = ntohl(magic_number) >> 8;
	if(magic_number != JUNIPER_PCAP_MAGIC)
		return -1;
	offset += sizeof(juniper_atm1->magic_number);
	memcpy(&juniper_atm1->flags, pkt + offset, sizeof(juniper_atm1->flags));
	offset += sizeof(juniper_atm1->flags);
	if ((juniper_atm1->flags & JUNIPER_FLAG_EXT) == JUNIPER_FLAG_EXT)
	{
		memcpy(&ext_total_len, pkt + offset, sizeof(ext_total_len));
		hdr_len = 6 + ext_total_len;
	}
	else
	{
		hdr_len = 4;	
	}
	if((juniper_atm1->flags & JUNIPER_FLAG_NO_L2) == JUNIPER_FLAG_NO_L2)
	{
	//	memcpy(&juniper_atm1->proto, pkt + hdr_len, sizeof(juniper_atm1->proto));
		offset += hdr_len;
		if(offset > len)
			return -1;
		juniper_atm1->load = pkt + offset;
		juniper_atm1->loadlen = len - offset;
		juniper_atm1->next_proto = JUNIPER_PROTO_IP; 
		return 0;
	} 
	else
	{
		atm1_header_len = 4;
	}
	offset = hdr_len;
	if((offset + sizeof(juniper_atm1->cookie1))>= len)
		return -1;
	memcpy(&juniper_atm1->cookie1, pkt + offset, sizeof(juniper_atm1->cookie1));
	offset += atm1_header_len;
	if((juniper_atm1->cookie1 >> 24) == 0x80)
	{
		juniper_atm1->next_proto = JUNIPER_PROTO_OAM;
		return 0;
	}
	if((offset + sizeof(juniper_atm1->proto) - 1) > len) //只需要拷贝3个字节作为proto
		return -1;
	memcpy(&juniper_atm1->proto, pkt + offset, sizeof(juniper_atm1->proto) - 1);
	juniper_atm1->proto = ntohl(juniper_atm1->proto) >> 8;
	if(juniper_atm1->proto == JUNIPER_HDR_NLPID)
	{	
		return -1;
	}
	if(juniper_atm1->proto == JUNIPER_HDR_SNAP)
	{
		offset += 6;  //偏移0xaaaa03 以及 0x000000 6个字节
		if(offset > len)
			return -1;
		memcpy(&ethtype, pkt + offset, sizeof(ethtype));
		if(ntohs(ethtype) == 0x0800)
		{
			offset += sizeof(ethtype);
			juniper_atm1->load = pkt + offset;
			juniper_atm1->loadlen = len - offset;
			juniper_atm1->next_proto = JUNIPER_PROTO_IP;
			return 0;
		}
		else
			return -1;
	}
	memset(&juniper_atm1->proto, 0, sizeof(juniper_atm1->proto));
//	memcpy(juniper_atm1->proto, pkt + offset, sizeof(juniper_atm1->proto) - 2);
//	juniper_atm1->proto = ntohs(juniper_atm1->proto);
	memcpy(&juniper_atm1->proto, pkt + offset, sizeof(uint8_t));
	if(juniper_atm1->proto == JUNIPER_HDR_LLC_UI)
	{
		offset += sizeof(uint8_t) * 2;
		juniper_atm1->load = pkt + offset;
		if(offset >= len)
		{
			return -1;
		}
		juniper_atm1->loadlen = len - offset;	
		juniper_atm1->next_proto = JUNIPER_PROTO_IP; 
		return 0;
	}
	juniper_atm1->next_proto = ip_heuristic_guess((uint8_t)juniper_atm1->proto);
	
	return 0;
}


static char *offline_link_pcap_dis(offline_link_vender_t *pvender, uint32_t *dstdatalen, char *srcdata, uint32_t srcdatalen)
{
	char *dstdata = NULL;
	int thr_id = pvender->thr_id;
	switch(pvender->linktype)
	{
		case LINKTYPE_RAW_IP:
			pvender->srcdatatype = datatype_raw_ip;
			dstdata    = srcdata;
			*dstdatalen = srcdatalen;
			pvender->datatype = datatype_ip;
			break;	
		case LINKTYPE_HDLC:
			pvender->srcdatatype = datatype_hdlc;
			offline_hdlc_t hdlc;		
			memcpy(&hdlc, srcdata, OFFLINE_HDLC_T_LEN);
			if(ntohs(hdlc.Protocol) == OFFLINE_IP_TYPE)
			{
				dstdata   = srcdata + OFFLINE_HDLC_T_LEN;
				*dstdatalen = srcdatalen - OFFLINE_HDLC_T_LEN;
				pvender->datatype = datatype_ip;
			}
			else
			{
				dstdata    = srcdata;     
				*dstdatalen = srcdatalen;			
				pvender->srcdatatype = datatype_eth;
			}
			hdlc.data      = (uint8_t *)(srcdata + OFFLINE_HDLC_T_LEN);
			hdlc.datalen   = srcdatalen - OFFLINE_HDLC_T_LEN;

			break;
		case LINKTYPE_JUNIPER_ATM1:
			pvender->srcdatatype = datatype_juniper_atm1;
			offline_juniper_atm1_t juniper_atm1;
			offline_juniper_atm1_proc(srcdata, srcdatalen, &juniper_atm1, thr_id);	

			if(juniper_atm1.next_proto == JUNIPER_PROTO_IP)      
			{
				dstdata    = juniper_atm1.load;
				*dstdatalen = juniper_atm1.loadlen;
				pvender->datatype    = datatype_ip;
			}   
			else
			{ 
				dstdata    = srcdata;
				*dstdatalen = srcdatalen;
				pvender->datatype = datatype_eth;
			}
			break;
		case LINKTYPE_ETHERNET:
			pvender->srcdatatype = datatype_eth;
			offline_ethernet_t ethernet_t;
			memcpy(&ethernet_t, srcdata, OFFLINE_ETHERNET_T_LEN);
			if(ntohs(ethernet_t.typeorlen) == OFFLINE_IP_TYPE)
			{
				dstdata   = srcdata + OFFLINE_ETHERNET_T_LEN;
				*dstdatalen = srcdatalen - OFFLINE_ETHERNET_T_LEN;
				pvender->datatype = datatype_ip;
			}
			else
			{
				offline_LLC_t LLC;
				memcpy(&LLC, srcdata + OFFLINE_ETHERNET_T_LEN, OFFLINE_LLC_T_LEN);
				LLC.data    = (uint8_t *)(srcdata + OFFLINE_ETHERNET_T_LEN + OFFLINE_LLC_T_LEN);
				LLC.datalen = srcdatalen - (OFFLINE_ETHERNET_T_LEN + OFFLINE_LLC_T_LEN);


				dstdata    = srcdata;     
				*dstdatalen = srcdatalen;
				pvender->datatype = datatype_eth;
			}
			break;
		case LINKTYPE_PPP:
			pvender->srcdatatype = datatype_ppp;
			offline_ppp_t ppp;
			memcpy(&ppp, srcdata, OFFLINE_PPP_T_LEN);
			if(ntohs(ppp.Protocol) == OFFLINE_PPP_IP_TYPE)
			{
				dstdata    = srcdata + OFFLINE_PPP_T_LEN;   
				*dstdatalen = srcdatalen - OFFLINE_PPP_T_LEN;
				pvender->datatype = datatype_ip;                 
			}
			else
			{
				dstdata = srcdata;     
				*dstdatalen = srcdatalen;
				pvender->datatype = datatype_eth;
			}
			break;
		case LINKTYPE_LCC:
			pvender->srcdatatype = datatype_lcc;
			offline_lcc_t lcc;
			memcpy(&lcc, srcdata, OFFLINE_LCC_T_LEN);	
			if(ntohs(lcc.Protocol) == OFFLINE_IP_TYPE)
			{
				dstdata    = srcdata + OFFLINE_LCC_T_LEN;
				*dstdatalen = srcdatalen - OFFLINE_LCC_T_LEN;
				pvender->datatype = datatype_ip;
			}
			else
			{
				dstdata = srcdata;
				*dstdatalen = srcdatalen;
				pvender->datatype = datatype_eth;
			}
			break;
		default:
			pvender->srcdatatype = datatype_eth;
			dstdata    = srcdata;
			*dstdatalen = srcdatalen;
			pvender->datatype = datatype_eth;
			break;
	}
	return dstdata;
}

static void offline_link_pcap_callback(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *pktset)
{
	offline_link_vender_t *pvender = (offline_link_vender_t *)arg;
	offline_gcount.offline_count[pvender->channel].inpkts   += 1;
	offline_gcount.offline_count[pvender->channel].inbytes  += pkthdr->caplen;

	offline_gcount.offline_count[pvender->channel].inpktsf   += 1;
	offline_gcount.offline_count[pvender->channel].inbytesf  += pkthdr->caplen;

	pvender->cap_timestamp      = jiffies;
	pvender->analysis_timestamp = jiffies;	


	pvender->data = offline_link_pcap_dis(pvender, &pvender->datalen, (char *)pktset, pkthdr->caplen);
	offline_link_dis_rbq_getbuf(pvender, (uint8_t *)pvender->data, pvender->datalen, pvender->datatype, pvender->thr_id);	


	offline_gcount.offline_count[pvender->channel].outpkts   += 1;
	offline_gcount.offline_count[pvender->channel].outbytes  += pvender->datalen; 


	offline_gcount.offline_count[pvender->channel].outpktsf   += 1;    
	offline_gcount.offline_count[pvender->channel].outbytesf  += pvender->datalen;
	pvender->ppcap->flagp = 0;


	offline_status_ex_t status_ex;
	snprintf(status_ex.clientip, OFFLINE_CLIENTIP_LEN, "%s", pvender->clientip);
	offline_status_get(&offline_gcount.offline_count[pvender->channel], pvender->channel, pvender->sessid, "PCAP", pvender->path, NULL, 0, OFFLINE_STATUS_NOTF_MESS_TYPE, &status_ex, pvender->thr_id);	
	
	return ;	
}

static void offline_link_pcap_proc(offline_dataproc_info_t *dataproc, int thr_id)
{
	FILE *fp = NULL;
	pcap_header_t pcap_header;
	uint32_t datalen = 0;
	char ebuff[512] = {0};

	if((fp = fopen(dataproc->path, "r")) != NULL)
	{
		fseek(fp, 0L, SEEK_END);
		datalen = ftell(fp);
		if(datalen < OFFLINE_PCAP_HEADER_T_LEN)
		{
			//错误状态信息上报
			fclose(fp);
			return;
		}
		fseek(fp, 0L, SEEK_SET);                        
		fread(&pcap_header, OFFLINE_PCAP_HEADER_T_LEN, 1, fp);
		dataproc->linktype = pcap_header.linktype;
		fclose(fp);
	}
	offline_link_key_t key;             
	offline_link_value_t *pvalue = NULL;
	memset(&key, 0, sizeof(offline_link_key_t));
	snprintf(key.glink_name, OFFLINE_GLINK_NAME_LEN, "%d", dataproc->channel);
	offline_link_vender_t vender;
	offline_link_vender_fill(dataproc, &vender);
	mini_hash_node_t *node = offline_link_hash_find(&key, dataproc->type, thr_id);
	if(node)
	{
		pvalue = (offline_link_value_t *)mini_hash_get_node_value(g_offline_link_handle[thr_id], node);	
		assert(pvalue);
		vender.ppcap = &pvalue->pcap;
		if(pvalue->pcap.flagp == 0)
		{
			pvalue->pcap.pcap = pcap_open_offline(dataproc->path, ebuff);
			if(!pvalue->pcap.pcap)
			{			
				//错误状态信息上报
				return;
			}
			pvalue->pcap.flagp = 1;
		}
		pcap_loop(pvalue->pcap.pcap, -1, offline_link_pcap_callback, (u_char *)&vender);		
		if(pvalue->pcap.flagp == 0)
		{
			pcap_close(pvalue->pcap.pcap);
			pvalue->pcap.pcap = NULL;
		}
	}
	return;
}
static char      g_iphc_name[OFFLINE_MAX_NAME_LEN];
static void      *g_iphc_ctx = NULL;
static uint8_t   g_iphc_frame_buf[OFFLINE_MAX_THR_NUM][OFFLINE_FRAME_BUF_SIZE];
static int iphc_handle_init(int thr_num)                    
{
	fbl2_iphc_init();
	fbl2_iphc_params_t iphc_params;
	if(g_iphc_ctx == NULL)
	{
		snprintf(g_iphc_name, OFFLINE_MAX_NAME_LEN, "iphc_handle");
		iphc_params.name = g_iphc_name;
		iphc_params.thr_num = thr_num;
		g_iphc_ctx = fbl2_iphc_create(&iphc_params);
		assert(g_iphc_ctx != NULL);
	}
	return 1;
}

static int offline_diy_entry(void *session, uint8_t *data, uint32_t datalen, uint32_t datatype, uint8_t *userinfo, uint32_t userinfolen, uint32_t userinfotype, void *ele, int thr_id, void **user_data)
{

	offline_link_vender_t *pvender = (offline_link_vender_t *)ele;
	offline_gcount.offline_count[pvender->channel].inpkts   += 1;
	offline_gcount.offline_count[pvender->channel].inbytes  += datalen;

	offline_gcount.offline_count[pvender->channel].inpktsf   += 1;
	offline_gcount.offline_count[pvender->channel].inbytesf  += datalen;


	pvender->cap_timestamp      = jiffies;
	pvender->analysis_timestamp = jiffies;
	pvender->userinfo           = userinfo;
	pvender->userinfolen        = userinfolen;
	pvender->userinfotype       = userinfotype;	
	offline_link_dis_rbq_getbuf(pvender, data, datalen, datatype, pvender->thr_id);	

	offline_gcount.offline_count[pvender->channel].outpkts   += 1;
	offline_gcount.offline_count[pvender->channel].outbytes  += datalen; 


	offline_gcount.offline_count[pvender->channel].outpktsf   += 1;    
	offline_gcount.offline_count[pvender->channel].outbytesf  += datalen;

	offline_status_get(&offline_gcount.offline_count[pvender->channel], pvender->channel, pvender->sessid, "DIY", pvender->path, NULL, 0, OFFLINE_STATUS_NOTF_MESS_TYPE, NULL, pvender->thr_id);	
	return 0;
}

int offline_link_init(uint32_t diy_switch, char *diy_path, uint32_t max_cache_len, uint32_t g_offline_link_bucket, uint32_t g_offline_link_node, int thr_num, int exthrnum)
{
	int i = 0, err = 0;
	diy_helper_t diy;

	if(max_cache_len <= 0 || g_offline_link_bucket <= 0 || g_offline_link_node <= 0 || thr_num < 0)
	{
		printf("offline_link_init error [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		exit(0);
	}
	offline_link_network_mcl = max_cache_len;
	capture_proc_init();
	iphc_handle_init(thr_num);
	offline_vshell_init(thr_num + exthrnum);
	if(diy_switch == OFFLINE_SWITCH_OPEN)
	{
		offline_diy_load(&offline_diy, diy_path);
	}
	if(offline_diy.canflag == OFFLINE_SWITCH_OPEN)
	{
		memset(&diy, 0 , sizeof(diy_helper_t));
		diy.diy_entry = offline_diy_entry;
		offline_diy.diy_init(thr_num);
		offline_diy.diy_register(&diy);
	}
	err = ll_open();              
	if(err != 0)                  
	{                             
		printf("ll_open error [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		exit(0);                  
	}                             
	offline_link_zlog = zlog_get_category("offline_link_zlog");
	if(!offline_link_zlog)
	{
		printf("zlog_get_category [offline_link_zlog] error [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		exit(0);
	}	
	for(i = 0; i < (thr_num + exthrnum); i ++)
	{
		g_offline_link_handle[i] = (mini_hash_t *)malloc(sizeof(mini_hash_t));
		assert(g_offline_link_handle[i]);
		err = mini_hash_create(g_offline_link_handle[i], g_offline_link_bucket, g_offline_link_node, sizeof(offline_link_key_t), sizeof(offline_link_value_t), fifo_expire);
		if(err)
		{
			printf("mini_hash_create error [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
			exit(0);
		}
		err = mini_hash_build_table(g_offline_link_handle[i]);
		if(err)
		{
			printf("mini_hash_build_table error [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
			exit(0);
		}
	}
	return 0;
}



static int  offline_link_network_lla_callbackp2(void *raw, int len, void *custom_ctx)
{
	offline_link_vender_t *pvender = (offline_link_vender_t *)custom_ctx;
	offline_gcount.offline_count[pvender->channel].inpkts   += 1;
	offline_gcount.offline_count[pvender->channel].inpktsf   += 1;



	return 0;
}

static void offline_link_network_lla_dis(offline_link_vender_t *pvender, uint32_t type, uint8_t *data, uint32_t datalen, int thr_id)
{
	uint32_t  iplen = datalen;
	uint16_t  protype = 0;
	uint16_t  prohead = 0xff03;
	switch(type)
	{
		case LL_TYPE_SPPP_CDP:
			protype = 0x0207;
			goto leave;
		case LL_TYPE_SPPP_LCP:
			protype = 0xc021;
			goto leave;
		case LL_TYPE_SPPP_CHAP:
			protype = 0xc223;
			goto leave;
		case LL_TYPE_SPPP_IPCP:
			protype = 0x8021;
leave:
			prohead = ntohs(prohead);
			protype = ntohs(protype);
			uint8_t noip[65535] = {0};
			memcpy(noip, &prohead, sizeof(prohead));
			memcpy(noip + sizeof(prohead), &protype, sizeof(protype));
			memcpy(noip + sizeof(prohead) + sizeof(protype), data, datalen);
			iplen = sizeof(prohead) + sizeof(protype) + datalen;
			offline_link_dis_rbq_getbuf(pvender, noip, iplen, datatype_not_ip, thr_id);
		break;
		default:
			offline_link_dis_rbq_getbuf(pvender, data, datalen, datatype_ip, thr_id);	
		break;
	}
	
	offline_gcount.offline_count[pvender->channel].outpkts  += 1;
	offline_gcount.offline_count[pvender->channel].outbytes += iplen;
	
	offline_gcount.offline_count[pvender->channel].outpktsf  += 1;              
	offline_gcount.offline_count[pvender->channel].outbytesf += iplen;
}

static int  offline_link_network_lla_callbackp1(ll_outbuf_t *out_buf, void *custom_ctx)
{
	offline_link_vender_t *pvender = (offline_link_vender_t *)custom_ctx;
	int thr_id = pvender->thr_id;
	if(out_buf->ip_len <= 0)
	{		
		printf("offline_link_network_lla_callbackp1 fail [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		offline_gcount.offline_count[pvender->channel].errpkts += 1;
		offline_gcount.offline_count[pvender->channel].errpktsf += 1;
		pvender->pnetwork->nodistime++;
		return -1;
	}
	if(pvender->cap_timestamp == 0)
		pvender->cap_timestamp      = jiffies;
	pvender->analysis_timestamp     = jiffies;	

	offline_link_network_lla_dis(pvender, out_buf->type, out_buf->ip, out_buf->ip_len, thr_id);

	offline_comm_ele_ll_info_entry(out_buf->type, out_buf->tags, pvender, thr_id);	

	offline_status_ex_t status_ex;
	snprintf(status_ex.clientip, OFFLINE_CLIENTIP_LEN, "%s", pvender->clientip);	
	offline_status_get(&offline_gcount.offline_count[pvender->channel], pvender->channel, pvender->sessid, "NETWORK", pvender->path, NULL, 0, OFFLINE_STATUS_NOTF_MESS_TYPE, &status_ex, thr_id);	
	
	return 0;
}

static int offline_link_network_discern(offline_link_network_t *pnetwork, uint8_t *data, uint32_t datalen, int thr_id)
{
	pnetwork->decoder = ll_find_decoder_by_data(data, datalen, &pnetwork->decoder_ctx, thr_id);
	if(!pnetwork->decoder)
		return -1;
	return 0;
}

//缓存空间刷新
void offline_link_network_proc_flush(offline_dataproc_info_t *pdataproc, int thr_id)
{
	if(pdataproc == NULL || thr_id < 0)	
	{
		printf("offline_link_network_proc_flush error [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		return ;
	}
	offline_link_key_t key;
	offline_link_value_t *pvalue = NULL;
	int ret = 0;

	memset(&key, 0, sizeof(offline_link_key_t));
	snprintf(key.glink_name, OFFLINE_GLINK_NAME_LEN, "%d", pdataproc->channel);	
	offline_link_vender_t vender;
	offline_link_vender_fill(pdataproc, &vender);
	mini_hash_node_t *node = offline_link_hash_find(&key, pdataproc->type, thr_id);
	if(node)
	{
		pvalue = (offline_link_value_t *)mini_hash_get_node_value(g_offline_link_handle[thr_id], node);	
		assert(pvalue);
		vender.pnetwork = &pvalue->network;	
		if(!pvalue->network.decoder)	
		{
			ret = offline_link_network_discern(&pvalue->network, pvalue->network.data, pvalue->network.datalen, thr_id);
			if(ret == 0)
			{
				pvalue->network.decoder->decoder_helper(pvalue->network.decoder_ctx, pvalue->network.data, pvalue->network.datalen, offline_link_network_lla_callbackp1, &vender, offline_link_network_lla_callbackp2);
			}			
		}
		else
		{
			pvalue->network.decoder->decoder_helper(pvalue->network.decoder_ctx, pvalue->network.data, pvalue->network.datalen, offline_link_network_lla_callbackp1, &vender, offline_link_network_lla_callbackp2);
		}
		if(pvalue->network.decoder != NULL)
		{
			pvalue->network.decoder->free_helper(pvalue->network.decoder_ctx);
			pvalue->network.decoder = NULL;
			pvalue->network.nodistime = 0;
			pvalue->network.decoder_ctx = NULL;
		}
	}
	return;
}

void offline_down_network_info_set(offline_init_t *offinit)
{
	if(offinit == NULL)                                                                 
		return;                                                                         
	snprintf(offline_down_network.downpath, OFFLINE_MAX_PATH_LEN, "%s", offinit->downlnwpath);
	offline_down_network.downswitch     = offinit->downlnwswitch;                                
	offline_down_network.networkmaxsize = offinit->lnwsize;                                  
	return;
}

static void offline_link_network_write(uint8_t *data, uint32_t datalen, char *downpath, uint32_t channel, int thr_id) 
{
	char datatime[215] = {0};
	char path[2048] = {0};
	int filesize = 0;
	time_t ptime;
	struct tm *ptm = NULL;
	uint32_t pflag = 0;
	
	time(&ptime);
	ptm = localtime(&ptime);
	snprintf(datatime, 200, "%04d-%02d-%02d", ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday);

	if(data == NULL || datalen <= 0 || downpath == NULL)
	{
		printf("offline_link_network_write fail! channel[%d] thr_id[%d] [%s-%s-%d]\n", channel, thr_id, __FILE__, __func__, __LINE__);
		return;
	}
	if(access(downpath, F_OK)  == -1)
	{
		comm_mkdirs_operation(downpath);
	}
	snprintf(path, sizeof(path),"%s/%s-%d-%d%s", downpath, datatime, channel, thr_id,".dat");
	while((filesize = offline_get_file_size(path)) != -1 && (filesize = offline_get_file_size(path)) > offline_down_network.networkmaxsize)
	{
		pflag++;
		snprintf(path, sizeof(path), "%s/%s-%d-%d-%d%s", downpath, datatime, channel, thr_id,pflag, ".dat");
	}
	FILE *fp = NULL;
	if((fp = fopen(path,"ab+")) != NULL)
	{
		fwrite(data, datalen, 1 ,fp);
		fclose(fp); 
	}
	return;
}

//数据缓存
void offline_link_network_proc(uint8_t *data, uint32_t datalen, offline_dataproc_info_t *pdataproc, int thr_id)
{
	if(data == NULL || datalen <= 0 || pdataproc == NULL || thr_id < 0)	
	{
	//	printf("offline_link_network_proc error [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		zlog_error(offline_link_zlog, "offline_link_network_proc error [%s-%s-%d]", __FILE__, __func__, __LINE__);
		return ;
	}
	offline_link_key_t key;
	offline_link_value_t *pvalue = NULL;
	int ret = 0;

	memset(&key, 0, sizeof(offline_link_key_t));
	snprintf(key.glink_name, OFFLINE_GLINK_NAME_LEN, "%d", pdataproc->channel);	
	offline_link_vender_t vender;
	offline_link_vender_fill(pdataproc, &vender);
	if(offline_down_network.downswitch == OFFLINE_SWITCH_OPEN)	
		offline_link_network_write(data, datalen, offline_down_network.downpath, vender.channel, thr_id);
	mini_hash_node_t *node = offline_link_hash_find(&key, pdataproc->type, thr_id);
	if(node)
	{
		pvalue = (offline_link_value_t *)mini_hash_get_node_value(g_offline_link_handle[thr_id], node);	
		assert(pvalue);
		vender.pnetwork = &pvalue->network;	
		if(datalen >= pvalue->network.maxlen && pvalue->network.datalen > 0)
		{
			uint8_t *buff = malloc(datalen + pvalue->network.datalen);
			memcpy(buff, pvalue->network.data, pvalue->network.datalen);
			memcpy(buff + pvalue->network.datalen, data, datalen);

			if(!pvalue->network.decoder)	
			{
				ret = offline_link_network_discern(&pvalue->network, buff,datalen +  pvalue->network.datalen, thr_id);
				if(ret == 0)
				{
					pvalue->network.decoder->decoder_helper(pvalue->network.decoder_ctx, buff, datalen +  pvalue->network.datalen, offline_link_network_lla_callbackp1, &vender, offline_link_network_lla_callbackp2);
				}			
				else
				{
					pvalue->network.datalen = 0;	
				}
			}
			else
			{
				pvalue->network.decoder->decoder_helper(pvalue->network.decoder_ctx, buff, datalen +  pvalue->network.datalen, offline_link_network_lla_callbackp1, &vender, offline_link_network_lla_callbackp2);
				pvalue->network.datalen = 0;
			}
			free(buff);
			buff = NULL;
		}
		else if(datalen >= pvalue->network.maxlen && pvalue->network.datalen <= 0)
		{
			if(!pvalue->network.decoder)
			{
				ret = offline_link_network_discern(&pvalue->network, data, datalen, thr_id);
				if(ret == 0)
				{
					pvalue->network.decoder->decoder_helper(pvalue->network.decoder_ctx, data, datalen, offline_link_network_lla_callbackp1, &vender, offline_link_network_lla_callbackp2);
				}
			}	
			else
			{
				pvalue->network.decoder->decoder_helper(pvalue->network.decoder_ctx, data, datalen, offline_link_network_lla_callbackp1, &vender, offline_link_network_lla_callbackp2);
			}	
		}
		else if((datalen + pvalue->network.datalen) >= pvalue->network.maxlen)
		{
			if(!pvalue->network.decoder)	
			{
				ret = offline_link_network_discern(&pvalue->network, pvalue->network.data, pvalue->network.datalen, thr_id);
				if(ret == 0)
				{
					pvalue->network.decoder->decoder_helper(pvalue->network.decoder_ctx, pvalue->network.data, pvalue->network.datalen, offline_link_network_lla_callbackp1, &vender, offline_link_network_lla_callbackp2);
				}			
			}
			else
			{
				pvalue->network.decoder->decoder_helper(pvalue->network.decoder_ctx, pvalue->network.data, pvalue->network.datalen, offline_link_network_lla_callbackp1, &vender, offline_link_network_lla_callbackp2);
			}
			memcpy(pvalue->network.data, data, datalen);
			pvalue->network.datalen = datalen;
		}
		else
		{
			memcpy(pvalue->network.data + pvalue->network.datalen, data, datalen);		
			pvalue->network.datalen += datalen;
		}
		if(pvalue->network.decoder != NULL && pvalue->network.nodistime > OFFLINE_NODIS_TIME)
		{
			pvalue->network.decoder->free_helper(pvalue->network.decoder_ctx);
			pvalue->network.decoder = NULL;
			pvalue->network.nodistime = 0;
			pvalue->network.decoder_ctx = NULL;
		}
	}
	return ;
}
static void offline_link_network_read(offline_dataproc_info_t *dataproc, int thr_id)
{
	char buff[4024] = {0};
	uint32_t bufflen = 0;
	if(dataproc == NULL || thr_id < 0)
	{
		printf("offline_link_network_read error [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		return ;
	}
	FILE *fp = fopen(dataproc->path, "r");
	if(fp == NULL)
	{
		//错误状态上报		
		return ;
	}
	while((bufflen = fread(buff, 1, sizeof(buff), fp)) > 0)
	{
		offline_gcount.offline_count[dataproc->channel].inbytes += bufflen;
		offline_gcount.offline_count[dataproc->channel].inbytesf += bufflen;
		offline_link_network_proc((uint8_t *)buff, bufflen, dataproc, thr_id);	
	}
	offline_link_network_proc_flush(dataproc, thr_id);	
	fclose(fp);
	return ;
}

static void offline_link_ipcat_push(offline_link_vender_t *pvender, uint8_t *ip, uint32_t iplen, int thr_id)
{

	offline_link_dis_rbq_getbuf(pvender, ip, iplen, datatype_ip, thr_id);
	offline_gcount.offline_count[pvender->channel].outpkts  += 1;
	offline_gcount.offline_count[pvender->channel].outbytes += iplen;

	offline_gcount.offline_count[pvender->channel].outpktsf  += 1;
	offline_gcount.offline_count[pvender->channel].outbytesf += iplen;
	offline_status_ex_t status_ex;
	snprintf(status_ex.clientip, OFFLINE_CLIENTIP_LEN, "%s", pvender->clientip);	
	offline_status_get(&offline_gcount.offline_count[pvender->channel], pvender->channel, pvender->sessid, "IPCAT", pvender->path, NULL, 0, OFFLINE_STATUS_NOTF_MESS_TYPE, &status_ex, thr_id);	
	
	return ;
}

static void offline_link_ipcat_proc(offline_dataproc_info_t *dataproc, int thr_id)
{

	offline_link_key_t key;             
	offline_link_value_t *pvalue = NULL;
	memset(&key, 0, sizeof(offline_link_key_t));
	uint8_t *ip = NULL;
	uint16_t iplen = 0;
	snprintf(key.glink_name, OFFLINE_GLINK_NAME_LEN, "%d", dataproc->channel);
	offline_link_vender_t vender;
	offline_link_vender_fill(dataproc, &vender);
	mini_hash_node_t *node = offline_link_hash_find(&key, dataproc->type, thr_id);
	if(node)
	{
		pvalue = (offline_link_value_t *)mini_hash_get_node_value(g_offline_link_handle[thr_id], node);	
		assert(pvalue);
		vender.pipcat = &pvalue->ipcat;
		if(pvalue->ipcat.flagh == 0)
		{
		   	capture_init(dataproc->path, 0, &pvalue->ipcat.handle);
			if(!pvalue->ipcat.handle)
			{			
				//错误状态信息上报
				return;
			}
			pvalue->ipcat.flagh = 1;
		}
		while(capture_get_pkt(vender.pipcat->handle, &ip, &iplen) == 1)
		{
			offline_gcount.offline_count[vender.channel].inpkts  += 1;
			offline_gcount.offline_count[vender.channel].inbytes += iplen;
	

			offline_gcount.offline_count[vender.channel].inpktsf  += 1;
			offline_gcount.offline_count[vender.channel].inbytesf += iplen;
			offline_link_ipcat_push(&vender, ip, iplen, thr_id);
			//if(........)
			//pvalue->ipcat.flagh = 1;
			//else
			pvalue->ipcat.flagh = 0;	
		}
		if(pvalue->ipcat.flagh == 0)
		{
			capture_destroy(pvalue->ipcat.handle);
			pvalue->ipcat.handle = NULL;
		}
	}
	return;
}

static int offline_link_iphc_check(offline_link_vender_t *pvender, uint8_t *data, uint32_t data_len, int thr_id)
{
	fbl2_iphc_result_t iphc_result;
	uint8_t frame_type;
	uint8_t *frame = NULL;
	uint32_t frame_len = 0;

	offline_gcount.offline_count[pvender->channel].inpkts += 1;
	offline_gcount.offline_count[pvender->channel].inpktsf += 1;
	ll_pkt_info_t info;
	if(data_len > 1)
	{
		if((data[0]&0xf0) == 0x40 && (data[0] & 0x0f) >= 0x05)
		{
			frame_type = FBL2_IPHC_REGULAE_TYPE;
			frame = data;
			frame_len = data_len;
		}
		else
		{
			frame_type = *data;
			frame = data + 1;
			frame_len = data_len - 1;
		}
		fbl2_iphc_decode_frame(g_iphc_ctx, NULL, frame_type, frame, frame_len, g_iphc_frame_buf[thr_id], OFFLINE_FRAME_BUF_SIZE, &iphc_result, thr_id);
		if(iphc_result.is_valid == 1)
		{
			memset(&info, 0, sizeof(ll_pkt_info_t));
			info.data_type = OFFLINE_NORMAL_IP_DATA_TYPE;
			info.mac_start = 0xFFFF;
			info.mac_len   = 0;
			info.ip_start  = 0;
			info.ip_len    = iphc_result.data_len;
			offline_gcount.offline_count[pvender->channel].outpkts += 1;
			offline_gcount.offline_count[pvender->channel].outbytes += iphc_result.data_len;	
			offline_gcount.offline_count[pvender->channel].outpktsf += 1;                    
			offline_gcount.offline_count[pvender->channel].outbytesf += iphc_result.data_len;

			offline_comm_ele_iphc_info_entry(&iphc_result, pvender, thr_id);
			offline_link_dis_rbq_getbuf(pvender, iphc_result.data, iphc_result.data_len, datatype_ip, thr_id);
			offline_status_ex_t status_ex;
			snprintf(status_ex.clientip, OFFLINE_CLIENTIP_LEN, "%s", pvender->clientip);
			offline_status_get(&offline_gcount.offline_count[pvender->channel], pvender->channel, pvender->sessid, "IPHC", pvender->path, NULL, 0, OFFLINE_STATUS_NOTF_MESS_TYPE, &status_ex, thr_id);	
	
			//	connectlog_ele_iphc_info_entry(&iphc_result, normal_vendor, thr_id);

			//	connectlog_ele_union_vendor_rx_info_entry(normal_vendor, (char *)iphc_result.data, iphc_result.data_len, thr_id, UNION_RECV_DATA, datatype_ip);	
		}
		else
		{
			offline_gcount.offline_count[pvender->channel].errpkts  += 1;
			offline_gcount.offline_count[pvender->channel].errbytes += iphc_result.data_len;
			
			offline_gcount.offline_count[pvender->channel].errpktsf  += 1;                   
			offline_gcount.offline_count[pvender->channel].errbytesf += iphc_result.data_len;

//			offline_status_get(&offline_gcount.offline_count[pvender->channel], pvender->channel, "IPHC", pvender->path, "check error!", 0, OFFLINE_STATUS_ERRO_MESS_TYPE, thr_id);	
	
			//错误上报
		}
	}
	else
	{
		//错误上报
	}
	return 0;
}

static int offline_link_iphc_read(offline_link_vender_t *pvender, int thr_id) 
{
	uint8_t   buff[65535] = {0};
	uint32_t  readlen = 0, total_len = 0, offset = 0;
	header_iphc_t *header;
	readlen = fread(buff, 1, sizeof(header_iphc_t), pvender->piphc->fp);
	if(readlen == sizeof(header_iphc_t))
	{
	
		offline_gcount.offline_count[pvender->channel].inbytes += readlen;
		offline_gcount.offline_count[pvender->channel].inbytesf += readlen;
		header = (header_iphc_t *)buff;
		if(header->magic != OFFLINE_MAGIC_IPHC_NUM)
		{
			offline_gcount.offline_count[pvender->channel].errpkts  += 1;
			offline_gcount.offline_count[pvender->channel].errbytes += readlen;
			
			offline_gcount.offline_count[pvender->channel].errpktsf  += 1;      
			offline_gcount.offline_count[pvender->channel].errbytesf += readlen;
			//
			return 0;
		}
		total_len += readlen;
		if(header->rlen < OFFLINE_HEADER_IPHC_LEN)
		{
			assert(1 != 0);	
		}
		else
		{
			offset = OFFLINE_HEADER_IPHC_LEN;
			readlen = fread(buff + offset, 1, header->rlen - OFFLINE_HEADER_IPHC_LEN, pvender->piphc->fp);
			if(readlen == header->rlen - OFFLINE_HEADER_IPHC_LEN)
			{
				total_len += readlen;
				if((buff[offset]&0xf0) == 0x40 && (buff[offset] & 0x0f) >= 0x05)
				{
					offline_gcount.offline_count[pvender->channel].errpkts  += 1;
					offline_gcount.offline_count[pvender->channel].errbytes += readlen;
				
					offline_gcount.offline_count[pvender->channel].errpktsf  += 1;      
					offline_gcount.offline_count[pvender->channel].errbytesf += readlen;
				}
				else
				{	
					offline_link_iphc_check(pvender, (uint8_t *)buff+offset, readlen, thr_id);
				}
			}
		}
	}
	return 0;
}

static void offline_link_iphc_proc(offline_dataproc_info_t *dataproc, int thr_id)
{
	offline_link_key_t key;             
	offline_link_value_t *pvalue = NULL;
	memset(&key, 0, sizeof(offline_link_key_t));
	
	snprintf(key.glink_name, OFFLINE_GLINK_NAME_LEN, "%d", dataproc->channel);
	offline_link_vender_t vender;
	offline_link_vender_fill(dataproc, &vender);
	mini_hash_node_t *node = offline_link_hash_find(&key, dataproc->type, thr_id);
	if(node)
	{
		pvalue = (offline_link_value_t *)mini_hash_get_node_value(g_offline_link_handle[thr_id], node);	
		assert(pvalue);
		vender.piphc = &pvalue->iphc;
		if(pvalue->iphc.flagf == 0)
		{
			pvalue->iphc.fp = fopen(dataproc->path, "r");
			if(!pvalue->iphc.fp)
			{			
				//错误状态信息上报
				return;
			}
			pvalue->iphc.flagf = 1;
		}
		while(!feof(pvalue->iphc.fp))
		{
			offline_link_iphc_read(&vender, thr_id);	
			pvalue->iphc.flagf = 0;	
		}
		if(pvalue->iphc.flagf == 0)
		{
			fclose(pvalue->iphc.fp);
			pvalue->iphc.fp = NULL;
		}
	}
	return;
}

static void offline_link_diy_proc(offline_dataproc_info_t *dataproc, int thr_id)
{
	offline_link_vender_t vender;
	offline_link_vender_fill(dataproc, &vender);
	void *session = NULL;
	void *user_data[OFFLINE_MAX_CHANNEL_NUM]; 

	if(offline_diy.canflag != OFFLINE_SWITCH_OPEN)
	{
		printf("offline_link_diy_proc error [%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		printf("diy_helper is NULL[%s-%s-%d]\n", __FILE__, __func__, __LINE__);
		return;
	}
	offline_diy.diy_gain(session, dataproc->path, dataproc->type, (void *)&vender, thr_id, &user_data[dataproc->channel]);	
		
	return;
}

static int onlineld_fc_entry(void *session, online_fc_t *fc, uint8_t *data, uint32_t datalen, uint32_t channel, int thr_id, void **user_data)
{
	if(fc == NULL || data == NULL || datalen <= 0 || thr_id < 0 || thr_id > OFFLINE_MAX_THR_NUM)
		return -1;
	uint32_t ckchannel = channel;
	if(channel > OFFLINE_MAX_CHANNEL_NUM)
		ckchannel = OFFLINE_MAX_CHANNEL_NUM - 1;
	
	offline_gcount.offline_count[ckchannel].countflag  = 1;
	offline_gcount.offline_count[ckchannel].thr_id     = thr_id;
	offline_gcount.offline_count[ckchannel].inpkts   += 1;
	offline_gcount.offline_count[ckchannel].inpktsf  += 1;

	offline_gcount.offline_count[ckchannel].inbytes   += datalen;
	offline_gcount.offline_count[ckchannel].inbytesf  += datalen;
	offline_dataproc_info_t dataproc;
	memset(&dataproc, 0, sizeof(offline_dataproc_info_t));
	snprintf(dataproc.sessid, OFFLINE_SESSID_LEN, "%s", fc->sessId);
	dataproc.sessid_len = fc->sessIdLen;
	dataproc.channel    = ckchannel;
	dataproc.thr_id     = thr_id;
	dataproc.offline_carry.extra.hostIp               = fc->extra.hostIp;
	dataproc.offline_carry.extra.dataType             = fc->extra.dataType;
	dataproc.offline_carry.capTimeStamp               = fc->capTimeStamp;
	dataproc.offline_carry.analysisTimeStamp          = fc->analysisTimeStamp;
	dataproc.offline_carry.userinfo     = fc->userInfo;
	dataproc.offline_carry.userinfolen  = fc->userInfoLen;
	dataproc.offline_carry.userinfotype = fc->userInfoType;
	dataproc.type                       = OFFLINE_LINK_NETWORK_TYPE; 

	offline_link_network_proc(data, datalen, &dataproc, thr_id);
	
	return 0;
}

static int onlinefh_fd_entry(void *session, online_fd_t *fd, uint8_t *data, uint32_t datalen, uint16_t pro_type, uint32_t channel, int thr_id, void **user_data)
{
	if(fd == NULL || data == NULL || datalen <= 0 || thr_id < 0 || thr_id > OFFLINE_MAX_THR_NUM)
		return 0;
	uint32_t ckchannel = channel;
	if(channel > OFFLINE_MAX_CHANNEL_NUM)
		ckchannel = OFFLINE_MAX_CHANNEL_NUM - 1;

	offline_gcount.offline_count[ckchannel].countflag  = 1;
	offline_gcount.offline_count[ckchannel].thr_id     = thr_id;
	
	offline_gcount.offline_count[ckchannel].inpkts   += 1;
	offline_gcount.offline_count[ckchannel].inbytes  += datalen;

	offline_gcount.offline_count[ckchannel].inpktsf   += 1;
	offline_gcount.offline_count[ckchannel].inbytesf  += datalen;
	offline_link_vender_t vender;
	memset(&vender, 0, sizeof(offline_link_vender_t));
	vender.thr_id             = thr_id;
	vender.channel            = channel;
	vender.cap_timestamp      = fd->capTimeStamp;
	vender.analysis_timestamp = fd->analysisTimeStamp;	
	snprintf(vender.sessid, OFFLINE_SESSID_LEN, "%s", fd->sessId);
	vender.sessid_len         = fd->sessIdLen;
	vender.userinfo           = fd->userInfo;
	vender.userinfolen        = fd->userInfoLen;
	vender.userinfotype       = fd->userInfoType;
	offline_comm_ele_fd_entry(fd, data, datalen, &vender, pro_type, thr_id);

	offline_gcount.offline_count[ckchannel].outpkts   += 1;
	offline_gcount.offline_count[ckchannel].outbytes  += datalen; 

	offline_gcount.offline_count[ckchannel].outpktsf   += 1;    
	offline_gcount.offline_count[ckchannel].outbytesf  += datalen;
	
	offline_status_get(&offline_gcount.offline_count[ckchannel], ckchannel, vender.sessid, "ONLINE", NULL, NULL, 0, OFFLINE_STATUS_NOTF_MESS_TYPE, NULL, thr_id);	
	
	return 0;
}
static int onlinepv_pv_entry(void *session, online_pv_t *pv, uint8_t *data, uint32_t datalen, uint32_t channel, int thr_id, void **user_data)
{
	if(pv == NULL || data == NULL || datalen <= 0 || thr_id < 0 || thr_id > OFFLINE_MAX_THR_NUM)
		return 0;
	uint32_t ckchannel = channel;
	if(channel > OFFLINE_MAX_CHANNEL_NUM)
		ckchannel = OFFLINE_MAX_CHANNEL_NUM - 1;

	offline_gcount.offline_count[ckchannel].countflag  = 1;
	offline_gcount.offline_count[ckchannel].thr_id     = thr_id;
	
	offline_gcount.offline_count[ckchannel].inpkts   += 1;
	offline_gcount.offline_count[ckchannel].inbytes  += datalen;

	offline_gcount.offline_count[ckchannel].inpktsf   += 1;
	offline_gcount.offline_count[ckchannel].inbytesf  += datalen;
	
	offline_comm_ele_pv_entry(pv, data, datalen, thr_id);

	offline_gcount.offline_count[ckchannel].outpkts   += 1;
	offline_gcount.offline_count[ckchannel].outbytes  += datalen; 

	offline_gcount.offline_count[ckchannel].outpktsf   += 1;    
	offline_gcount.offline_count[ckchannel].outbytesf  += datalen;
	
//	offline_status_get(&offline_gcount.offline_count[ckchannel], ckchannel, vender.sessid, "ONLINE", NULL, NULL, 0, OFFLINE_STATUS_NOTF_MESS_TYPE, NULL, thr_id);	
	
	return 0;
}
int *online_mddw_start(online_helper_t *online_helper)
{
	online_helper->onlineip_entry = onlineip_fb_entry;
	online_helper->onlineld_entry = onlineld_fc_entry;
	online_helper->onlinefh_entry = onlinefh_fd_entry;
	online_helper->onlinepv_entry = onlinepv_pv_entry;
	return 0;
}

void online_start(online_dyn_load_t *dyn_load)
{
	online_helper_t online_helper;
	memset(&online_helper, 0, sizeof(online_helper_t));	
	online_helper.onlineip_entry = onlineip_fb_entry;
	online_helper.onlineld_entry = onlineld_fc_entry;
	online_helper.onlinefh_entry = onlinefh_fd_entry;
	online_helper.onlinepv_entry = onlinepv_pv_entry;
	dyn_load->online_register(&online_helper);
	dyn_load->online_init(dyn_load->dyn_channel, dyn_load->thr_id);
	return;
}

void offline_link_proc(offline_dataproc_extra_t *pextra, offline_dataproc_info_t *dataproc, int thr_id)
{
	
	if(dataproc->channel >= OFFLINE_MAX_CHANNEL_NUM)
		dataproc->channel = OFFLINE_MAX_CHANNEL_NUM - 1;
	snprintf(offline_gcount.offline_count[dataproc->channel].nowfilename, OFFLINE_MAX_NAME_LEN, "%s", dataproc->path);
	offline_gcount.offline_count[dataproc->channel].sjiffiesf = jiffies;
	offline_gcount.offline_count[dataproc->channel].countflag = 1;
	offline_gcount.offline_count[dataproc->channel].thr_id    = thr_id;
	offline_gcount.offline_count[dataproc->channel].infiles   += 1;
	
	offline_status_ex_t status_ex;
	snprintf(status_ex.clientip, OFFLINE_CLIENTIP_LEN, "%s", dataproc->clientip);	
	switch(dataproc->type)
	{
		case OFFLINE_LINK_PCAP_TYPE:
			offline_status_get(&offline_gcount.offline_count[dataproc->channel], dataproc->channel, dataproc->sessid, "PCAP", dataproc->path, NULL, OFFLINE_PROC_START_TYPE, OFFLINE_STATUS_PROC_PROG_TYPE, &status_ex, thr_id);	

			offline_link_pcap_proc(dataproc, thr_id);

			offline_status_get(&offline_gcount.offline_count[dataproc->channel], dataproc->channel, dataproc->sessid, "PCAP", dataproc->path, NULL, OFFLINE_PROC_END_TYPE, OFFLINE_STATUS_PROC_PROG_TYPE, &status_ex, thr_id);	
	
			break;
		case OFFLINE_LINK_NETWORK_TYPE:
			offline_status_get(&offline_gcount.offline_count[dataproc->channel], dataproc->channel, dataproc->sessid, "NETWORK", dataproc->path, NULL, OFFLINE_PROC_START_TYPE, OFFLINE_STATUS_PROC_PROG_TYPE, &status_ex, thr_id);	
	
			offline_link_network_read(dataproc, thr_id);

			offline_status_get(&offline_gcount.offline_count[dataproc->channel], dataproc->channel, dataproc->sessid, "NETWORK", dataproc->path, NULL, OFFLINE_PROC_END_TYPE, OFFLINE_STATUS_PROC_PROG_TYPE, &status_ex, thr_id);		
			break;
		case OFFLINE_LINK_IPCAT_TYPE:
			offline_status_get(&offline_gcount.offline_count[dataproc->channel], dataproc->channel, dataproc->sessid, "IPCAT", dataproc->path, NULL, OFFLINE_PROC_START_TYPE, OFFLINE_STATUS_PROC_PROG_TYPE, &status_ex, thr_id);	
			
			offline_link_ipcat_proc(dataproc, thr_id);		
			offline_status_get(&offline_gcount.offline_count[dataproc->channel], dataproc->channel, dataproc->sessid, "IPCAT", dataproc->path, NULL, OFFLINE_PROC_END_TYPE, OFFLINE_STATUS_PROC_PROG_TYPE, &status_ex, thr_id);	
	
			break;
		case OFFLINE_LINK_IPHC_TYPE:
			offline_status_get(&offline_gcount.offline_count[dataproc->channel], dataproc->channel, dataproc->sessid, "IPHC", dataproc->path, NULL, OFFLINE_PROC_START_TYPE, OFFLINE_STATUS_PROC_PROG_TYPE, &status_ex, thr_id);

			offline_link_iphc_proc(dataproc, thr_id);
			
			offline_status_get(&offline_gcount.offline_count[dataproc->channel], dataproc->channel, dataproc->sessid, "IPHC", dataproc->path, NULL, OFFLINE_PROC_END_TYPE, OFFLINE_STATUS_PROC_PROG_TYPE, &status_ex, thr_id);
			break;
		default:
			
			offline_status_get(&offline_gcount.offline_count[dataproc->channel], dataproc->channel, dataproc->sessid, "DIY", dataproc->path, NULL, OFFLINE_PROC_START_TYPE, OFFLINE_STATUS_PROC_PROG_TYPE, &status_ex, thr_id);

			offline_link_diy_proc(dataproc, thr_id);
			
			offline_status_get(&offline_gcount.offline_count[dataproc->channel], dataproc->channel, dataproc->sessid, "DIY", dataproc->path, NULL, OFFLINE_PROC_END_TYPE, OFFLINE_STATUS_PROC_PROG_TYPE, &status_ex, thr_id);
			break;
	}
	memset(offline_gcount.offline_count[dataproc->channel].nowfilename, 0, OFFLINE_MAX_NAME_LEN);

	offline_gcount.offline_count[dataproc->channel].inpktsf = 0;
	offline_gcount.offline_count[dataproc->channel].outpktsf = 0;
	offline_gcount.offline_count[dataproc->channel].errpktsf = 0;
	offline_gcount.offline_count[dataproc->channel].inbytesf = 0;
	offline_gcount.offline_count[dataproc->channel].outbytesf = 0;
	offline_gcount.offline_count[dataproc->channel].errbytesf = 0;
	offline_gcount.offline_count[dataproc->channel].djiffiesf = jiffies - offline_gcount.offline_count[dataproc->channel].ljiffies;
	return;
}


