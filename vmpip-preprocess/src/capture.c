#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "capture.h"
#include "zlog.h"

#define CACHE_SIZE (2*1024*1024)

#define Magic_Vaule		(0x00000601)
#define PKMSG_MAGIC		(0xff5fcf04)
//#define PKMSG_MAGIC		(0x04cf5fff)
#define _xj_ 			(1)

typedef enum
{
	CAP_RANDOM = 1,			//硬匹配 获取ip数据包 模式
	CAP_HEADER				//通过校验特定的数据包头结构 获取数据包 模式
}pcap_type_t;

#pragma pack(1)

typedef struct
{
    FILE *fp;
    uint8_t cache[CACHE_SIZE];
    int offset;
    int count;
    int eof;
	uint64_t *option_num_bad;
    
    uint8_t decode_switch; 
    uint8_t decode_buf[CACHE_SIZE];
    uint8_t flag_7d;
}capture_t;
 
typedef struct
{
	uint32_t magic;
	uint16_t total_len;
	uint16_t header_len;
	uint16_t seqno;
	uint32_t channel_num;
	uint32_t subchannel_num;
	uint8_t  payload_proto;
	uint8_t  freq[6];
	uint8_t  line[10];
	uint8_t  position[6];
	//uint8_t  line_num[20];	//通信格式：大端
	uint16_t mac_proto;		//链路协议号
	uint8_t  crc;			//1:通过校验 0：不通过校验
	uint64_t cap_time;
	uint64_t  start_time;
	uint8_t  end_jiff[8];
	uint8_t  type;
}pkmsg_head_t;

#pragma pack()

#define START_MAGIC                 (0x1122334455667788)
#define END_MAGIC                   (0x8877665544332211)

static uint64_t g_option_err = 0;
static zlog_category_t * mod_capture_proc_20160906 = NULL;
static capture_helper_t g_capture_helper[SNIFFER_HELPER_GRP_NUM];
static int g_helper_grp_num = 0;

static int g_decode_switch = 0;
static int g_decode_speed  = 0;

static void do_pcap_data(void *handle, void *data, int data_len)
{
	//printf("%s(%d) start!\n", __func__, __LINE__);
	int i = 0;
	
	if(handle == NULL || data == NULL)
		goto exit;

	for(i = 0; i < g_helper_grp_num; i++)
	{
		if(g_capture_helper[i].pcap_data == NULL)
			goto exit;
			
		g_capture_helper[i].pcap_data(handle, (char *)data, data_len);
	}
	
exit:
	return ;
}

int capture_helper_register(capture_helper_t *capture_helper)
{
	int iret = capture_ret_ok;
	
	if(capture_helper == NULL)
	{
		iret = capture_ret_error;
		goto exit;
	}

	if(g_helper_grp_num >= SNIFFER_HELPER_GRP_NUM)
	{
		iret = capture_ret_too_many_helper;
		goto exit;
	}

	memcpy(g_capture_helper + g_helper_grp_num, capture_helper, sizeof(capture_helper_t));
	g_helper_grp_num++;

exit:
	return iret;
}

/* this function generates header checksums */
static unsigned short csum (unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

void *capture_init(char *filename, uint8_t decode_switch, void **dst)
{
    *dst = (capture_t *)malloc(sizeof(capture_t));
    capture_t *handle = (capture_t *)*dst;
    if(handle == NULL)
    {
		zlog_debug(mod_capture_proc_20160906, "%s(%d) capture_init handle malloc fail!\n", __func__, __LINE__);
        return NULL;
    }
    memset(handle, 0, sizeof(capture_t));

    handle->fp = fopen(filename, "rb");
    if(handle->fp == NULL)
    {
		zlog_debug(mod_capture_proc_20160906, "%s(%d) fopen %s fail!\n", __func__, __LINE__, filename);
        free(handle);
        return NULL;
    }
    handle->decode_switch = decode_switch;
    
    return (void *)handle;
}
int capture_destroy(void *handle)
{
    capture_t *capture = (capture_t *)handle;

    if(capture != NULL)
    {
        if(capture->fp != NULL)
        {
            fclose(capture->fp);
        }
        free(capture);
    }
    return CAPTURE_OK;
}
/**
 * 解码函数
 *
 */
static int decode_fx(void *handle, int remain_len)
{
    capture_t *capture = (capture_t *)handle;
    uint32_t i = 0;
    uint32_t dst_len = 0;
    uint8_t *src     = capture->cache+remain_len;
    uint32_t src_len = capture->count-remain_len;
    uint8_t *dst         = capture->decode_buf;
    uint32_t max_dst_len = CACHE_SIZE;

    for(i=0; i<src_len; i++)
    {
        if(capture->flag_7d == 1)
        {
            if(src[i] == 0x5e)
            {
                dst[dst_len++] = 0x7e; 
            }
            else if(src[i] == 0x5d)
            {
                dst[dst_len++] = 0x7d;  
            }
            else if((src[i] < 0x40) && (src[i] >= 0x20))
            {
                dst[dst_len++] = src[i]-0x20;
            }
            else
            {
                zlog_debug(mod_capture_proc_20160906,"data is bad, data[i]=0x%x\n", src[i]);
            }
            capture->flag_7d = 0;
            continue;
            //第一个数据需要转义处理 
        }
        if(src[i] == 0x7d)
        {
            if(i+2 > src_len)
            {
                capture->flag_7d = 1;
                break;
                //后面没有数据需要缓存
            }
            else
            {
                //特殊处理
                if(src[i+1] == 0x5e)
                {
                    dst[dst_len++] = 0x7e; 
                }
                else if(src[i+1] == 0x5d)
                {
                    dst[dst_len++] = 0x7d;  
                }
                else if(src[i+1] < 0x40)
                {
                    dst[dst_len++] = src[i+1]-0x20;
                }
                else
                {
                    zlog_debug(mod_capture_proc_20160906,"data is bad, data[i]=0x%x\n", src[i+1]);
                }
                i++;
            }
        }
        else
        {
            dst[dst_len++] = src[i];   
        }
        if(dst_len >= max_dst_len)
        {
            zlog_debug(mod_capture_proc_20160906,"maybe error, dst_len(%u) >= max_dst_len(%u)\n", dst_len, max_dst_len);
            break;
        }
    }  

    memcpy(capture->cache+remain_len, dst, dst_len);
    capture->count  = dst_len+remain_len;

    return CAPTURE_OK;
}

/*
 * 检查数据长度是否满足要求
 */
static int capture_ensure_data(void *handle, int len)
{
    capture_t *capture = (capture_t *)handle;
    int ret, data_len, buf_len;

    assert(capture != NULL);
    data_len = capture->count - capture->offset;
    if(data_len < len)
    {
        if(capture->eof == 1)
        {
            if(data_len == 0)
                return CAPTURE_EOF;
            else
                return CAPTURE_DATA_SHORT;
        }

        memmove(capture->cache, capture->cache+capture->offset, data_len);
        capture->offset = 0;
        capture->count = data_len;
        
        buf_len = CACHE_SIZE - data_len;
        ret = fread(capture->cache + capture->count, 1, buf_len, capture->fp);
        if(ret != buf_len)
        {
            if(feof(capture->fp))
            {
                capture->eof = 1;
            }
            else
            {
				zlog_debug(mod_capture_proc_20160906, "%s(%d) capture_get_pkt read error!\n", __func__, __LINE__);
                return CAPTURE_FAIL;
            }
        }
        capture->count += ret;
        if(capture->decode_switch == 1)
        {
            decode_fx(handle, data_len);
        }
#if 0
        FILE *fp = NULL;
        fp = fopen("1.txt", "ab+");
        fwrite(capture->cache + data_len, 1, capture->count-data_len, fp);
        fclose(fp); 
#endif
    }
    data_len = capture->count - capture->offset;
    if(data_len < len)
    {
        return CAPTURE_DATA_SHORT;
    }

    return CAPTURE_OK;
}

int capture_get_pkt(void *handle, uint8_t **ip, uint16_t *ip_len)
{
    capture_t *capture = (capture_t *)handle;
    int ret, iplen, hlen;
    struct iphdr *iph;

    assert(capture != NULL);

    while(1)
    {
        /*
         * 不够IP头长度, 则认为CAPTURE_EOF
         */
        ret = capture_ensure_data(handle, sizeof(struct iphdr));
        if(ret != CAPTURE_OK)
        {
            return CAPTURE_EOF; 
        }

        /*
           剩余的数据肯定大于等于一个IP头
           */
        iph = (struct iphdr *)(capture->cache + capture->offset);
        if(iph->version != 4)
        {
            capture->offset ++;
            continue;
        }
        hlen = iph->ihl * 4;
        if(hlen < 20)
        {
            capture->offset ++;
            continue;
        }
        iplen = ntohs(iph->tot_len);
        if(iplen < hlen)
        {
            capture->offset ++;
            continue;
        }
		#if 0
		if(iph->ihl > 5 && ip_options_compile((uint8_t *)iph))
		{
			(*capture->option_num_bad)++;
			g_option_err++;
            capture->offset ++;
            continue;
		}
		#endif
        ret = capture_ensure_data(handle, iplen);
        if(ret != CAPTURE_OK)
        {
            /*
             * 数据不足, 我们认为定位IP包失败
             */
            if(ret == CAPTURE_DATA_SHORT)
            {
                capture->offset ++;
                continue;
            }
            if(ret != CAPTURE_EOF)
            {
               ret = CAPTURE_FAIL; 
            }
            return ret; 
        }

        iph = (struct iphdr *)(capture->cache + capture->offset);
        hlen = iph->ihl * 4;
        if(csum((uint16_t *)iph, hlen>>1)!=0)
        {
            capture->offset ++;
            continue;
        }
        iplen = ntohs(iph->tot_len);

        *ip = (uint8_t *)iph;
        *ip_len = iplen;
        capture->offset += iplen;
        break;
    }

    return CAPTURE_OK;
}

int capture_msgdata_is_enough(void *handle, int len)
{
    capture_t *capture = (capture_t *)handle;
	int enough_flag = 0;
	int data_len = 0;
	pkmsg_head_t *pkmsg_head = NULL;

    assert(capture != NULL);

    data_len = capture->count - capture->offset;
	if(data_len > 0 && data_len > len)
	{
		pkmsg_head = (pkmsg_head_t *)(capture->cache + capture->offset);

		if(data_len >= pkmsg_head->total_len)
			enough_flag = 1;
	}

	return enough_flag;
}

/*
 * 检查数据长度是否满足要求
 */
static int capture_ensure_msgdata(void *handle, int len)
{
    capture_t *capture = (capture_t *)handle;
	int iret = -1;
	int data_len = 0;
	int buf_len = 0;

    assert(capture != NULL);

	//判断cache中 数据是否足够
	iret = capture_msgdata_is_enough(handle, sizeof(pkmsg_head_t));
	if(iret == 1)
		return CAPTURE_OK;
	
	//判断文件是否结束
	if(capture->eof == 1)
	{
		if(data_len == 0)
			return CAPTURE_EOF;
		else
			return CAPTURE_DATA_SHORT;
	}

	//去掉无用的数据
    data_len = capture->count - capture->offset;
	memmove(capture->cache, capture->cache + capture->offset, data_len);
	capture->offset = 0;
	capture->count = data_len;

	//读取文件中的数据到cache中
	buf_len = CACHE_SIZE - data_len;
	iret = fread(capture->cache + capture->count, 1, buf_len, capture->fp);
	if(iret != buf_len)
	{
		if(feof(capture->fp))
		{
			capture->eof = 1;
		}
		else
		{
			zlog_debug(mod_capture_proc_20160906, "fread file error!\n");
			return CAPTURE_FAIL;
		}
	}
	capture->count += iret;

	//再次判断cache中 数据是否足够
	iret = capture_msgdata_is_enough(handle, sizeof(pkmsg_head_t));
	if(iret != 1)
	{
		zlog_debug(mod_capture_proc_20160906, "data is too short!\n");
        return CAPTURE_DATA_SHORT;
	}

    return CAPTURE_OK;
}

void capture_pack_send_data(void *handle, uint8_t *pkt, uint32_t pkt_len, int capture_moudle, note_vendor_t *vendor)
{
	int len = 0;
	uint8_t send_buf[65535] = {0};
	pkmsg_head_t pkmsg_head;

	if( handle == NULL || pkt == NULL || pkt_len <= 0 || (capture_moudle < CAP_RANDOM || capture_moudle > CAP_HEADER) )
		goto leave;

	if(sizeof(pkmsg_head_t) + pkt_len > 65535)
		goto leave;
	
	if( capture_moudle == CAP_RANDOM )
	{
		memset(&pkmsg_head, 0, sizeof(pkmsg_head_t));
		
		memcpy(pkmsg_head.line, vendor->line, 10);
		memcpy(pkmsg_head.freq, vendor->Freq, 6); 
		memcpy(pkmsg_head.position, vendor->position, 6);
		pkmsg_head.start_time = vendor->jiffies;
		pkmsg_head.subchannel_num = vendor->subchannel;

		pkmsg_head.magic	= PKMSG_MAGIC;
		pkmsg_head.header_len	= sizeof(pkmsg_head_t);
		pkmsg_head.total_len	= sizeof(pkmsg_head_t) + pkt_len;
		//memcpy(pkmsg_head.line_num, ((tcpclient_t *)handle)->line_num, sizeof(pkmsg_head.line_num));

		memcpy(send_buf + len, &pkmsg_head, sizeof(pkmsg_head_t));
		len += sizeof(pkmsg_head_t);
		memcpy(send_buf + len, pkt, pkt_len);
		len += pkt_len;
	}
	else if( capture_moudle == CAP_HEADER )
	{

		memcpy(send_buf + len, pkt, pkt_len);
		len += pkt_len;
	}

	do_pcap_data(handle, send_buf, len);

leave:
	return ;
}

int capture_get_msg(void *handle, uint8_t **msg, uint16_t *msg_len)
{
    capture_t *capture = (capture_t *)handle;
    int iret = 0;
	pkmsg_head_t *pkmsg_head = NULL;

    assert(capture != NULL);

	//如果cache中数据，不能满足一个消息的长度, 则认为CAPTURE_EOF
	iret = capture_ensure_msgdata(handle, sizeof(pkmsg_head_t));
	if(iret != CAPTURE_OK)
	{
		return CAPTURE_EOF; 
	}

	//校验包同步
	pkmsg_head = (pkmsg_head_t *)(capture->cache + capture->offset);
	if(pkmsg_head->magic != PKMSG_MAGIC)
	{
		zlog_debug(mod_capture_proc_20160906, "包同步校验错误！\n");
		return CAPTURE_FAIL; 
	}

	*msg = (uint8_t *)pkmsg_head;
	*msg_len = pkmsg_head->total_len;
	capture->offset += pkmsg_head->total_len;

    return CAPTURE_OK;
}


//返回1是成功的，0是失败
int get_vendor_name(char *path_name, char *buffer, uint32_t buffer_size)
{
	uint32_t length = strlen(path_name);
	int i = 0;
	uint32_t offset = 0;
	for(i = 0; i < length; i++)
	{
		if(path_name[i] == '.')
		{
			offset = i;			
		}
	}
	if(offset == 0 || offset == length)
	{
		return 0;
	}
	if(length + 5 > buffer_size)
	{
		return 0;
	}
	memcpy(buffer, path_name, offset);
	memcpy(buffer+offset, ".xml", 4);
	buffer[offset + 4] = '\0';
	return 1;
}




static void capture_proc_log_init(void)
{
	mod_capture_proc_20160906 = zlog_get_category("mod_file_proc_20160906");
	if(!mod_capture_proc_20160906)
	{
		printf("%s(%d) zlog get mod_capture_proc_20160906 fail\n", __func__, __LINE__);
		exit(-1);
	}

	return ;	
}

void capture_proc_init(void)
{
	capture_proc_log_init();

	return ;	
}

