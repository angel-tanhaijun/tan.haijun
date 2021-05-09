/*************************************************************************
	> File Name: offline_comm.h
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月03日 星期三 15时41分04秒
 ************************************************************************/
#ifndef __OFFLINE_COMM_H__
#define __OFFLINE_COMM_H__

#include "offline.h"
#define OFFLINE_MAX_NUM(x,y)  (x>y?x:y)    
#define OFFLINE_COMM_RETAIN_LEN                       (200)
#define OFFLINE_COMM_ELE_LL_RETAIN_LEN                (8*5)
#define OFFLINE_COMM_MSG_HEAD_LEN                                sizeof(msg_header_t)
#define OFFLINE_COMM_BODY_HEAD_LEN                               sizeof(body_header_t)



#define offline_my_ntohl ntohl
#define offline_my_ntohs ntohs  
#define offline_my_htonl htonl
#define offline_my_htons htons
#define offline_my_hton64 ntoh64


#pragma pack (1)

typedef struct{
	uint32_t CpuOccupy;
	uint32_t CpuId;
}cpu_id_grep_t;        


typedef struct{
	uint32_t      send_qlen;
	uint32_t      send_qsize;
	uint32_t      write_thr_num;
	uint32_t      send_thr_num;
	group_param_t  group_param;
	uint8_t       cpumap[OFFLINE_MAX_THR_NUM];
	cpu_id_grep_t  CIG[OFFLINE_MAX_THR_NUM];
	uint32_t      block_mod;
	uint32_t      conn_debug_info;
}offline_comm_send_rbq_t;

typedef struct{
	offline_comm_send_rbq_t m2_send_rbq;
	offline_comm_send_rbq_t link_send_rbq;
	offline_comm_send_rbq_t pv_send_rbq;
	offline_comm_send_rbq_t dis_send_rbq;
}offline_comm_init_t;

typedef struct __msg_header_t {
	uint32_t      magic_num;
	uint16_t      checksum;
	uint16_t      msg_type;
	uint32_t      cont_len;
}msg_header_t; /*sizeof = 20B */

typedef struct 
{        
	uint32_t type;
	uint32_t len;
}body_header_t;   
typedef struct __offline_connect_log_info_t {
	uint64_t   conn_id;     //全局连接ID，同一个连接里面的不同会话使用相同的连接ID
	uint32_t   src_ip;      //客户端IP，tcp协议为发起syn一方;udp协议为首包的源ip，网络序
	uint32_t   dst_ip;      //服务端ip，tcp协议为发起syn_ack一方;udp为首包的目的ip，网络序

	uint16_t   src_port;    //若既非tcp，又非udp，该数值取0；
	uint16_t   dst_port;    //若既非tcp，又非udp，该数值取0；
	uint8_t    log_type;    //当前日志类型
	uint8_t    protocol;    //ip承载的协议
	uint8_t    app_class;
	uint16_t   app_id;      //应用程序类型ID
	uint8_t    dir_status;  //0x01:单向 0x02:单向 0x03:双向

//	uint32_t   pro_type;  //协议类型
//	uint8_t    flags;     //标志位
	uint8_t    padl[3];   //填充
	uint32_t   total_cs_pkts;   //从连接建立到现在客户端向服务端累计传输的包数；
	uint32_t   total_sc_pkts;   //从连接建立到现在服务端向客户端累计传输的包数；
	uint64_t   total_cs_bytes;  //从连接建立到现在客户端向服务端累计传输的字节数；
	uint64_t   total_sc_bytes;  //从连接建立到现在服务端向客户端累计传输的字节数；

	uint32_t   cs_pkts;         //当前会话客户端向服务端传输的包数；
	uint32_t   sc_pkts;         //当前会话服务端向客户端传输的包数；
	uint64_t   cs_bytes;        //当前会话客户端向服务端传输的字节数；
	uint64_t   sc_bytes;        //当前会话服务端向客户端传输的字节数；

	uint64_t   log_gen_time;    //该条日志的生成时间.(单位:秒)
	uint64_t   conn_start_time; //连接开始时间.(单位:毫秒)
	uint64_t   conn_time;       //连接持续时间.(单位:毫秒)

	uint32_t   src_ip_desc_id;  //描述源IP的一个所属地(索引ID)
	uint32_t   dst_ip_desc_id;  //描述目的IP的一个所属地(索引ID)
	uint32_t   src_ip_as_id;    //描述源IP的一个所属AS(索引ID)
	uint32_t   dst_ip_as_id;    //描述目的IP的一个所属AS(索引ID)
}offline_connect_log_info_t;

typedef enum
{    
	/*
	 *      *      * 只有分流信息
	 *           *           */ 
	ONLY_FNG_TYPE = 0,
	/*
	 *      *      * NCA销毁时触发的未关联上流信息的通联
	 *           *           */
	FINAL_SELF_TYPE,
	/*
	 *      *      * NCA销毁时触发的关联上流信息的通联
	 *           *           */
	SELF_AND_FNG_TYPE,
	/*
	 *      *      * NCA发出的非销毁通联 
	 *           *           */
	ONLY_SELF_TYPE,                               
	FLOOD_DATA_TYPE = 10,
}connlog_log_type_t;




#pragma pack (0)
void offline_link_tcpsend_init(offline_comm_init_t *comm_init);

void offline_comm_ele_ll_info_entry(uint32_t type, uint8_t *tags, offline_link_vender_t *pvender, int thr_id);

void offline_link_dis_rbq_getbuf(offline_link_vender_t *vender, uint8_t *ip, uint32_t iplen, uint32_t type, int thr_id);
rbq_buf_t *offline_comm_begin_store(void *rbq_handle, const int thr_id, const uint64_t total_len, uint32_t *pmsg_cont_len, body_header_t **pbody_header);

void offline_comm_begin_add_big_record(rbq_buf_t *rbq_buf, const int thr_id, const uint32_t data_type, uint32_t *pmsg_cont_len, body_header_t **pbody_header);

void offline_comm_add_one_sub_record(rbq_buf_t *rbq_buf, const int thr_id, const uint32_t data_type, const uint8_t *data, const uint32_t data_len);

void offline_comm_end_add_big_record(rbq_buf_t *rbq_buf, const int thr_id,  const uint32_t msg_cont_len, body_header_t *body_header);

void offline_comm_end_store(void *rbq_handle, rbq_buf_t *rbq_buf, int thr_id, uint32_t msg_cont_len, body_header_t *body_header);

void offline_comm_read_link(char *conn_filename, offline_comm_send_rbq_t *send_rbq);

void ip_data_recv_info_entry(void *recv_handle, void *ele, int thr_id);

void offline_comm_ele_iphc_info_entry(fbl2_iphc_result_t *iphc, offline_link_vender_t *pvender, int thr_id);

void offline_comm_ele_fd_entry(online_fd_t *fd, uint8_t *data, uint32_t datalen, offline_link_vender_t *pvender, uint16_t pro_type, int thr_id);

uint32_t offline_comm_len_set(char *buff, uint32_t bufflen);
int offline_get_file_size(char *filepath);
void offline_link_dis_init(offline_comm_send_rbq_t *send_rbq);
void offline_comm_ele_pv_entry(online_pv_t *pv, uint8_t *data, uint32_t datalen, int thr_id);

#endif

