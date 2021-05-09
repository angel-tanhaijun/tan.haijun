/*************************************************************************
	> File Name: dyn.h
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月20日 星期六 18时33分17秒
 ************************************************************************/

#pragma pack (1)


typedef struct{
	uint32_t hostIp; //主机地址
	uint32_t dataType; //数据类型 0x01：ip数据；0x08:以太数据；其他：链路数据
}online_extra_t;

typedef struct{
	char      sessId[215];
	int       sessIdLen;
	uint64_t  capTimeStamp;
	uint64_t  analysisTimeStamp;
	uint32_t  IPOffset;
	uint8_t   *userInfo;
	uint32_t  userInfoLen;
	uint32_t  userInfoType;  //10005001->userInfoType,为userInfo的类型指定项,0x10005094为用户标签可用最小值
	online_extra_t extra;
}online_fb_t;

typedef struct{
	char      sessId[215];
	int       sessIdLen;
	uint64_t  capTimeStamp;
	uint64_t  analysisTimeStamp;
	uint8_t   *userInfo;
	uint32_t  userInfoLen;
	uint32_t  userInfoType;  //10005001->userInfoType,为userInfo的类型指定项,0x10005094为用户标签可用最小值
	online_extra_t extra;
}online_fc_t;

typedef struct{
	char      sessId[215];
	int       sessIdLen;
	uint64_t  capTimeStamp;
	uint64_t  analysisTimeStamp;
	uint32_t  m2BigType;    //新协议大类型
	uint32_t  m2AddType;    //新协议大类型下的一层类型
	uint8_t   *userInfo;
	uint32_t  userInfoLen;
	uint32_t  userInfoType;  //10005001->userInfoType,为userInfo的类型指定项,0x10005094为用户标签可用最小值
	online_extra_t extra;
}online_fd_t;

typedef struct{
	uint8_t cover;
}online_pv_t;



//ip数据反馈
typedef int onlineip_entry_helper(void *session, online_fb_t *fb, uint8_t *data, uint32_t datalen, uint32_t datatype, uint32_t channel, int thr_id, void **user_data);
/*
 *fb：数据携带结构体
 *data：ip数据
 *datalen：ip数据长度
 *datatype：数据类型（0x01  //ip数据，开头为0x45; 0x08  //以太数据，开头带有14个字节的以太头; 0x20  //非ip数据）
 *
 * */
//链路数据反馈
typedef int onlineld_entry_helper(void *session, online_fc_t *fc, uint8_t *data, uint32_t datalen, uint32_t channel, int thr_id, void **user_data);
/*
 *fc：数据携带结构体
 *data：链路数据
 *datalen：链路数据长度
 *
 * */
//帧数据直接反馈，无ip数据无链路数据，直接发送给ndds，类似新协议开发
typedef int onlinefh_entry_helper(void *session, online_fd_t *fd, uint8_t *data, uint32_t datalen, uint16_t pro_type, uint32_t channel, int thr_id, void **user_data);
/*
 *fd：数据携带结构体
 *data：组装的M2消息，此消息会被放在fd->m2BigType:fd->m2AddType下
 *datalen：组装的M2消息长度
 * pro_type：新协议的pro_type
 * */

//无M2格式数据发送，用来传递自定义消息格式
typedef int onlinepv_entry_helper(void *session, online_pv_t *pv, uint8_t *data, uint32_t datalen, uint32_t channel, int thr_id, void **user_data);
/*
 *pv：数据携带结构体
 *data：需要发送的信息
 *datalen：需要发送的信息长度
 * */

typedef struct{
	onlineip_entry_helper *onlineip_entry;
	onlineld_entry_helper *onlineld_entry;
	onlinefh_entry_helper *onlinefh_entry;
	onlinepv_entry_helper *onlinepv_entry;
}online_helper_t;


#pragma pack (0)
