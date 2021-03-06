
#ifndef __VMP_DEMOD_H__
#define	__VMP_DEMOD_H__

#ifdef __linux__
#define __declspec(dllexport)
#endif

#include <stdint.h>


#ifdef __cplusplus
extern "C"
{
#endif

	typedef enum __vmpapi_err_t
	{
		VMPAPI_SUCCESS = 0,						/**调用成功**/
		VMPAPI_ARGNULL,							/**传入参数中存在NULL指针**/
		VMPAPI_MALLOCERR,						/**malloc申请内存失败**/
		VMPAPI_THREADERR,						/**创建线程失败**/
		VMPAPI_TYPEERR,							/**传入的vmp_demod_type_t与实际ip地址和端口不对应**/
		VMPAPI_UNKNOWNTYPE,						/**传入了未知的vmp_demod_type_t**/
		VMPAPI_NETERR,							/**网络连接失败（Windows调用WSAGetLastError获取错误信息；Linux调用perror获取错误信息）**/
		VMPAPI_BUFLENSMALL,						/**传入的buf_len长度小于当前数据包的长度**/
		VMPAPI_EMPTY,							/**没有可用的数据**/
	} vmpapi_err_t;


#pragma pack(push, 1)

	typedef struct __burst_hdr_t
	{
		uint32_t		u32Signature;			/**头标志0xF0473C58**/
		uint32_t		u32Fre;					/**解调器中突发载波初始估计的中频频率**/
		uint64_t		u64PacketCount;			/**突发计数**/
		uint64_t		u64StartPosition;		/**突发起始采样计数**/
		uint64_t		u64Systime;				/**突发时戳,单位100ns**/
		int32_t			i32EbNO;				/**信噪比估计，通过 10*log10(i32EbNO/100) 转换成 dB 值**/
		int32_t			FreOffset;				/**突发载波频偏**/
		uint32_t		u32DataLen;				/**当前突发的数据长度，单位字节**/
		uint32_t		u32SymbolRate;			/**突发符号速率**/
		uint32_t		u32ChannelID;			/**突发对应的解调通道号**/
		uint16_t		u16CrcResult;			/** 突发解调译码后的 CRC-16 结果，0 表示通过 CRC**/
		uint16_t		u16DataType;			/**数据类型**/
		union
		{
			uint16_t	u16FrameNum;			/**突发所在帧的帧序号**/
			uint32_t	u32FrameNum;
			int32_t		i32Corrval;				/**比特相关检测器的输出值**/
			float		f32Corrval;				/**基带相关检测器的输出值**/
		};
		int16_t			code_rate;				/**突发码率： 0 - 1/2, 1 - 2/3, 2 - 4/5, 3 - 9/10， -1 表示未知**/
		int16_t			payload_offset;			/**突发载荷相对突发起始位置的偏移，单位 bit，-1 表示未能匹配到独特字**/
		uint16_t		dec_len;				/**突发译码后的载荷长度，单位：字节**/
		uint16_t		payload_len;			/**突发译码前的载荷长度，单位：bit**/
		union
		{
			uint16_t	u16AssignID;			/**网控匹配后的AssignID**/
			uint32_t	u32AssignID;
			float		payload_ratio;
		};
		union
		{
			uint32_t    u32SerialNum;
			float       fCorrThreshold;
		};
		uint16_t		u16Reserved;
		union
		{
			uint8_t		u8AlohaCrc;
			uint8_t		u8Priority;
			uint8_t		u8BurstType;
		};
		uint8_t			u8GroupID;
	} burst_hdr_t;

	typedef struct __vmp_demod_data_ts
	{
		uint16_t		pid;					/**TS数据的pid**/
		uint8_t			data[0];				/**TS数据**/
	} vmp_demod_data_ts;

	typedef struct __vmp_demod_data_mpe
	{
		uint16_t		pid;					/**MPE数据的pid**/
		uint8_t			data[0];				/**MPE数据*/
	} vmp_demod_data_mpe;

	typedef struct __vmp_demod_data_pdu
	{
		uint16_t		pid;					/**PDU数据的pid**/
		uint8_t			data[0];				/**PDU数据**/
	} vmp_demod_data_pdu;

	typedef struct __vmp_demod_data_demod
	{
		burst_hdr_t		header;					/**解调数据头**/
		uint8_t			data[0];				/**解调数据**/
	} vmp_demod_data_demod;

	typedef struct __vmp_demod_data_decode
	{
		burst_hdr_t		header;					/**译码数据头**/
		uint8_t			data[0];				/**译码数据**/
	} vmp_demod_data_decode;

	typedef struct __vmp_demod_data_station
	{
		burst_hdr_t		header;					/**TDMA帧数据头**/
		uint8_t			data[0];				/**TDMA帧数据**/
	} vmp_demod_data_station;


	typedef struct __vmp_demod_data_ip
	{
		uint32_t		assign_id;				/**小站临时id**/
		uint32_t		serial_num;				/**小站临时序列号**/
		uint64_t		mac;					/**MAC地址**/
		uint8_t			right;					/**数据是否完整**/
		uint8_t			group_id;				/**组id**/
		uint8_t			priority;				/**优先级**/
		uint8_t			data[0];				/**IP数据**/
	} vmp_demod_data_ip;
	
	typedef struct __vmp_demod_data_loc_refer
	{
		uint8_t		port_id;
		uint8_t		ch_id;
		uint32_t	samp_rate;
		uint8_t		data[0];
	}vmp_demod_data_loc_refer_t;

	typedef enum __vmp_demod_type_t
	{
		vmp_demod_type_ts = 0,					/**TS数据**/
		vmp_demod_type_mpe,						/**MPE数据**/
		vmp_demod_type_pdu,						/**PDU数据**/
		vmp_demod_type_demod,					/**TDMA解调数据**/
		vmp_demod_type_decode,					/**TDMA译码数据**/
		vmp_demod_type_station,					/**TDMA帧**/
		vmp_demod_type_ip,						/**IP数据**/
		vmp_demod_type_optloc,					/**LOC数据**/
		vmp_demod_type_meta,					/** 靠� **/
		vmp_demod_type_meta2,					/** s57靠� **/
		vmp_demod_type_loc_refer,				/** LOC refer**/
	} vmp_demod_type_t;


	typedef struct __vmp_demod_data_info_t
	{
		uint8_t					dev_id[32];		/**设备id**/
		uint64_t				timestamp;		/**时戳**/
		vmp_demod_type_t		type;			/**数据类型**/
	} vmp_demod_data_info_t;

		typedef struct __vmp_demod_stats_t
	{
		uint64_t		rx_bytes;				/**收到的总字节数**/
		uint64_t		rx_num;					/**收到的数据总条数**/
		uint64_t		cc_err;					/**连续性计数检测错误的条数**/
		uint64_t		put_num;				/**放入缓冲区队列的条数**/
		uint64_t		get_num;				/**从缓冲区队列取出的条数**/
		uint64_t		drop_num;				/**放入缓冲区队列失败的条数**/
		uint64_t		connect_num;			/**socket连接的次数**/
		uint64_t		last_time;				/**最近一次连接的时间**/
	} vmp_demod_stats_t;

#pragma pack(pop)

	__declspec(dllexport) void* vmp_demod_open(uint32_t ip, uint16_t port, vmp_demod_type_t type, int *retcode);

	__declspec(dllexport) void vmp_demod_close(void *handle, int *retcode);

	__declspec(dllexport) int vmp_demod_get_data(void *handle, vmp_demod_data_info_t *info, void *buf, uint32_t buf_len, int *retcode);

	__declspec(dllexport) void vmp_demod_get_stats(void *handle, vmp_demod_stats_t *stats, int *retcode);

	__declspec(dllexport) void vmp_demod_reset_stats(void *handle, int *retcode);

#ifdef __cplusplus
}
#endif


#endif /**vmp_demod.h**/
