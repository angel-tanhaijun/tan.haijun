
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
		VMPAPI_SUCCESS = 0,						/**���óɹ�**/
		VMPAPI_ARGNULL,							/**��������д���NULLָ��**/
		VMPAPI_MALLOCERR,						/**malloc�����ڴ�ʧ��**/
		VMPAPI_THREADERR,						/**�����߳�ʧ��**/
		VMPAPI_TYPEERR,							/**�����vmp_demod_type_t��ʵ��ip��ַ�Ͷ˿ڲ���Ӧ**/
		VMPAPI_UNKNOWNTYPE,						/**������δ֪��vmp_demod_type_t**/
		VMPAPI_NETERR,							/**��������ʧ�ܣ�Windows����WSAGetLastError��ȡ������Ϣ��Linux����perror��ȡ������Ϣ��**/
		VMPAPI_BUFLENSMALL,						/**�����buf_len����С�ڵ�ǰ���ݰ��ĳ���**/
		VMPAPI_EMPTY,							/**û�п��õ�����**/
	} vmpapi_err_t;


#pragma pack(push, 1)

	typedef struct __burst_hdr_t
	{
		uint32_t		u32Signature;			/**ͷ��־0xF0473C58**/
		uint32_t		u32Fre;					/**�������ͻ���ز���ʼ���Ƶ���ƵƵ��**/
		uint64_t		u64PacketCount;			/**ͻ������**/
		uint64_t		u64StartPosition;		/**ͻ����ʼ��������**/
		uint64_t		u64Systime;				/**ͻ��ʱ��,��λ100ns**/
		int32_t			i32EbNO;				/**����ȹ��ƣ�ͨ�� 10*log10(i32EbNO/100) ת���� dB ֵ**/
		int32_t			FreOffset;				/**ͻ���ز�Ƶƫ**/
		uint32_t		u32DataLen;				/**��ǰͻ�������ݳ��ȣ���λ�ֽ�**/
		uint32_t		u32SymbolRate;			/**ͻ����������**/
		uint32_t		u32ChannelID;			/**ͻ����Ӧ�Ľ��ͨ����**/
		uint16_t		u16CrcResult;			/** ͻ����������� CRC-16 �����0 ��ʾͨ�� CRC**/
		uint16_t		u16DataType;			/**��������**/
		union
		{
			uint16_t	u16FrameNum;			/**ͻ������֡��֡���**/
			uint32_t	u32FrameNum;
			int32_t		i32Corrval;				/**������ؼ���������ֵ**/
			float		f32Corrval;				/**������ؼ���������ֵ**/
		};
		int16_t			code_rate;				/**ͻ�����ʣ� 0 - 1/2, 1 - 2/3, 2 - 4/5, 3 - 9/10�� -1 ��ʾδ֪**/
		int16_t			payload_offset;			/**ͻ���غ����ͻ����ʼλ�õ�ƫ�ƣ���λ bit��-1 ��ʾδ��ƥ�䵽������**/
		uint16_t		dec_len;				/**ͻ���������غɳ��ȣ���λ���ֽ�**/
		uint16_t		payload_len;			/**ͻ������ǰ���غɳ��ȣ���λ��bit**/
		union
		{
			uint16_t	u16AssignID;			/**����ƥ����AssignID**/
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
		uint16_t		pid;					/**TS���ݵ�pid**/
		uint8_t			data[0];				/**TS����**/
	} vmp_demod_data_ts;

	typedef struct __vmp_demod_data_mpe
	{
		uint16_t		pid;					/**MPE���ݵ�pid**/
		uint8_t			data[0];				/**MPE����*/
	} vmp_demod_data_mpe;

	typedef struct __vmp_demod_data_pdu
	{
		uint16_t		pid;					/**PDU���ݵ�pid**/
		uint8_t			data[0];				/**PDU����**/
	} vmp_demod_data_pdu;

	typedef struct __vmp_demod_data_demod
	{
		burst_hdr_t		header;					/**�������ͷ**/
		uint8_t			data[0];				/**�������**/
	} vmp_demod_data_demod;

	typedef struct __vmp_demod_data_decode
	{
		burst_hdr_t		header;					/**��������ͷ**/
		uint8_t			data[0];				/**��������**/
	} vmp_demod_data_decode;

	typedef struct __vmp_demod_data_station
	{
		burst_hdr_t		header;					/**TDMA֡����ͷ**/
		uint8_t			data[0];				/**TDMA֡����**/
	} vmp_demod_data_station;


	typedef struct __vmp_demod_data_ip
	{
		uint32_t		assign_id;				/**Сվ��ʱid**/
		uint32_t		serial_num;				/**Сվ��ʱ���к�**/
		uint64_t		mac;					/**MAC��ַ**/
		uint8_t			right;					/**�����Ƿ�����**/
		uint8_t			group_id;				/**��id**/
		uint8_t			priority;				/**���ȼ�**/
		uint8_t			data[0];				/**IP����**/
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
		vmp_demod_type_ts = 0,					/**TS����**/
		vmp_demod_type_mpe,						/**MPE����**/
		vmp_demod_type_pdu,						/**PDU����**/
		vmp_demod_type_demod,					/**TDMA�������**/
		vmp_demod_type_decode,					/**TDMA��������**/
		vmp_demod_type_station,					/**TDMA֡**/
		vmp_demod_type_ip,						/**IP����**/
		vmp_demod_type_optloc,					/**LOC����**/
		vmp_demod_type_meta,					/** ��� **/
		vmp_demod_type_meta2,					/** s57��� **/
		vmp_demod_type_loc_refer,				/** LOC refer**/
	} vmp_demod_type_t;


	typedef struct __vmp_demod_data_info_t
	{
		uint8_t					dev_id[32];		/**�豸id**/
		uint64_t				timestamp;		/**ʱ��**/
		vmp_demod_type_t		type;			/**��������**/
	} vmp_demod_data_info_t;

		typedef struct __vmp_demod_stats_t
	{
		uint64_t		rx_bytes;				/**�յ������ֽ���**/
		uint64_t		rx_num;					/**�յ�������������**/
		uint64_t		cc_err;					/**�����Լ��������������**/
		uint64_t		put_num;				/**���뻺�������е�����**/
		uint64_t		get_num;				/**�ӻ���������ȡ��������**/
		uint64_t		drop_num;				/**���뻺��������ʧ�ܵ�����**/
		uint64_t		connect_num;			/**socket���ӵĴ���**/
		uint64_t		last_time;				/**���һ�����ӵ�ʱ��**/
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
