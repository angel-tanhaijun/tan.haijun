
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
		VMPAPI_SUCCESS = 0,						/**µ÷ÓÃ³É¹¦**/
		VMPAPI_ARGNULL,							/**´«Èë²ÎÊıÖĞ´æÔÚNULLÖ¸Õë**/
		VMPAPI_MALLOCERR,						/**mallocÉêÇëÄÚ´æÊ§°Ü**/
		VMPAPI_THREADERR,						/**´´½¨Ïß³ÌÊ§°Ü**/
		VMPAPI_TYPEERR,							/**´«ÈëµÄvmp_demod_type_tÓëÊµ¼ÊipµØÖ·ºÍ¶Ë¿Ú²»¶ÔÓ¦**/
		VMPAPI_UNKNOWNTYPE,						/**´«ÈëÁËÎ´ÖªµÄvmp_demod_type_t**/
		VMPAPI_NETERR,							/**ÍøÂçÁ¬½ÓÊ§°Ü£¨Windowsµ÷ÓÃWSAGetLastError»ñÈ¡´íÎóĞÅÏ¢£»Linuxµ÷ÓÃperror»ñÈ¡´íÎóĞÅÏ¢£©**/
		VMPAPI_BUFLENSMALL,						/**´«ÈëµÄbuf_len³¤¶ÈĞ¡ÓÚµ±Ç°Êı¾İ°üµÄ³¤¶È**/
		VMPAPI_EMPTY,							/**Ã»ÓĞ¿ÉÓÃµÄÊı¾İ**/
	} vmpapi_err_t;


#pragma pack(push, 1)

	typedef struct __burst_hdr_t
	{
		uint32_t		u32Signature;			/**Í·±êÖ¾0xF0473C58**/
		uint32_t		u32Fre;					/**½âµ÷Æ÷ÖĞÍ»·¢ÔØ²¨³õÊ¼¹À¼ÆµÄÖĞÆµÆµÂÊ**/
		uint64_t		u64PacketCount;			/**Í»·¢¼ÆÊı**/
		uint64_t		u64StartPosition;		/**Í»·¢ÆğÊ¼²ÉÑù¼ÆÊı**/
		uint64_t		u64Systime;				/**Í»·¢Ê±´Á,µ¥Î»100ns**/
		int32_t			i32EbNO;				/**ĞÅÔë±È¹À¼Æ£¬Í¨¹ı 10*log10(i32EbNO/100) ×ª»»³É dB Öµ**/
		int32_t			FreOffset;				/**Í»·¢ÔØ²¨ÆµÆ«**/
		uint32_t		u32DataLen;				/**µ±Ç°Í»·¢µÄÊı¾İ³¤¶È£¬µ¥Î»×Ö½Ú**/
		uint32_t		u32SymbolRate;			/**Í»·¢·ûºÅËÙÂÊ**/
		uint32_t		u32ChannelID;			/**Í»·¢¶ÔÓ¦µÄ½âµ÷Í¨µÀºÅ**/
		uint16_t		u16CrcResult;			/** Í»·¢½âµ÷ÒëÂëºóµÄ CRC-16 ½á¹û£¬0 ±íÊ¾Í¨¹ı CRC**/
		uint16_t		u16DataType;			/**Êı¾İÀàĞÍ**/
		union
		{
			uint16_t	u16FrameNum;			/**Í»·¢ËùÔÚÖ¡µÄÖ¡ĞòºÅ**/
			uint32_t	u32FrameNum;
			int32_t		i32Corrval;				/**±ÈÌØÏà¹Ø¼ì²âÆ÷µÄÊä³öÖµ**/
			float		f32Corrval;				/**»ù´øÏà¹Ø¼ì²âÆ÷µÄÊä³öÖµ**/
		};
		int16_t			code_rate;				/**Í»·¢ÂëÂÊ£º 0 - 1/2, 1 - 2/3, 2 - 4/5, 3 - 9/10£¬ -1 ±íÊ¾Î´Öª**/
		int16_t			payload_offset;			/**Í»·¢ÔØºÉÏà¶ÔÍ»·¢ÆğÊ¼Î»ÖÃµÄÆ«ÒÆ£¬µ¥Î» bit£¬-1 ±íÊ¾Î´ÄÜÆ¥Åäµ½¶ÀÌØ×Ö**/
		uint16_t		dec_len;				/**Í»·¢ÒëÂëºóµÄÔØºÉ³¤¶È£¬µ¥Î»£º×Ö½Ú**/
		uint16_t		payload_len;			/**Í»·¢ÒëÂëÇ°µÄÔØºÉ³¤¶È£¬µ¥Î»£ºbit**/
		union
		{
			uint16_t	u16AssignID;			/**Íø¿ØÆ¥ÅäºóµÄAssignID**/
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
		uint16_t		pid;					/**TSÊı¾İµÄpid**/
		uint8_t			data[0];				/**TSÊı¾İ**/
	} vmp_demod_data_ts;

	typedef struct __vmp_demod_data_mpe
	{
		uint16_t		pid;					/**MPEÊı¾İµÄpid**/
		uint8_t			data[0];				/**MPEÊı¾İ*/
	} vmp_demod_data_mpe;

	typedef struct __vmp_demod_data_pdu
	{
		uint16_t		pid;					/**PDUÊı¾İµÄpid**/
		uint8_t			data[0];				/**PDUÊı¾İ**/
	} vmp_demod_data_pdu;

	typedef struct __vmp_demod_data_demod
	{
		burst_hdr_t		header;					/**½âµ÷Êı¾İÍ·**/
		uint8_t			data[0];				/**½âµ÷Êı¾İ**/
	} vmp_demod_data_demod;

	typedef struct __vmp_demod_data_decode
	{
		burst_hdr_t		header;					/**ÒëÂëÊı¾İÍ·**/
		uint8_t			data[0];				/**ÒëÂëÊı¾İ**/
	} vmp_demod_data_decode;

	typedef struct __vmp_demod_data_station
	{
		burst_hdr_t		header;					/**TDMAÖ¡Êı¾İÍ·**/
		uint8_t			data[0];				/**TDMAÖ¡Êı¾İ**/
	} vmp_demod_data_station;


	typedef struct __vmp_demod_data_ip
	{
		uint32_t		assign_id;				/**Ğ¡Õ¾ÁÙÊ±id**/
		uint32_t		serial_num;				/**Ğ¡Õ¾ÁÙÊ±ĞòÁĞºÅ**/
		uint64_t		mac;					/**MACµØÖ·**/
		uint8_t			right;					/**Êı¾İÊÇ·ñÍêÕû**/
		uint8_t			group_id;				/**×éid**/
		uint8_t			priority;				/**ÓÅÏÈ¼¶**/
		uint8_t			data[0];				/**IPÊı¾İ**/
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
		vmp_demod_type_ts = 0,					/**TSÊı¾İ**/
		vmp_demod_type_mpe,						/**MPEÊı¾İ**/
		vmp_demod_type_pdu,						/**PDUÊı¾İ**/
		vmp_demod_type_demod,					/**TDMA½âµ÷Êı¾İ**/
		vmp_demod_type_decode,					/**TDMAÒëÂëÊı¾İ**/
		vmp_demod_type_station,					/**TDMAÖ¡**/
		vmp_demod_type_ip,						/**IPÊı¾İ**/
		vmp_demod_type_optloc,					/**LOCÊı¾İ**/
		vmp_demod_type_meta,					/** ¿¿¿ **/
		vmp_demod_type_meta2,					/** s57¿¿¿ **/
		vmp_demod_type_loc_refer,				/** LOC refer**/
	} vmp_demod_type_t;


	typedef struct __vmp_demod_data_info_t
	{
		uint8_t					dev_id[32];		/**Éè±¸id**/
		uint64_t				timestamp;		/**Ê±´Á**/
		vmp_demod_type_t		type;			/**Êı¾İÀàĞÍ**/
	} vmp_demod_data_info_t;

		typedef struct __vmp_demod_stats_t
	{
		uint64_t		rx_bytes;				/**ÊÕµ½µÄ×Ü×Ö½ÚÊı**/
		uint64_t		rx_num;					/**ÊÕµ½µÄÊı¾İ×ÜÌõÊı**/
		uint64_t		cc_err;					/**Á¬ĞøĞÔ¼ÆÊı¼ì²â´íÎóµÄÌõÊı**/
		uint64_t		put_num;				/**·ÅÈë»º³åÇø¶ÓÁĞµÄÌõÊı**/
		uint64_t		get_num;				/**´Ó»º³åÇø¶ÓÁĞÈ¡³öµÄÌõÊı**/
		uint64_t		drop_num;				/**·ÅÈë»º³åÇø¶ÓÁĞÊ§°ÜµÄÌõÊı**/
		uint64_t		connect_num;			/**socketÁ¬½ÓµÄ´ÎÊı**/
		uint64_t		last_time;				/**×î½üÒ»´ÎÁ¬½ÓµÄÊ±¼ä**/
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
