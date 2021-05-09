/*************************************************************************
	> File Name: mddw.h
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年08月25日 星期二 11时27分14秒
 ************************************************************************/


#include <stdint.h>
 
#define MDDW_MAX_BUFF_LEN       64
#define MDDW_MAX_THR_NUM  64
#define MDDW_MAX_SC_NUM   16
#pragma pack (1)


typedef struct{
	uint32_t channel; 
	char     ip[MDDW_MAX_BUFF_LEN];
	uint16_t port;
	int      Stat_ID;
	char     Stat_Sig_Type[16];
	float    Stat_Freq;
	float    Stat_Width;
	char     Stat_Band[2];
	char     Stat_Pol[1];
}mddw_sc_info_t;

typedef struct{
	int      Stat_ID;
	char     Stat_Sig_Type[16];
	float    Stat_Freq;
	float    Stat_Width;
	char     Stat_Band[2];
	char     Stat_Pol[1];
}mddw_sc_t;
typedef struct{
	uint32_t       mddw_sc_num;
	mddw_sc_info_t mddw_sc[MDDW_MAX_SC_NUM];
}mddw_gsc_info_t;

typedef struct{
	int thrnum;                  
	int thr_id[MDDW_MAX_THR_NUM];
}mddw_dyn_init_t;
typedef struct{
	int thrnum;
}mddw_dyn_push_t;

typedef struct{
	int thr_num;
}mddw_push_t;

typedef struct{
	int thrnum;
	int thr_id[MDDW_MAX_THR_NUM];
	int canuse[MDDW_MAX_THR_NUM];
}mddw_init_t;
#pragma pack (0)


