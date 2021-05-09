// 下列 ifdef 块是创建使从 DLL 导出更简单的
//宏的标准方法。此 DLL 中的所有文件都是用命令行上定义的 SOFTBUS_EXPORTS
// 符号编译的。在使用此 DLL 的
//任何其他项目上不应定义此符号。这样，源文件中包含此文件的任何其他项目都会将 
// SOFTBUS_API 函数视为是从此 DLL 导入的，而此 DLL 则将用此宏定义的
// 符号视为是被导出的。
#ifndef _SOFTBUS_H_
#define _SOFTBUS_H_

/*********************************************************
文件名：SoftBus.h
创建人：刘峰
创建日期：2008-8-8
描述：软件总线动态库的数据定义和导出函数定义头文件
修改记录：
1）修改日期2009-02-10 ，修改人 刘峰，修改内容：开发完成
*********************************************************/

#ifdef SOFTBUS_EXPORTS
#define SOFTBUS_API __declspec(dllexport)
#else
#define SOFTBUS_API __declspec(dllimport)
#endif

#ifndef _WINDOWS
#define __stdcall
#define __declspec(x)
#define __cdecl
#endif

#define IP_STR_LEN (16)
#define ERR_MSG_MAX_LEN (256)

//最大插槽数
#define MAX_SLOT_NUM (10)
//最大引脚数
#define MAX_FOOT_NUM (100)
//最大目的节点数
#define MAX_DESTNODE_NUM (100)

typedef unsigned char	BYTE;
typedef unsigned short	WORD;
//typedef unsigned long	DWORD;


typedef struct BusDataIdent{
	int iSlotType;					//插槽类型序号
	int iDataType;					//数据形式：1－块数据；2－数据文件
	char strSrcIP[IP_STR_LEN];		//发送方IP地址
	int iSrcAppEntityNo;			//发送方应用实体号
	unsigned int uiSrcListenPort;	//发送方监听端口
	int iSrcFootNo;					//发送方引脚序号
	char strDestIP[IP_STR_LEN];		//接收方IP地址
	int iDestAppEntityNo;			//接收方应用实体号
	int iDestFootNo;				//接收方引脚序号
	unsigned int uiDataSN;			//流水号
} BUSDATAIDENT;

//stDataIdent，输入参数，数据标识
//iLen，输入参数，含义分两种情况：收到块数据的字节数；收到数据文件的文件名长度，单位为字节。
//pbyData，输入参数，含义分两种情况：收到的块数据；收到数据文件的文件名。其空间由软件总线维护。
//返回值：
//说明：
//如果数据形式为文件，该文件由数据消费者维护。
//一个应用程序只注册一个回调函数，供各类插槽共用。
//要求回调函数可重入。
//回调函数返回后，当前收到的数据将从软件总线缓存中删除。
//建议回调函数只做接受数据的操作，把耗时较多的数据处理工作放到其它线程中进行。
typedef void(__stdcall *CallBackFunc)(const BUSDATAIDENT stDataIdent,  const int iLen,  const  BYTE*  pbyData);


//通知标识
//usNotifyType通知类型:	0-信息	|	1-错误信息	|	2-文件进度
//iValue值：			无定义	|	错误码		|	文件发送进度0-100
//strContent内容：		信息内容|	错误信息	|	文件名
typedef struct NotifyId
{
	int		iAppEntityNo;			//应用实体号
	int		iSlotType;				//插槽类型序号
	int		iFootNo;				//发送方引脚序号
	unsigned short	usNotifyType;	//通知类型：0-信息；1-错误信息；2-文件进度
	int		iValue;					//值，具体意义由通知类型决定
	char	strContent[256];		//内容，字符串，以‘\0’结束
}NOTIFYID;

//通知回调
//建议此函数不要阻塞
typedef void(__stdcall *OnNotify)(const NOTIFYID& stNotifyID);

typedef struct Slot{
	int iSlotType;				//插槽类型序号
	int iFootNum;				//引脚数量
	int arFoot[MAX_FOOT_NUM][3];			//第二维的三列分别表示引脚序号、类型序号、优先级
	CallBackFunc OnRecvDataOfFoot[MAX_FOOT_NUM];	//所有接收引脚的默认回调函数，默认值为NULL
} SLOT;	//插槽结构定义

//注册信息结构定义
typedef struct RegInfo{
	int iAppEntityNo;			//应用实体号
	int iSlotNum;				//该组插槽的插槽总数
	SLOT arSlotGroup[MAX_SLOT_NUM];		//插槽组，包括：流插槽、控制插槽、状态插槽
	CallBackFunc OnRecvData;		//收到数据的回调函数
} REGINFO; 

//错误信息定义
typedef struct BusErrMes{
	int iErrCode;				//错误代码
	char strErrMes [ERR_MSG_MAX_LEN];		//错误信息描述
	int iErrSlotTypeNo;			//出错的插槽类型序号
	int iErrFootNo;			//出错的引脚序号
} BUSERRMES;

//参数：
//stRegInfo，输入，注册信息
//返回值：
//1－注册成功；<0－注册失败，返回值为错误代码。错误代码列表参见附录1。
extern "C" __declspec(dllexport)
int RegBus(REGINFO stRegInfo);


//参数：
//iSlotType，输入参数，插槽类型序号。
//iSendFootNo，输入参数，发送引脚序号。
//strDestIP，输入参数，新消费者的IP地址。
//返回值：
//说明：
//如果输入值iSendFootNo = -1，表示该类型插槽的所有发送引脚的消费者都同步修改。
extern "C" __declspec(dllexport)
void ReplaceConsumer(const int iSlotType, const int iSendFootNo,  const char* strDestIP);

//设置通知，总线通过设置的通知回调函数，告知应用重要信息
//fnNotify-通知回调函数，NULL 表示不需通知
extern "C" __declspec(dllexport)
void SetNotify(OnNotify fnNotify, const int iAppEntityNo);

//发送数据块
//参数：
//iSlotType，输入参数，插槽类型序号。
//iSendFootNo，输入参数，发送引脚序号。
//iLen，输入参数，输入值为待发数据块pbyData字节数。
//pbyData，输入参数，待发数据块。其空间由调用者维护。
//iRespLen，输人输出参数。输入值表示空间pbyResp的字节数；输出值表示实际应答数据的总字节数，如果输入空间不够输出值将超过输入值，但返回数据包pbyResp长度等于输入值。
//pbyResp，输出参数，响应数据块，该参数仅在发送控制数据时有效。如果空间不足，从后面截短响应数据进行存储。调用者负责维护空间。
//iAppEntityNo，输入参数，调用者的应用实体号。该参数用于单个EXE程序的多个组件分别使用软件总线的场合，其它场合不用指定该参数。未指定该输入参数时取默认值0，该数据将被归属为第一个注册的应用实体。
//返回值：
//1－发送成功；
//0－响应数据块空间不足，
//<0－发送失败，返回值为错误代码。错误代码列表参见附录1。
//说明：
//该函数对各种类型插槽是通用的。
//组播发送最大包长度为1400B，点对点发送最大包长度为10MB。
extern "C" __declspec(dllexport)
int SendBlock (const int iSlotType,  const int iSendFootNo,  int iLen, BYTE* pbyData, int& iRespLen, BYTE* pbyResp,  const int iAppEntityNo = 0);


//发送数据块,发送连续数据
//参数：
//iSlotType，输入参数，插槽类型序号
//iSendFootNo，输入参数，发送引脚序号
//iLen，输入参数。待发数据块pbyData长度。
//pbyData，输入参数，待发数据块。其空间由调用者维护。
//iAppEntityNo，输入参数，调用者的应用实体号。该参数用于单个EXE程序的多个组件分别使用软件总线的场合，其它场合不用指定该参数。未指定该输入参数时取默认值0，该数据将被归属为第一个注册的应用实体。
//返回值：>=0成功发送的字节数；<0－发送失败，返回值为错误代码。错误代码列表参见附录1。
//说明：该函数只适用于流插槽。
extern "C" __declspec(dllexport)
int SendBlockEx (const int iSlotType,  const int iSendFootNo,  int iLen, BYTE* pbyData,  const int iAppEntityNo = 0);

//发送数据块到指定IP地址
//发送数据块pbyData到指定的IP地址strDestIP的应用程序。如果是在控制插槽上发送数据，该函数将阻塞到应答数据到达或者超时为止。
//iSlotType，输入参数，插槽类型序号
//strDestIP，输入参数，接收方IP地址
//iLen，输入参数，输入值为待发数据块pbyData字节数。
//pbyData，输入参数，待发数据块。其空间由调用者维护。
//iRespLen，输人输出参数。输入值表示空间pbyResp的字节数；输出值表示实际应答数据的总字节数，如果输入空间不够输出值将超过输入值，但返回数据包pbyResp长度等于输入值。
//pbyResp，输出参数，响应数据块，该参数仅在发送控制数据时有效。如果空间不足，从后面截短响应数据进行存储。调用者负责维护空间。
//iAppEntityNo，输入参数，调用者的应用实体号。该参数用于单个EXE程序的多个组件分别使用软件总线的场合，其它场合不用指定该参数。未指定该输入参数时取默认值0，该数据将被归属为第一个注册的应用实体。
//返回值：
//1－发送成功；
//0－响应数据块空间不足，
//<0－发送失败，返回值为错误代码。错误代码列表参见附录1。
//说明：
//该函数对各种类型插槽是通用的。
//组播发送最大包长度为1400B，点对点发送最大包长度为10MB。
//该方法只适用于该只有一个发送引脚的目的IP对应此IP
extern "C" __declspec(dllexport)
int SendBlockToIP (const int iSlotType, char* strDestIP,  int iLen, BYTE* pbyData, int& iRespLen, BYTE* pbyResp,  const int iAppEntityNo = 0);


//发送数据文件
//参数：
//iSlotType，输入参数，插槽类型序号
//iSendFootNo，输入参数，发送引脚序号
//strFileName，输入参数，待发数据文件名
//iAppEntityNo，输入参数，调用者的应用实体号。该参数用于单个EXE程序的多个组件分别使用软件总线的场合，其它场合不用指定该参数。未指定该输入参数时取默认值0，该数据将被归属为第一个注册的应用实体。
//返回值：1－发送成功；<0－发送失败，返回值为错误代码。错误代码列表参见附录1。
extern "C" __declspec(dllexport)
int SendFile(const int iSlotType,  const int iSendFootNo, char* strFileName,  const int iAppEntityNo = 0);

//2.5新增接口，发送控制文件
extern "C" __declspec(dllexport)
int SendCtrlFile(const int iSlotType,  const int iSendFootNo, char* strFileName, int& iRespLen, BYTE* pbyResp,  const int iAppEntityNo = 0);

//发送数据文件到IP地址
//参数：
//iSlotType，输入参数，插槽类型序号
//strDestIP，输入参数，接收方IP地址
//strFileName，输入参数，待发数据文件名
//iAppEntityNo，输入参数，调用者的应用实体号。该参数用于单个EXE程序的多个组件分别使用软件总线的场合，其它场合不用指定该参数。未指定该输入参数时取默认值0，该数据将被归属为第一个注册的应用实体。
//返回值：
//1－发送成功；
//<0－发送失败，返回值为错误代码。错误代码列表参见附录1。
extern "C" __declspec(dllexport)
int SendFileToIP(const int iSlotType, const char* strDestIP,  char* strFileName,  const int iAppEntityNo = 0);


//应答控制数据
//参数：
//stDataIdent，输入参数，控制数据的标识。读取控制数据时返回的数据标识结构。
//iBufLen，输入参数，表示发送数据大小，单位为字节。
//pbyBuf，输出参数，接收数据缓冲区，其空间由数据消费者维护。输出值分两种情况：(1).如果成功读取到块数据，输出值是该块数据；(2).如果成功读取到数据文件，输出值是其文件名。
//返回值：
//1－发送成功；
//<0－发送失败，返回值为错误代码。错误代码列表参见附录1。
extern "C" __declspec(dllexport)
int ReplyControl(BUSDATAIDENT stDataIdent,  int iBufLen,  BYTE* pbyBuf);



//参数：
//stDataIdent，输出参数，数据标识
//iBufLen，输入输出参数，输入值表示接收数据缓冲区大小，单位为字节。输出值分三种情况： (1).如果成功读取到块数据，输出值是该块数据字节数；(2).如果成功读取到数据文件，输出值是其文件名长度，单位为字节；(3). 接收数据缓冲区pbyBuf空间不够时，输出值是需要的最小缓冲区大小，单位为字节。
//pbyBuf，输出参数，接收数据缓冲区，其空间由数据消费者维护。输出值分两种情况：(1).如果成功读取到块数据，输出值是该块数据；(2).如果成功读取到数据文件，输出值是其文件名。
//iAppEntityNo，输入参数，调用者的应用实体号。该参数用于单个EXE程序的多个组件分别使用软件总线的场合，其它场合不用指定该参数。未指定该输入参数时取默认值0，该数据将被归属为第一个注册的应用实体。
//返回值：
//>0－读取数据总字节；
//0－无新数据
//<0－读取失败，返回值为错误代码。错误代码列表参见附录1。
//说明：如果数据形式为文件，该文件由数据消费者维护。
extern "C" __declspec(dllexport)
int ReadData(BUSDATAIDENT& stDataIdent,  int& iBufLen,  BYTE* pbyBuf,  const int iAppEntityNo = 0);


//注销总线
//iAppEntityNo，输入参数，调用者的应用实体号。该参数用于单个EXE程序的多个组件分别使用软件总线的场合，其它场合不用指定该参数。未指定该输入参数时取默认值0，该数据将被归属为第一个注册的应用实体。
extern "C" __declspec(dllexport)
bool ReleaseBus(const int iAppEntityNo= 0);


//参数：
//iAppEntityNo，输入参数，调用者的应用实体号。该参数用于单个EXE程序的多个组件分别使用软件总线的场合，其它场合不用指定该参数。未指定该输入参数时取默认值0，该数据将被归属为第一个注册的应用实体。
//返回值：
//>0－软件总线可提交的异常总数；
//=0－无异常；
extern "C" __declspec(dllexport)
int  GetErrorNum(const int iAppEntityNo= 0);


//参数：
//iNum，输入输出参数，输入值表示数组pstErrMes的大小（BUSERRMES数），输出值表示软件总线错误总数。
//pstErrMes，输出参数，软件总线错误。其空间由调用者维护。
//iAppEntityNo，输入参数，调用者的应用实体号。该参数用于单个EXE程序的多个组件分别使用软件总线的场合，其它场合不用指定该参数。未指定该输入参数时取默认值0，该数据将被归属为第一个注册的应用实体。
//返回值：
//>0－读取到的错误数；
//=0－无错误；
//说明：
//如果软件总线的实际错误数多于输入参数iNum，本次调用只返回iNum输入值个数的错误。如果需要读出所有错误，只能增加pstErrMes大小再次调用。
extern "C" __declspec(dllexport)
int  GetErrorMes(int &iNum, BUSERRMES* pstErrMes,  const int iAppEntityNo= 0);

//发送数据块给外部Socket程序（JXC01工程特有）
//发送数据块给外部设备（未使用软件总线的应用程序简称“外部设备”）。 软件总线通过windows socket接口与外部设备通信，外部设备作为Socket通信服务器端，软件总线作为客户端。
//参数：
//strExtIP，输入参数，外部设备的IP地址。
//uiExtPort，输入参数，外部设备的Winsock端口号。
//iLen，输入参数。待发数据块pbyData长度，单位为字节。
//pbyData，输入参数，待发数据块。其空间由调用者维护。
//iAppEntityNo，输入参数，调用者的应用实体号。该参数用于单个EXE程序的多个组件分别使用软件总线的场合，其它场合不用指定该参数。未指定该输入参数时取默认值0，该数据将被归属为第一个注册的应用实体。
//返回值：
//1－发送成功；
//<0－发送失败，返回值为错误代码。错误代码列表参见附录1。
extern "C" __declspec(dllexport)
int SendBlockExt(char* strExtIP,  unsigned int uiExtPort,  int iLen, BYTE* pbyData, const int iAppEntityNo = 0);

//设置控制超时时间间隔
//参数：
//iMilliSeconds，输入参数，超时时间间隔（单位：毫秒）。
//iAppEntityNo，输入参数，调用者的应用实体号。该参数用于单个EXE程序的多个组件分别使用软件总线的场合，其它场合不用指定该参数。未指定该输入参数时取默认值0，该数据将被归属为第一个注册的应用实体。
//返回值：
//无
//说明：
//如果没调用此方法设置超时时间间隔，则超时时间间隔默认为10000毫秒(10秒)。
extern "C" __declspec(dllexport)
void SetCtrlTimeOut(const int iMilliSeconds, const int iAppEntityNo = 0);


//获取本地总线IP
//参数：无
//返回值：字符串形式的总线IP地址，未注册成功时返回"0.0.0.0"
extern "C" __declspec(dllexport)
char* GetLocalBusIP(const int iAppEntityNo = 0);

#define  SUCCESS				(1)			//操作成功
#define  PARAM_ERROR			(-1)		//参数错误
#define  PTR_INVALID			(-2)		//指针无效
#define  BUSCORE_LOAD_INVALID	(-3)		//总线核心库加载无效

#define  BUSCONTROLLERFAILED	(-1000)		//总线控制器失效
#define  APPENTITYNOERROR		(-1001)		//应用实体号错误
#define  APPENTITYNOERROR		(-1001)		//应用实体号错误
#define  SLOTNUMERROR			(-1002)		//插槽数量错误
#define  SLOTTYPEERROR			(-1003)		//插槽类型序号无效
#define  FOOTNUMERROR			(-1004)		//引脚数量错误
#define  FOOTNOERROR			(-1005)		//引脚序号错误
#define  FOOTTYPEERROR			(-1006)		//引脚类型序号无效
#define  FOOTPRIERROR			(-1007)		//引脚优先级无效
#define	 FOOT_NOT_EXIST			(-1008)		//指定IP发送,引脚不存在
#define  DATA_TYPE_ERROR		(-1009)		//数据形式错，如不能发送文件到外部Socket程序,在控制插槽上发送文件等

#define  BUSBUFFERFULL			(-1101)		//软件总线接收缓冲区满
#define  BUFFERINSUFFICIENT		(-1102)		//缓冲区空间不足
#define  CONTROLTIMEOUT			(-1103)		//控制命令超时无应答
#define  FILE_SIZE_INVALID		(-1104)		//数据文件大小无效，4G以下
#define  ACCESSFILEERROR		(-1105)		//访问数据文件失败

#define  BUS_ENV_INVALID		(-1200)		//总线环境失效
#define  ALREADY_REG			(-1201)		//重复注册总线
#define	 STARTRECEIVERFAILED	(-1202)		//启动接收失败
#define  START_THRD_FAILD		(-1203)		//启动线程失败
#define  CONN_RECV_FULL			(-1204)		//接收连接数已满
#define  REG_INS_FULL			(-1205)		//注册实例已满

#define  READ_BUSSYSFILE_ERROR	(-1300)		//读取总线系统配置文件错误
#define  BUSCTRL_PARAM_ERR		(-1301)		//总线控制配置参数有误
#define  BUSCTRL_REPLY_ERR		(-1302)		//总线控制回复信息有误
#define  BUSCTRL_APP_NOTEXIST	(-1303)		//总线控制中找不到应用
#define  BUS_LISTEN_PORT_ERR	(-1304)		//总线TCP监听端口错误
#define  BUS_UDP_PORT_ERR		(-1305)		//总线UDP端口错误
#define  SOCK_LISTEN_PORT_ERR	(-1306)		//SOCKET监听端口错误
#define  DEST_TYPE_ERR			(-1310)		//目的类型错误
#define  DEST_REL_ERR			(-1311)		//目的关系类型错误
#define  DEST_NUM_ERR			(-1312)		//目的数量错误
#define  DEST_PORT_ERR			(-1313)		//目的端口错误

#define  DESTHOSTFAILED			(-2001)		//目标主机PING不通
#define  DESTAPPFAILED			(-2002)		//目标应用程序失效
#define  NOENOUGHMEMORY			(-2003)		//内存空间不足

#define  CREATESIGNALFAILED		(-2003)		//创建信号量失败



#endif

