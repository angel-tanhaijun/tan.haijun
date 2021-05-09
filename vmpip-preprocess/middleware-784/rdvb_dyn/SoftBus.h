// ���� ifdef ���Ǵ���ʹ�� DLL �������򵥵�
//��ı�׼�������� DLL �е������ļ��������������϶���� SOFTBUS_EXPORTS
// ���ű���ġ���ʹ�ô� DLL ��
//�κ�������Ŀ�ϲ�Ӧ����˷��š�������Դ�ļ��а������ļ����κ�������Ŀ���Ὣ 
// SOFTBUS_API ������Ϊ�ǴӴ� DLL ����ģ����� DLL ���ô˺궨���
// ������Ϊ�Ǳ������ġ�
#ifndef _SOFTBUS_H_
#define _SOFTBUS_H_

/*********************************************************
�ļ�����SoftBus.h
�����ˣ�����
�������ڣ�2008-8-8
������������߶�̬������ݶ���͵�����������ͷ�ļ�
�޸ļ�¼��
1���޸�����2009-02-10 ���޸��� ���壬�޸����ݣ��������
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

//�������
#define MAX_SLOT_NUM (10)
//���������
#define MAX_FOOT_NUM (100)
//���Ŀ�Ľڵ���
#define MAX_DESTNODE_NUM (100)

typedef unsigned char	BYTE;
typedef unsigned short	WORD;
//typedef unsigned long	DWORD;


typedef struct BusDataIdent{
	int iSlotType;					//����������
	int iDataType;					//������ʽ��1�������ݣ�2�������ļ�
	char strSrcIP[IP_STR_LEN];		//���ͷ�IP��ַ
	int iSrcAppEntityNo;			//���ͷ�Ӧ��ʵ���
	unsigned int uiSrcListenPort;	//���ͷ������˿�
	int iSrcFootNo;					//���ͷ��������
	char strDestIP[IP_STR_LEN];		//���շ�IP��ַ
	int iDestAppEntityNo;			//���շ�Ӧ��ʵ���
	int iDestFootNo;				//���շ��������
	unsigned int uiDataSN;			//��ˮ��
} BUSDATAIDENT;

//stDataIdent��������������ݱ�ʶ
//iLen��������������������������յ������ݵ��ֽ������յ������ļ����ļ������ȣ���λΪ�ֽڡ�
//pbyData��������������������������յ��Ŀ����ݣ��յ������ļ����ļ�������ռ����������ά����
//����ֵ��
//˵����
//���������ʽΪ�ļ������ļ�������������ά����
//һ��Ӧ�ó���ֻע��һ���ص��������������۹��á�
//Ҫ��ص����������롣
//�ص��������غ󣬵�ǰ�յ������ݽ���������߻�����ɾ����
//����ص�����ֻ���������ݵĲ������Ѻ�ʱ�϶�����ݴ������ŵ������߳��н��С�
typedef void(__stdcall *CallBackFunc)(const BUSDATAIDENT stDataIdent,  const int iLen,  const  BYTE*  pbyData);


//֪ͨ��ʶ
//usNotifyType֪ͨ����:	0-��Ϣ	|	1-������Ϣ	|	2-�ļ�����
//iValueֵ��			�޶���	|	������		|	�ļ����ͽ���0-100
//strContent���ݣ�		��Ϣ����|	������Ϣ	|	�ļ���
typedef struct NotifyId
{
	int		iAppEntityNo;			//Ӧ��ʵ���
	int		iSlotType;				//����������
	int		iFootNo;				//���ͷ��������
	unsigned short	usNotifyType;	//֪ͨ���ͣ�0-��Ϣ��1-������Ϣ��2-�ļ�����
	int		iValue;					//ֵ������������֪ͨ���;���
	char	strContent[256];		//���ݣ��ַ������ԡ�\0������
}NOTIFYID;

//֪ͨ�ص�
//����˺�����Ҫ����
typedef void(__stdcall *OnNotify)(const NOTIFYID& stNotifyID);

typedef struct Slot{
	int iSlotType;				//����������
	int iFootNum;				//��������
	int arFoot[MAX_FOOT_NUM][3];			//�ڶ�ά�����зֱ��ʾ������š�������š����ȼ�
	CallBackFunc OnRecvDataOfFoot[MAX_FOOT_NUM];	//���н������ŵ�Ĭ�ϻص�������Ĭ��ֵΪNULL
} SLOT;	//��۽ṹ����

//ע����Ϣ�ṹ����
typedef struct RegInfo{
	int iAppEntityNo;			//Ӧ��ʵ���
	int iSlotNum;				//�����۵Ĳ������
	SLOT arSlotGroup[MAX_SLOT_NUM];		//����飬����������ۡ����Ʋ�ۡ�״̬���
	CallBackFunc OnRecvData;		//�յ����ݵĻص�����
} REGINFO; 

//������Ϣ����
typedef struct BusErrMes{
	int iErrCode;				//�������
	char strErrMes [ERR_MSG_MAX_LEN];		//������Ϣ����
	int iErrSlotTypeNo;			//����Ĳ���������
	int iErrFootNo;			//������������
} BUSERRMES;

//������
//stRegInfo�����룬ע����Ϣ
//����ֵ��
//1��ע��ɹ���<0��ע��ʧ�ܣ�����ֵΪ������롣��������б�μ���¼1��
extern "C" __declspec(dllexport)
int RegBus(REGINFO stRegInfo);


//������
//iSlotType��������������������š�
//iSendFootNo���������������������š�
//strDestIP������������������ߵ�IP��ַ��
//����ֵ��
//˵����
//�������ֵiSendFootNo = -1����ʾ�����Ͳ�۵����з������ŵ������߶�ͬ���޸ġ�
extern "C" __declspec(dllexport)
void ReplaceConsumer(const int iSlotType, const int iSendFootNo,  const char* strDestIP);

//����֪ͨ������ͨ�����õ�֪ͨ�ص���������֪Ӧ����Ҫ��Ϣ
//fnNotify-֪ͨ�ص�������NULL ��ʾ����֪ͨ
extern "C" __declspec(dllexport)
void SetNotify(OnNotify fnNotify, const int iAppEntityNo);

//�������ݿ�
//������
//iSlotType��������������������š�
//iSendFootNo���������������������š�
//iLen���������������ֵΪ�������ݿ�pbyData�ֽ�����
//pbyData������������������ݿ顣��ռ��ɵ�����ά����
//iRespLen�������������������ֵ��ʾ�ռ�pbyResp���ֽ��������ֵ��ʾʵ��Ӧ�����ݵ����ֽ������������ռ䲻�����ֵ����������ֵ�����������ݰ�pbyResp���ȵ�������ֵ��
//pbyResp�������������Ӧ���ݿ飬�ò������ڷ��Ϳ�������ʱ��Ч������ռ䲻�㣬�Ӻ���ض���Ӧ���ݽ��д洢�������߸���ά���ռ䡣
//iAppEntityNo����������������ߵ�Ӧ��ʵ��š��ò������ڵ���EXE����Ķ������ֱ�ʹ��������ߵĳ��ϣ��������ϲ���ָ���ò�����δָ�����������ʱȡĬ��ֵ0�������ݽ�������Ϊ��һ��ע���Ӧ��ʵ�塣
//����ֵ��
//1�����ͳɹ���
//0����Ӧ���ݿ�ռ䲻�㣬
//<0������ʧ�ܣ�����ֵΪ������롣��������б�μ���¼1��
//˵����
//�ú����Ը������Ͳ����ͨ�õġ�
//�鲥������������Ϊ1400B����Ե㷢����������Ϊ10MB��
extern "C" __declspec(dllexport)
int SendBlock (const int iSlotType,  const int iSendFootNo,  int iLen, BYTE* pbyData, int& iRespLen, BYTE* pbyResp,  const int iAppEntityNo = 0);


//�������ݿ�,������������
//������
//iSlotType���������������������
//iSendFootNo����������������������
//iLen������������������ݿ�pbyData���ȡ�
//pbyData������������������ݿ顣��ռ��ɵ�����ά����
//iAppEntityNo����������������ߵ�Ӧ��ʵ��š��ò������ڵ���EXE����Ķ������ֱ�ʹ��������ߵĳ��ϣ��������ϲ���ָ���ò�����δָ�����������ʱȡĬ��ֵ0�������ݽ�������Ϊ��һ��ע���Ӧ��ʵ�塣
//����ֵ��>=0�ɹ����͵��ֽ�����<0������ʧ�ܣ�����ֵΪ������롣��������б�μ���¼1��
//˵�����ú���ֻ����������ۡ�
extern "C" __declspec(dllexport)
int SendBlockEx (const int iSlotType,  const int iSendFootNo,  int iLen, BYTE* pbyData,  const int iAppEntityNo = 0);

//�������ݿ鵽ָ��IP��ַ
//�������ݿ�pbyData��ָ����IP��ַstrDestIP��Ӧ�ó���������ڿ��Ʋ���Ϸ������ݣ��ú�����������Ӧ�����ݵ�����߳�ʱΪֹ��
//iSlotType���������������������
//strDestIP��������������շ�IP��ַ
//iLen���������������ֵΪ�������ݿ�pbyData�ֽ�����
//pbyData������������������ݿ顣��ռ��ɵ�����ά����
//iRespLen�������������������ֵ��ʾ�ռ�pbyResp���ֽ��������ֵ��ʾʵ��Ӧ�����ݵ����ֽ������������ռ䲻�����ֵ����������ֵ�����������ݰ�pbyResp���ȵ�������ֵ��
//pbyResp�������������Ӧ���ݿ飬�ò������ڷ��Ϳ�������ʱ��Ч������ռ䲻�㣬�Ӻ���ض���Ӧ���ݽ��д洢�������߸���ά���ռ䡣
//iAppEntityNo����������������ߵ�Ӧ��ʵ��š��ò������ڵ���EXE����Ķ������ֱ�ʹ��������ߵĳ��ϣ��������ϲ���ָ���ò�����δָ�����������ʱȡĬ��ֵ0�������ݽ�������Ϊ��һ��ע���Ӧ��ʵ�塣
//����ֵ��
//1�����ͳɹ���
//0����Ӧ���ݿ�ռ䲻�㣬
//<0������ʧ�ܣ�����ֵΪ������롣��������б�μ���¼1��
//˵����
//�ú����Ը������Ͳ����ͨ�õġ�
//�鲥������������Ϊ1400B����Ե㷢����������Ϊ10MB��
//�÷���ֻ�����ڸ�ֻ��һ���������ŵ�Ŀ��IP��Ӧ��IP
extern "C" __declspec(dllexport)
int SendBlockToIP (const int iSlotType, char* strDestIP,  int iLen, BYTE* pbyData, int& iRespLen, BYTE* pbyResp,  const int iAppEntityNo = 0);


//���������ļ�
//������
//iSlotType���������������������
//iSendFootNo����������������������
//strFileName��������������������ļ���
//iAppEntityNo����������������ߵ�Ӧ��ʵ��š��ò������ڵ���EXE����Ķ������ֱ�ʹ��������ߵĳ��ϣ��������ϲ���ָ���ò�����δָ�����������ʱȡĬ��ֵ0�������ݽ�������Ϊ��һ��ע���Ӧ��ʵ�塣
//����ֵ��1�����ͳɹ���<0������ʧ�ܣ�����ֵΪ������롣��������б�μ���¼1��
extern "C" __declspec(dllexport)
int SendFile(const int iSlotType,  const int iSendFootNo, char* strFileName,  const int iAppEntityNo = 0);

//2.5�����ӿڣ����Ϳ����ļ�
extern "C" __declspec(dllexport)
int SendCtrlFile(const int iSlotType,  const int iSendFootNo, char* strFileName, int& iRespLen, BYTE* pbyResp,  const int iAppEntityNo = 0);

//���������ļ���IP��ַ
//������
//iSlotType���������������������
//strDestIP��������������շ�IP��ַ
//strFileName��������������������ļ���
//iAppEntityNo����������������ߵ�Ӧ��ʵ��š��ò������ڵ���EXE����Ķ������ֱ�ʹ��������ߵĳ��ϣ��������ϲ���ָ���ò�����δָ�����������ʱȡĬ��ֵ0�������ݽ�������Ϊ��һ��ע���Ӧ��ʵ�塣
//����ֵ��
//1�����ͳɹ���
//<0������ʧ�ܣ�����ֵΪ������롣��������б�μ���¼1��
extern "C" __declspec(dllexport)
int SendFileToIP(const int iSlotType, const char* strDestIP,  char* strFileName,  const int iAppEntityNo = 0);


//Ӧ���������
//������
//stDataIdent������������������ݵı�ʶ����ȡ��������ʱ���ص����ݱ�ʶ�ṹ��
//iBufLen�������������ʾ�������ݴ�С����λΪ�ֽڡ�
//pbyBuf������������������ݻ���������ռ�������������ά�������ֵ�����������(1).����ɹ���ȡ�������ݣ����ֵ�Ǹÿ����ݣ�(2).����ɹ���ȡ�������ļ������ֵ�����ļ�����
//����ֵ��
//1�����ͳɹ���
//<0������ʧ�ܣ�����ֵΪ������롣��������б�μ���¼1��
extern "C" __declspec(dllexport)
int ReplyControl(BUSDATAIDENT stDataIdent,  int iBufLen,  BYTE* pbyBuf);



//������
//stDataIdent��������������ݱ�ʶ
//iBufLen�������������������ֵ��ʾ�������ݻ�������С����λΪ�ֽڡ����ֵ����������� (1).����ɹ���ȡ�������ݣ����ֵ�Ǹÿ������ֽ�����(2).����ɹ���ȡ�������ļ������ֵ�����ļ������ȣ���λΪ�ֽڣ�(3). �������ݻ�����pbyBuf�ռ䲻��ʱ�����ֵ����Ҫ����С��������С����λΪ�ֽڡ�
//pbyBuf������������������ݻ���������ռ�������������ά�������ֵ�����������(1).����ɹ���ȡ�������ݣ����ֵ�Ǹÿ����ݣ�(2).����ɹ���ȡ�������ļ������ֵ�����ļ�����
//iAppEntityNo����������������ߵ�Ӧ��ʵ��š��ò������ڵ���EXE����Ķ������ֱ�ʹ��������ߵĳ��ϣ��������ϲ���ָ���ò�����δָ�����������ʱȡĬ��ֵ0�������ݽ�������Ϊ��һ��ע���Ӧ��ʵ�塣
//����ֵ��
//>0����ȡ�������ֽڣ�
//0����������
//<0����ȡʧ�ܣ�����ֵΪ������롣��������б�μ���¼1��
//˵�������������ʽΪ�ļ������ļ�������������ά����
extern "C" __declspec(dllexport)
int ReadData(BUSDATAIDENT& stDataIdent,  int& iBufLen,  BYTE* pbyBuf,  const int iAppEntityNo = 0);


//ע������
//iAppEntityNo����������������ߵ�Ӧ��ʵ��š��ò������ڵ���EXE����Ķ������ֱ�ʹ��������ߵĳ��ϣ��������ϲ���ָ���ò�����δָ�����������ʱȡĬ��ֵ0�������ݽ�������Ϊ��һ��ע���Ӧ��ʵ�塣
extern "C" __declspec(dllexport)
bool ReleaseBus(const int iAppEntityNo= 0);


//������
//iAppEntityNo����������������ߵ�Ӧ��ʵ��š��ò������ڵ���EXE����Ķ������ֱ�ʹ��������ߵĳ��ϣ��������ϲ���ָ���ò�����δָ�����������ʱȡĬ��ֵ0�������ݽ�������Ϊ��һ��ע���Ӧ��ʵ�塣
//����ֵ��
//>0��������߿��ύ���쳣������
//=0�����쳣��
extern "C" __declspec(dllexport)
int  GetErrorNum(const int iAppEntityNo= 0);


//������
//iNum�������������������ֵ��ʾ����pstErrMes�Ĵ�С��BUSERRMES���������ֵ��ʾ������ߴ���������
//pstErrMes�����������������ߴ�����ռ��ɵ�����ά����
//iAppEntityNo����������������ߵ�Ӧ��ʵ��š��ò������ڵ���EXE����Ķ������ֱ�ʹ��������ߵĳ��ϣ��������ϲ���ָ���ò�����δָ�����������ʱȡĬ��ֵ0�������ݽ�������Ϊ��һ��ע���Ӧ��ʵ�塣
//����ֵ��
//>0����ȡ���Ĵ�������
//=0���޴���
//˵����
//���������ߵ�ʵ�ʴ����������������iNum�����ε���ֻ����iNum����ֵ�����Ĵ��������Ҫ�������д���ֻ������pstErrMes��С�ٴε��á�
extern "C" __declspec(dllexport)
int  GetErrorMes(int &iNum, BUSERRMES* pstErrMes,  const int iAppEntityNo= 0);

//�������ݿ���ⲿSocket����JXC01�������У�
//�������ݿ���ⲿ�豸��δʹ��������ߵ�Ӧ�ó����ơ��ⲿ�豸������ �������ͨ��windows socket�ӿ����ⲿ�豸ͨ�ţ��ⲿ�豸��ΪSocketͨ�ŷ������ˣ����������Ϊ�ͻ��ˡ�
//������
//strExtIP������������ⲿ�豸��IP��ַ��
//uiExtPort������������ⲿ�豸��Winsock�˿ںš�
//iLen������������������ݿ�pbyData���ȣ���λΪ�ֽڡ�
//pbyData������������������ݿ顣��ռ��ɵ�����ά����
//iAppEntityNo����������������ߵ�Ӧ��ʵ��š��ò������ڵ���EXE����Ķ������ֱ�ʹ��������ߵĳ��ϣ��������ϲ���ָ���ò�����δָ�����������ʱȡĬ��ֵ0�������ݽ�������Ϊ��һ��ע���Ӧ��ʵ�塣
//����ֵ��
//1�����ͳɹ���
//<0������ʧ�ܣ�����ֵΪ������롣��������б�μ���¼1��
extern "C" __declspec(dllexport)
int SendBlockExt(char* strExtIP,  unsigned int uiExtPort,  int iLen, BYTE* pbyData, const int iAppEntityNo = 0);

//���ÿ��Ƴ�ʱʱ����
//������
//iMilliSeconds�������������ʱʱ��������λ�����룩��
//iAppEntityNo����������������ߵ�Ӧ��ʵ��š��ò������ڵ���EXE����Ķ������ֱ�ʹ��������ߵĳ��ϣ��������ϲ���ָ���ò�����δָ�����������ʱȡĬ��ֵ0�������ݽ�������Ϊ��һ��ע���Ӧ��ʵ�塣
//����ֵ��
//��
//˵����
//���û���ô˷������ó�ʱʱ��������ʱʱ����Ĭ��Ϊ10000����(10��)��
extern "C" __declspec(dllexport)
void SetCtrlTimeOut(const int iMilliSeconds, const int iAppEntityNo = 0);


//��ȡ��������IP
//��������
//����ֵ���ַ�����ʽ������IP��ַ��δע��ɹ�ʱ����"0.0.0.0"
extern "C" __declspec(dllexport)
char* GetLocalBusIP(const int iAppEntityNo = 0);

#define  SUCCESS				(1)			//�����ɹ�
#define  PARAM_ERROR			(-1)		//��������
#define  PTR_INVALID			(-2)		//ָ����Ч
#define  BUSCORE_LOAD_INVALID	(-3)		//���ߺ��Ŀ������Ч

#define  BUSCONTROLLERFAILED	(-1000)		//���߿�����ʧЧ
#define  APPENTITYNOERROR		(-1001)		//Ӧ��ʵ��Ŵ���
#define  APPENTITYNOERROR		(-1001)		//Ӧ��ʵ��Ŵ���
#define  SLOTNUMERROR			(-1002)		//�����������
#define  SLOTTYPEERROR			(-1003)		//������������Ч
#define  FOOTNUMERROR			(-1004)		//������������
#define  FOOTNOERROR			(-1005)		//������Ŵ���
#define  FOOTTYPEERROR			(-1006)		//�������������Ч
#define  FOOTPRIERROR			(-1007)		//�������ȼ���Ч
#define	 FOOT_NOT_EXIST			(-1008)		//ָ��IP����,���Ų�����
#define  DATA_TYPE_ERROR		(-1009)		//������ʽ���粻�ܷ����ļ����ⲿSocket����,�ڿ��Ʋ���Ϸ����ļ���

#define  BUSBUFFERFULL			(-1101)		//������߽��ջ�������
#define  BUFFERINSUFFICIENT		(-1102)		//�������ռ䲻��
#define  CONTROLTIMEOUT			(-1103)		//�������ʱ��Ӧ��
#define  FILE_SIZE_INVALID		(-1104)		//�����ļ���С��Ч��4G����
#define  ACCESSFILEERROR		(-1105)		//���������ļ�ʧ��

#define  BUS_ENV_INVALID		(-1200)		//���߻���ʧЧ
#define  ALREADY_REG			(-1201)		//�ظ�ע������
#define	 STARTRECEIVERFAILED	(-1202)		//��������ʧ��
#define  START_THRD_FAILD		(-1203)		//�����߳�ʧ��
#define  CONN_RECV_FULL			(-1204)		//��������������
#define  REG_INS_FULL			(-1205)		//ע��ʵ������

#define  READ_BUSSYSFILE_ERROR	(-1300)		//��ȡ����ϵͳ�����ļ�����
#define  BUSCTRL_PARAM_ERR		(-1301)		//���߿������ò�������
#define  BUSCTRL_REPLY_ERR		(-1302)		//���߿��ƻظ���Ϣ����
#define  BUSCTRL_APP_NOTEXIST	(-1303)		//���߿������Ҳ���Ӧ��
#define  BUS_LISTEN_PORT_ERR	(-1304)		//����TCP�����˿ڴ���
#define  BUS_UDP_PORT_ERR		(-1305)		//����UDP�˿ڴ���
#define  SOCK_LISTEN_PORT_ERR	(-1306)		//SOCKET�����˿ڴ���
#define  DEST_TYPE_ERR			(-1310)		//Ŀ�����ʹ���
#define  DEST_REL_ERR			(-1311)		//Ŀ�Ĺ�ϵ���ʹ���
#define  DEST_NUM_ERR			(-1312)		//Ŀ����������
#define  DEST_PORT_ERR			(-1313)		//Ŀ�Ķ˿ڴ���

#define  DESTHOSTFAILED			(-2001)		//Ŀ������PING��ͨ
#define  DESTAPPFAILED			(-2002)		//Ŀ��Ӧ�ó���ʧЧ
#define  NOENOUGHMEMORY			(-2003)		//�ڴ�ռ䲻��

#define  CREATESIGNALFAILED		(-2003)		//�����ź���ʧ��



#endif

