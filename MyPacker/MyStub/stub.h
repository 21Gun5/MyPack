#pragma once
#include <windows.h>

// �������ݽṹ��
typedef struct _SHAREDATA
{
	long OldOep = 0;// ԭʼ oep
	long rva = 0;// ���ܵ�rva
	long size = 0;// ���ܵĴ�С
	BYTE key = 0;// ���ܵ� key
	long oldRelocRva = 0;// ԭʼ�ض�λ��λ��
	long oldImageBase = 0;// ԭʼ���ػ�ַ

	DWORD FrontCompressRva;//0
	DWORD FrontCompressSize;//1
	DWORD LaterCompressSize;//2

	unsigned char key1[16] = {};//������Կ
	int index = 0;			  //���ܵ��������� �õ�ʱ����Ҫ-1
	int data[20][2];  //���ܵ�����RVA��Size	

	int index2 = 0;			  //���ܵ��������� �õ�ʱ����Ҫ-1
	int data2[20][3];  //���ܵ�����RVA��Size

	DWORD dwDataDir[20][2];  //����Ŀ¼���RVA��Size	
	DWORD dwNumOfDataDir;	//����Ŀ¼��ĸ���

	long ImportRva;


	DWORD TlsCallbackFuncRva;
	bool bIsTlsUseful;

} SHAREDATA, *PSHAREDATA;

// �ض�λ��ṹ��
struct TypeOffset
{
	WORD Offset : 12;
	WORD Type : 4;
};

// ����ȫ�ֺ�������
#define DefApiFun(name)\
	decltype(name)* My_##name = NULL;

// ��ȡָ��API
#define GetApiFun(mod,name)\
	decltype(name)* My_##name = (decltype(name)*)My_GetProcAddress(mod,#name)

// ��ȡָ��API
#define SetAPI(mod,name)\
		My_##name = (decltype(name)*)MyGetProcAddress(mod,#name)