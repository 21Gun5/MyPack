#pragma once
#include <windows.h>

typedef struct _SHAREDATE
{
	DWORD srcOep;		//��ڵ�
	DWORD textScnRVA;	//�����RVA
	DWORD textScnSize;	//����εĴ�С
			
	unsigned char key[16] ={};//������Կ
	int index = 0;			  //���ܵ��������� �õ�ʱ����Ҫ-1
	int data[20][2];  //���ܵ�����RVA��Size	

	DWORD dwDataDir[20][2];  //����Ŀ¼���RVA��Size	
	DWORD dwNumOfDataDir;	//����Ŀ¼��ĸ���


	DWORD oep;
	DWORD nImportVirtual;
	DWORD nImportSize;
	DWORD nRelocVirtual;
	DWORD nRelocSize;
	DWORD nResourceVirtual;
	DWORD nResourceSize;
	DWORD nTlsVirtual;
	DWORD nTlsSize;


}SHAREDATE;

//����stub.dll��Ϣ�Ľṹ��
struct StubInfo
{
	char* dllbase;			//stub.dll�ļ��ػ�ַ
	DWORD pfnStart;			//stub.dll(start)���������ĵ�ַ
	SHAREDATE* pStubConf;	//stub.dll(g_conf)����ȫ�ֱ����ĵ�ַ		
};