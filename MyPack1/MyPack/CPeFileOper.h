#pragma once
#include <windows.h>
#include "data.h"

class CPeFileOper
{
public:
	CPeFileOper();
	~CPeFileOper();
	//��ȡ�ļ���С������
	char* GetFileData(_In_ const char* pFilePath, _Out_opt_ int* nFileSize = NULL);

	//�򿪴����е�һ��PE�ļ�
	HANDLE OpenPeFile(_In_ const char* path);

	//���һ��������
	void AddSection(char*& pFileBuff,int& fileSize,const char* scnName,int scnSize);

	//��ȡ�ļ�ͷ
	IMAGE_FILE_HEADER* GetFileHead(_In_  char* pFileData);

	//��ȡNtͷ
	IMAGE_NT_HEADERS* GetNtHeader(_In_ char* pFileData);

	//��ȡDosͷ
	IMAGE_DOS_HEADER* GetDosHeader(_In_ char* pFileData);

	//��ȡ��ѡͷ
	IMAGE_OPTIONAL_HEADER* GetOptionHeader(_In_ char* pFileData);

	//��ȡ���һ������
	IMAGE_SECTION_HEADER* GetLastSection(_In_ char* pFileData);

	//��������Ĵ�С
	int AlignMent(_In_ int size,_In_ int alignment);

	//��ȡָ�����ֵ�����ͷ
	IMAGE_SECTION_HEADER* GetSection(_In_ char* pFileData,_In_ const char* scnName);

	//���汻�ӿǵĳ���
	BOOL SavePEFile(_In_ const char* pFileData,_In_ int size, _In_ const char*path);

	//����stub.dll
	void LoadStub(StubInfo* pStub);

	//����Ŀ��������������
	void Encrypt(_In_ char* pFileData, _In_  StubInfo pStub);

	//�������Ŀ¼��
	void ClearDataDir(_In_ char* pFileData, _In_  StubInfo pStub);

	//�޸��ض�λ
	void FixStubRelocation(DWORD stubDllbase,DWORD stubTextRva,DWORD targetDllbase,DWORD targetNewScnRva);
};

