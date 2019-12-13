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

	unsigned char key1[16] = {};//AES������Կ
	int index = 0;			  //���ܵ��������� �õ�ʱ����Ҫ-1
	int data[20][2];  //���ܵ�����RVA��Size	

	int index2 = 0;			  //���ܵ��������� �õ�ʱ����Ҫ-1
	int data2[20][2];  //���ܵ�����RVA��Size	


	DWORD dwDataDir[20][3];  //����Ŀ¼���RVA��Size	
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

class MyPack
{
private:
	DWORD FileSize = 0;// �ļ���С,�����ڴ�/�����ļ�ʱ���õ�
	DWORD FileBase = 0;// �ļ�����ַ; DWORD��Ϊ�˼��㷽��
	DWORD DllBase = 0;// dll �ļ��ػ�ַ/ģ����
	DWORD StartOffset = 0;// start �����Ķ���ƫ��,���ڼ�����OEP
	PSHAREDATA ShareData = nullptr;// ���干������,��Ǵ���dll�ṩ��Ϣ(�Թ������ݵĲ�����Ҫд�ڿ�������֮ǰ)
private:
	// ���ߺ���,���ڻ�ȡPEͷ�����Ϣ
	PIMAGE_DOS_HEADER DosHeader(DWORD Base);
	PIMAGE_NT_HEADERS NtHeader(DWORD Base);
	PIMAGE_FILE_HEADER FileHeader(DWORD Base);
	PIMAGE_OPTIONAL_HEADER OptHeader(DWORD Base);
	DWORD Alignment(DWORD n, DWORD align);// �ļ�/�ڴ����
	PIMAGE_SECTION_HEADER GetSection(DWORD Base, LPCSTR SectionName);// ��ȡ����ͷ��Ϣ
public:
	VOID LoadExeFile(LPCSTR FileName);// ��ȡĿ�����
	VOID LoadDllStub(LPCSTR FileName);// ��ȡ�Ǵ���
	VOID XorSection(LPCSTR SectionName);// ��������
	void ClearDataDirTab();// �������Ŀ¼����Ϣ
	VOID AddSection(LPCSTR SectionName, LPCSTR SrcName);//���������
	VOID FixReloc();// �޸����ض�λ
	VOID FixReloc2();// �����Ǵ�����ض�λ��  (VirtualAddress) 
	VOID SetRelocTable();// �޸�Ŀ���������Ŀ����ض�λ���λ�õ����ض�λ��.stu_re��
	VOID SetOEP();// ��������OEP
	VOID CopySectionData(LPCSTR SectionName, LPCSTR SrcName);// ��������������(���߿�����ǰ��
	VOID SaveFile(LPCSTR FileName);// ������ļ�
	bool CompressSection(char * SectionName);// ѹ������
	VOID SetClearImport();// ���������	
	void EncryptAllSection();// AES������������
};

