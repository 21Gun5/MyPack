#pragma once
#include <windows.h>

//�ض�λ��ṹ��
struct TypeOffset
{
	WORD Offset : 12;
	WORD Type : 4;
};

// �������ݽṹ��
typedef struct _SHAREDATA
{
	long origOEP = 0;// ԭʼOEP
	long rva = 0;// ������λ�õ�RVA
	long size = 0;// ���ܵĴ�С
	BYTE key = 0;// ����ʱ��Կ
} SHAREDATA, *PSHAREDATA;

class MyPack
{
private:
	DWORD m_fileSize = 0;// �ļ���С,�����ڴ�/�����ļ�ʱ���õ�
	DWORD m_fileBase = 0;// �ļ�����ַ; DWORD��Ϊ�˼��㷽��
	DWORD m_dllBase = 0;// dll �ļ��ػ�ַ/ģ����
	DWORD m_startOffset = 0;// start �����Ķ���ƫ��,���ڼ�����OEP
	PSHAREDATA m_pShareData = NULL;// ���干������,��Ǵ���dll�ṩ��Ϣ(�Թ������ݵĲ�����Ҫд�ڿ�������֮ǰ)
private:
	// ���ߺ���,���ڻ�ȡPEͷ�����Ϣ
	PIMAGE_DOS_HEADER GetDosHeader(DWORD fileBase);
	PIMAGE_NT_HEADERS GetNtHeader(DWORD fileBase);
	PIMAGE_FILE_HEADER GetFileHeader(DWORD fileBase);
	PIMAGE_OPTIONAL_HEADER GetOptHeader(DWORD fileBase);
	// ����: ��size����n�����ڴ�/�ļ�����,���ض����Ĵ�С
	DWORD Align(DWORD size, DWORD n);

public:
	void LoadFile(LPCSTR fileName);// ��ȡԴ�ļ����ڴ�
	void LoadStub(LPCSTR fileName);// ��ȡ�Ǵ���dll���ڴ�
	void CopySection(LPCSTR dstSectionName, LPCSTR srcSectionName);// ���߸��Ƶ�ǰ��,ʵ�����������
	void SaveFile(LPCSTR fileName);// ������ļ�
	PIMAGE_SECTION_HEADER GetSection(DWORD fileBase, LPCSTR sectionName);// ��ȡ����ͷ��Ϣ(����ͷ�ṹ��
	void SetOEP();// ��������OEP
	void CopySectionData(LPCSTR dstSectionName, LPCSTR srcSectionName);// ��������������(���߿�����ǰ��
	void FixDllReloc();// �޸�dll�Ǵ�����Ҫ�ض�λ�ĵط�
	void EncodeSection(LPCSTR sectionName);// ��������(������
};