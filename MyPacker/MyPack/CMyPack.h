#pragma once
#include <windows.h>

// �������ݽṹ��
typedef struct _SHAREDATE
{
	DWORD srcOep;		//��ڵ�
	DWORD textScnRVA;	//�����RVA
	DWORD textScnSize;	//����εĴ�С
	unsigned char key[16] = {};//������Կ
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
}SHAREDATE, *PSHAREDATA;

class CMyPack
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
public:
	void LoadFile(LPCSTR fileName);// ��ȡԴ�ļ����ڴ�
	void LoadStub1(LPCSTR fileName);// ��ȡ�Ǵ���dll���ڴ�
	PIMAGE_SECTION_HEADER GetSection(DWORD fileBase, LPCSTR sectionName);// ��ȡ����ͷ��Ϣ(����ͷ�ṹ��
	void SetOEP();// ��������OEP
	void CopySectionData(LPCSTR dstSectionName, LPCSTR srcSectionName);// ��������������(���߿�����ǰ��
	void SaveFile(LPCSTR fileName);// ������ļ�
	void CancelRandomBase();
	void AddSection(LPCSTR dstSectionName, LPCSTR srcSectionName);//���һ��������
	IMAGE_SECTION_HEADER* GetLastSection();//��ȡ���һ������
	int AlignMent(_In_ int size,_In_ int alignment);//��������Ĵ�С
	void Encrypt();//����Ŀ��������������
	void ClearDataDir();//�������Ŀ¼��
	void FixStubRelocation();//�޸��ض�λ
};

