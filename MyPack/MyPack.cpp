#include "MyPack.h"
 

 // ��ȡPEͷ�����Ϣ
PIMAGE_DOS_HEADER MyPack::GetDosHeader(DWORD fileBase)
{
	return (PIMAGE_DOS_HEADER)fileBase;
}
PIMAGE_NT_HEADERS MyPack::GetNtHeader(DWORD fileBase)
{
	return (PIMAGE_NT_HEADERS)(fileBase +GetDosHeader(fileBase)->e_lfanew);
}
PIMAGE_FILE_HEADER MyPack::GetFileHeader(DWORD fileBase)
{
	return &GetNtHeader(fileBase)->FileHeader;
}
PIMAGE_OPTIONAL_HEADER MyPack::GetOptHeader(DWORD fileBase)
{
	return &GetNtHeader(fileBase)->OptionalHeader;
}

// �����ļ�/�ڴ����
DWORD MyPack::Align(DWORD size, DWORD n)
{
	return size / n == 0 ? n : (size / n + 1)*n;
}

//�����ļ���,���ļ�������ΪPE���
void MyPack::LoadFile(LPCSTR fileName)
{
	// 1 ���ļ����ھʹ�,�򿪽�Ϊ�˶�ȡ�ļ�����
	HANDLE hFile = CreateFileA(fileName, GENERIC_READ, NULL,NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	// 2 ��ȡ�ļ���С,���ô˴�С���뻺����
	m_fileSize = GetFileSize(hFile, NULL);
	m_fileBase = (DWORD)calloc(m_fileSize, sizeof(BYTE));//calloc ���벢��ʼ��
	// 3 ���ļ����ݶ�ȡ��������
	DWORD readSize = 0;// ʵ�ʶ�ȡ�Ĵ�С
	ReadFile(hFile, (LPVOID)m_fileBase, m_fileSize, &readSize, NULL);
	// 4 ��ֹ���й¶,�رվ��
	CloseHandle(hFile);

	return;
}

// ΪPE�ļ����������
void MyPack::AddSection(LPCSTR sectionName)
{
	// 1 ��ȡ���α����һ������ͷ�ĵ�ַ
	auto pLastSection = &IMAGE_FIRST_SECTION(GetNtHeader(m_fileBase))[GetFileHeader(m_fileBase)->NumberOfSections - 1];
	// 2 ����������+1(�ļ�ͷ��
	GetFileHeader(m_fileBase)->NumberOfSections += 1;
	// 3 ͨ�����һ������ͷ,�ҵ����������ͷ��λ��,�����0
	auto pNewSection = pLastSection + 1;
	memset(pNewSection, 0, sizeof(IMAGE_SECTION_HEADER));
	// 4 ����������ͷ���ֶ�:��������
	memcpy(pNewSection->Name, sectionName, 7);// ��memcpy����strcpy; �ܹ�8�ֽ�,����7,Ԥ��һ����\0
	// 5 ����������ͷ���ֶ�:��������
	pNewSection->Characteristics = 0xE00000E0;// ��ʱһ��������/д/ִ��Ȩ��
	// 6 ��������������RVA = ��һ������RVA��+ ��������ڴ��С
	pNewSection->VirtualAddress = pLastSection->VirtualAddress + Align(pLastSection->Misc.VirtualSize, GetOptHeader(m_fileBase)->SectionAlignment);
	// 7 ��������������FOA = ��һ������FOA + ��������ļ���С
	pNewSection->PointerToRawData = pLastSection->PointerToRawData + Align(pLastSection->SizeOfRawData, GetOptHeader(m_fileBase)->FileAlignment);
	// 8 ���������ε��ļ���С���ڴ��С(������ȼ���
	pNewSection->SizeOfRawData = pNewSection->Misc.VirtualSize = 0x200;
	// 9 ���¼����ļ��������С= ���һ������FOA + ���ļ���С,����ԭ�ļ����ݱ�������
	m_fileSize = pNewSection->PointerToRawData + pNewSection->SizeOfRawData;
	m_fileBase = (DWORD)realloc((void *)m_fileBase, m_fileSize);// ֮������allco����new,����Ϊ�˺��������realloc
	// 10 �޸��ļ����ڴ��С = ���һ������RVA + ���ڴ��С
	GetOptHeader(m_fileBase)->SizeOfImage = pNewSection->VirtualAddress + pNewSection->Misc.VirtualSize;
	
	return;
}

// ��������κ���ļ����Ϊ���ļ�
void MyPack::SaveFile(LPCSTR fileName)
{
	// 1 �����ļ�,��ȡ���(д�ļ�/���۴�����������
	HANDLE hFile = CreateFileA(fileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	// 2 ���ڴ��е��ļ�����д�����ļ���
	DWORD writeSize = 0;// ʵ��д���С
	WriteFile(hFile, (LPVOID *)m_fileBase, m_fileSize, &writeSize, NULL);
	// �ر��ļ�����Է�ֹй¶
	CloseHandle(hFile);

	return;
}
