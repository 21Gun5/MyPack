#pragma once
#include <windows.h>

class MyPack
{
private:
	DWORD m_fileSize = 0;//�ļ���С,�����ڴ�/�����ļ�ʱ���õ�
	DWORD m_fileBase = 0;//�ļ�����ַ; DWORD��Ϊ�˼��㷽��
private:
	// ���ߺ���,���ڻ�ȡPEͷ�����Ϣ
	PIMAGE_DOS_HEADER GetDosHeader(DWORD fileBase);
	PIMAGE_NT_HEADERS GetNtHeader(DWORD fileBase);
	PIMAGE_FILE_HEADER GetFileHeader(DWORD fileBase);
	PIMAGE_OPTIONAL_HEADER GetOptHeader(DWORD fileBase);
	// ����: ��size����n�����ڴ�/�ļ�����,���ض����Ĵ�С
	DWORD Align(DWORD size, DWORD n);

public:
	void LoadFile(LPCSTR fileName);// ��ȡPE�ļ����ڴ�
	void AddSection(LPCSTR sectionName);// ���������
	void SaveFile(LPCSTR fileName);// ������ļ�
};