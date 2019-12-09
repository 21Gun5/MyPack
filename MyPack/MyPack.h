#pragma once
#include <windows.h>

class MyPack
{
private:
	DWORD m_fileSize = 0;//文件大小,申请内存/保存文件时会用到
	DWORD m_fileBase = 0;//文件基地址; DWORD是为了计算方便
private:
	// 工具函数,用于获取PE头相关信息
	PIMAGE_DOS_HEADER GetDosHeader(DWORD fileBase);
	PIMAGE_NT_HEADERS GetNtHeader(DWORD fileBase);
	PIMAGE_FILE_HEADER GetFileHeader(DWORD fileBase);
	PIMAGE_OPTIONAL_HEADER GetOptHeader(DWORD fileBase);
	// 对齐: 将size按照n进行内存/文件对齐,返回对齐后的大小
	DWORD Align(DWORD size, DWORD n);

public:
	void LoadFile(LPCSTR fileName);// 读取PE文件到内存
	void AddSection(LPCSTR sectionName);// 添加新区段
	void SaveFile(LPCSTR fileName);// 另存新文件
};