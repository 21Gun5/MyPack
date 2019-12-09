#pragma once
#include <windows.h>

//重定位项结构体
struct TypeOffset
{
	WORD Offset : 12;
	WORD Type : 4;
};

// 共享数据结构体
typedef struct _SHAREDATA
{
	long originalOEP = 0;// 原始OEP
} SHAREDATA, *PSHAREDATA;

class MyPack
{
private:
	DWORD m_fileSize = 0;// 文件大小,申请内存/保存文件时会用到
	DWORD m_fileBase = 0;// 文件基地址; DWORD是为了计算方便
	DWORD m_dllBase = 0;// dll 的加载基址/模块句柄
	DWORD m_startOffset = 0;// start 函数的段内偏移,用于计算新OEP
	PSHAREDATA m_pShareData = NULL;// 定义共享数据,向壳代码dll提供信息
private:
	// 工具函数,用于获取PE头相关信息
	PIMAGE_DOS_HEADER GetDosHeader(DWORD fileBase);
	PIMAGE_NT_HEADERS GetNtHeader(DWORD fileBase);
	PIMAGE_FILE_HEADER GetFileHeader(DWORD fileBase);
	PIMAGE_OPTIONAL_HEADER GetOptHeader(DWORD fileBase);
	// 对齐: 将size按照n进行内存/文件对齐,返回对齐后的大小
	DWORD Align(DWORD size, DWORD n);

public:
	void LoadFile(LPCSTR fileName);// 读取源文件到内存
	void LoadStub(LPCSTR fileName);// 读取壳代码dll到内存
	void CopySection(LPCSTR dstSectionName, LPCSTR srcSectionName);// 后者复制到前者,实现添加新区段
	void SaveFile(LPCSTR fileName);// 另存新文件
	PIMAGE_SECTION_HEADER GetSection(DWORD fileBase, LPCSTR sectionName);// 获取区段头信息(区段头结构体
	void SetOEP();// 重新设置OEP
	void CopySectionData(LPCSTR dstSectionName, LPCSTR srcSectionName);// 设置新区段内容(后者拷贝至前者
	void FixDllReloc();
};