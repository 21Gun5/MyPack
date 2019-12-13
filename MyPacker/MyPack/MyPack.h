#pragma once
#include <windows.h>

// 共享数据结构体
typedef struct _SHAREDATA
{
	long OldOep = 0;// 原始 oep
	long rva = 0;// 加密的rva
	long size = 0;// 加密的大小
	BYTE key = 0;// 加密的 key
	long oldRelocRva = 0;// 原始重定位表位置
	long oldImageBase = 0;// 原始加载基址

	DWORD FrontCompressRva;//0
	DWORD FrontCompressSize;//1
	DWORD LaterCompressSize;//2

	unsigned char key1[16] = {};//AES解密密钥
	int index = 0;			  //加密的区段数量 用的时候需要-1
	int data[20][2];  //加密的区段RVA和Size	

	int index2 = 0;			  //加密的区段数量 用的时候需要-1
	int data2[20][2];  //加密的区段RVA和Size	


	DWORD dwDataDir[20][3];  //数据目录表的RVA和Size	
	DWORD dwNumOfDataDir;	//数据目录表的个数

	long ImportRva;

	DWORD TlsCallbackFuncRva;
	bool bIsTlsUseful;

} SHAREDATA, *PSHAREDATA;

// 重定位项结构体
struct TypeOffset
{
	WORD Offset : 12;
	WORD Type : 4;
};

class MyPack
{
private:
	DWORD FileSize = 0;// 文件大小,申请内存/保存文件时会用到
	DWORD FileBase = 0;// 文件基地址; DWORD是为了计算方便
	DWORD DllBase = 0;// dll 的加载基址/模块句柄
	DWORD StartOffset = 0;// start 函数的段内偏移,用于计算新OEP
	PSHAREDATA ShareData = nullptr;// 定义共享数据,向壳代码dll提供信息(对共享数据的操作都要写在拷贝区段之前)
private:
	// 工具函数,用于获取PE头相关信息
	PIMAGE_DOS_HEADER DosHeader(DWORD Base);
	PIMAGE_NT_HEADERS NtHeader(DWORD Base);
	PIMAGE_FILE_HEADER FileHeader(DWORD Base);
	PIMAGE_OPTIONAL_HEADER OptHeader(DWORD Base);
	DWORD Alignment(DWORD n, DWORD align);// 文件/内存对齐
	PIMAGE_SECTION_HEADER GetSection(DWORD Base, LPCSTR SectionName);// 获取区段头信息
public:
	VOID LoadExeFile(LPCSTR FileName);// 读取目标程序
	VOID LoadDllStub(LPCSTR FileName);// 读取壳代码
	VOID XorSection(LPCSTR SectionName);// 加密区段
	void ClearDataDirTab();// 清除数据目录表信息
	VOID AddSection(LPCSTR SectionName, LPCSTR SrcName);//添加新区段
	VOID FixReloc();// 修复壳重定位
	VOID FixReloc2();// 修正壳代码的重定位表  (VirtualAddress) 
	VOID SetRelocTable();// 修改目标程序数据目标表，重定位表的位置到新重定位表（.stu_re）
	VOID SetOEP();// 重新设置OEP
	VOID CopySectionData(LPCSTR SectionName, LPCSTR SrcName);// 设置新区段内容(后者拷贝至前者
	VOID SaveFile(LPCSTR FileName);// 另存新文件
	bool CompressSection(char * SectionName);// 压缩区段
	VOID SetClearImport();// 操作导入表	
	void EncryptAllSection();// AES加密所有区段
};

