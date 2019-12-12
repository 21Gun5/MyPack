#pragma once
#include <windows.h>

// 共享数据结构体
typedef struct _SHAREDATE
{
	DWORD srcOep;		//入口点
	DWORD textScnRVA;	//代码段RVA
	DWORD textScnSize;	//代码段的大小
	unsigned char key[16] = {};//解密密钥
	int index = 0;			  //加密的区段数量 用的时候需要-1
	int data[20][2];  //加密的区段RVA和Size	
	DWORD dwDataDir[20][2];  //数据目录表的RVA和Size	
	DWORD dwNumOfDataDir;	//数据目录表的个数
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
	DWORD m_fileSize = 0;// 文件大小,申请内存/保存文件时会用到
	DWORD m_fileBase = 0;// 文件基地址; DWORD是为了计算方便
	DWORD m_dllBase = 0;// dll 的加载基址/模块句柄
	DWORD m_startOffset = 0;// start 函数的段内偏移,用于计算新OEP
	PSHAREDATA m_pShareData = NULL;// 定义共享数据,向壳代码dll提供信息(对共享数据的操作都要写在拷贝区段之前)
private:
	// 工具函数,用于获取PE头相关信息
	PIMAGE_DOS_HEADER GetDosHeader(DWORD fileBase);
	PIMAGE_NT_HEADERS GetNtHeader(DWORD fileBase);
	PIMAGE_FILE_HEADER GetFileHeader(DWORD fileBase);
	PIMAGE_OPTIONAL_HEADER GetOptHeader(DWORD fileBase);
public:
	void LoadFile(LPCSTR fileName);// 读取源文件到内存
	void LoadStub1(LPCSTR fileName);// 读取壳代码dll到内存
	PIMAGE_SECTION_HEADER GetSection(DWORD fileBase, LPCSTR sectionName);// 获取区段头信息(区段头结构体
	void SetOEP();// 重新设置OEP
	void CopySectionData(LPCSTR dstSectionName, LPCSTR srcSectionName);// 设置新区段内容(后者拷贝至前者
	void SaveFile(LPCSTR fileName);// 另存新文件
	void CancelRandomBase();
	void AddSection(LPCSTR dstSectionName, LPCSTR srcSectionName);//添加一个新区段
	IMAGE_SECTION_HEADER* GetLastSection();//获取最后一个区段
	int AlignMent(_In_ int size,_In_ int alignment);//计算对齐后的大小
	void Encrypt();//加密目标程序的所有区段
	void ClearDataDir();//清除数据目录表
	void FixStubRelocation();//修复重定位
};

