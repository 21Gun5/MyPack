// MyStub.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"

// 0 提供壳代码的Stub部分,通常用于:解压缩/解密'修复重定位表'修复/加密IAT表'调用TLS函数等

// 1 将.data .rdata 合并到 .text 区段,并设置读 写 可执行属性(合三为一,减少依赖,方便拷贝
#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
#pragma comment(linker,"/section:.text,RWE")

// 2 用于共享数据的结构体
typedef struct _SHAREDATA
{
	long origOEP = 0;//原始OEP
	long rva = 0;// 待加密位置的RVA
	long size = 0;// 加密的大小
	BYTE key = 0;// 加密时密钥
}SHAREDATA, PSHAREDATA;

// 3 PVirtualProtect的函数指针
typedef BOOL(WINAPI* PVirtualProtect)(_In_ LPVOID lpAddress,_In_ SIZE_T dwSize,_In_ DWORD flNewProtect,_Out_ PDWORD lpflOldProtect);
PVirtualProtect pVirtualProtect;

extern "C"
{
	// 4 导出一个变量,用于接收数据(数据在.data段,会合并到.text中,整体复制到新区段
	__declspec(dllexport) SHAREDATA shareData;
	// 5 自定义获取函数地址的函数
	DWORD MyGetProcAddress(DWORD Module, LPCSTR funcName)
	{
		// 5.1 获取DOS头 NT头
		auto DosHeader = (PIMAGE_DOS_HEADER)Module;
		auto NtHeader = (PIMAGE_NT_HEADERS)(Module + DosHeader->e_lfanew);
		// 5.2 获取导出表
		DWORD ExportRva = NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
		auto ExportTable = (PIMAGE_EXPORT_DIRECTORY)(Module + ExportRva);
		// 5.2=3 获取ENT EOT EAT
		auto ENT = (DWORD*)(ExportTable->AddressOfNames + Module);
		auto EAT = (DWORD*)(ExportTable->AddressOfFunctions + Module);
		auto EOT = (WORD*)(ExportTable->AddressOfNameOrdinals + Module);
		// 5.4 遍历ENT
		for (DWORD i = 0; i < ExportTable->NumberOfNames; ++i)
		{
			// 5.5 根据函数名称找地址(三表关系
			char* name = (char*)(ENT[i] + Module);
			if (!strcmp(name, funcName))
				return EAT[EOT[i]] + Module;
		}
		return -1;
	}
	// 6 获取kernel32.dll基址
	__declspec(naked) long GetKernelBase()
	{
		__asm
		{
			// 按照加载顺序
			mov eax, dword ptr fs : [0x30]
			mov eax, dword ptr[eax + 0x0C]
			mov eax, dword ptr[eax + 0x0C]
			mov eax, dword ptr[eax]
			mov eax, dword ptr[eax]
			mov eax, dword ptr[eax + 0x18]
			ret
		}
	}
	// 7 解密区段
	long DecodeSection()
	{
		// 7.1 获取待解密区段的起始位置
		DWORD oldProtect;
		__asm
		{
			mov ebx, dword ptr fs : [0x30];	// 获取PEB
			mov ebx, dword ptr[ebx + 0x08];	// 获取加载基址ImageBase
			add shareData.rva, ebx;// RVA+基址= 区段VA(执行后,名rva实va
		}
		// 7.2 解密前先修改其访问属性(可写
		pVirtualProtect((LPVOID)shareData.rva, shareData.size, PAGE_READWRITE, &oldProtect);
		// 7.3 循环,逐位解密
		for (int i = 0; i < shareData.size; ++i)
		{
			((BYTE*)shareData.rva)[i] ^= shareData.key;
		}
		// 7.4 解密写入后,将属性恢复
		pVirtualProtect((LPVOID)shareData.rva, shareData.size, oldProtect, &oldProtect);
	}
	// 8 跳转至原始OEP
	__declspec(naked) long JmpOEP()
	{
		__asm
		{
			mov ebx, dword ptr fs : [0x30];	// 获取PEB
			mov ebx, dword ptr[ebx + 0x08];	// 获取加载基址ImageBase
			add ebx, shareData.origOEP;		// RVA+基址= 原始OEP
			jmp ebx;						// 跳转原始OEP
		}
	}
	// 9 获取任意api地址
	void GetAPIAddr()
	{
		pVirtualProtect = (PVirtualProtect)MyGetProcAddress(GetKernelBase(), "VirtualProtect");
	}
	// 10 壳代码起始函数(没有名称粉碎/导出/裸函数)
	__declspec(dllexport) __declspec(naked) void start()
	{
		// 10.1 运行前先获取必要的api
		GetAPIAddr();
		// 10.2 解密/解压缩区段
		DecodeSection();
		// 10.3 所有壳代码执行完毕,跳往真实OEP
		JmpOEP();
	}
}