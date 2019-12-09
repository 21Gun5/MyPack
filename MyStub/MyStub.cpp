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
	long originalOEP = 0;//原始OEP
}SHAREDATA, PSHAREDATA;

extern "C"
{
	// 3 导出一个变量,用于接收数据(数据在.data段,会合并到.text中,整体复制到新区段
	__declspec(dllexport) SHAREDATA shareData;
	// 4 提供一个函数,作为源程序的新OEP(没有名称粉碎/导出/裸函数)
	__declspec(dllexport) __declspec(naked) void start()
	{
		__asm
		{
			mov ebx, dword ptr fs : [0x30];	// 获取PEB
			mov ebx, dword ptr[ebx + 0x08];	// 获取加载基址ImageBase
			add ebx, shareData.originalOEP;		// RVA+基址= 原始OEP
			jmp ebx;						// 跳转原始OEP
		}
	}
}