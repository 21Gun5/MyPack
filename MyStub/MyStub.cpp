// MyStub.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"

// 0 提供壳代码的Stub部分,通常用于:解压缩/解密'修复重定位表'修复/加密IAT表'调用TLS函数等

// 1 将.data .rdata 合并到 .text 区段,并设置读 写 可执行属性(合三为一,减少依赖,方便拷贝
#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
#pragma comment(linker,"/section:.text,RWE")

// 2 提供一个函数,作为源程序的新OEP(没有名称粉碎'导出'裸函数)
extern "C" __declspec(dllexport) __declspec(naked) void start()
{
	__asm
	{
		mov eax, eax;
		mov eax, eax;
		mov eax, eax;
	}
}