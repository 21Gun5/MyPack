// MyStub.cpp : 定义 DLL 应用程序的导出函数
#include "stdafx.h"
#include "MyStub.h"
#include <windows.h>

// 提供壳代码的Stub部分,通常用于:解压缩/解密'修复重定位表'修复/加密IAT表'调用TLS函数等

// 合并data rdata 到text段, 将text改成可读可写可执行
#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")

// 导出一个全局变量来共享数据
extern "C" __declspec(dllexport)SHAREDATA shareData = { 0 };

// 密码框相关变量(函数外定义,全局化
HINSTANCE g_hInstance;	//窗口实例句柄
HWND hEdit;				//密码输入窗口
BOOL IsPassCorrect;		//密码是否正确

// 定义函数指针变量(函数外定义,全局化
PLoadLibraryA pLoadLibraryA;
PVirtualProtect pVirtualProtect;
PGetMoudleHandleA pGetMoudleHandleA;
PRegisterClassEx pRegisterClassEx;
PCreateWindowEx pCreateWindowEx;
PUpdateWindow pUpdateWindow;
PShowWindow pShowWindow;
PGetMessage pGetMessage;
PTranslateMessage pTranslateMessage;
PDispatchMessageW pDispatchMessageW;
PGetWindowTextW pGetWindowTextW;
PExitProcess pExitProcess;
PSendMessageW pSendMessageW;
PDefWindowProcW pDefWindowProcW;
PPostQuitMessage pPostQuitMessage;
PFindWindowW pFindWindowW;
PMessageBoxW pMessageBoxW;

// 解密区段
void DecodeSection()
{
	// 1 获取待解密区段的起始位置
	DWORD oldProtect;
	__asm
	{
		mov ebx, dword ptr fs : [0x30];	// 获取PEB
		mov ebx, dword ptr[ebx + 0x08];	// 获取加载基址ImageBase
		add shareData.rva, ebx;// RVA+基址= 区段VA(执行后,名rva实va
	}
	// 2 解密前先修改其访问属性(可写
	pVirtualProtect((LPVOID)shareData.rva, shareData.size, PAGE_READWRITE, &oldProtect);
	// 3 循环,逐位解密
	for (int i = 0; i < shareData.size; ++i)
	{
		((BYTE*)shareData.rva)[i] ^= shareData.key;
	}
	// 4 解密写入后,将属性恢复
	pVirtualProtect((LPVOID)shareData.rva, shareData.size, oldProtect, &oldProtect);
}

// 获取kernel32.dll基址
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

// 自定义获取函数地址函数
DWORD MyGetProcAddress(DWORD Module, LPCSTR funcName)
{
	// 1 获取DOS头 NT头
	auto DosHeader = (PIMAGE_DOS_HEADER)Module;
	auto NtHeader = (PIMAGE_NT_HEADERS)(Module + DosHeader->e_lfanew);
	// 2 获取导出表
	DWORD ExportRva = NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
	auto ExportTable = (PIMAGE_EXPORT_DIRECTORY)(Module + ExportRva);
	// 3 获取ENT EOT EAT
	auto ENT = (DWORD*)(ExportTable->AddressOfNames + Module);
	auto EAT = (DWORD*)(ExportTable->AddressOfFunctions + Module);
	auto EOT = (WORD*)(ExportTable->AddressOfNameOrdinals + Module);
	// 4 遍历ENT
	for (DWORD i = 0; i < ExportTable->NumberOfNames; ++i)
	{
		// 5 根据函数名称找地址(三表关系
		char* name = (char*)(ENT[i] + Module);
		if (!strcmp(name, funcName))
			return EAT[EOT[i]] + Module;
	}
	return -1;
}

// 获取任意API地址
void GetAPIAddr()
{
	// 1 kernel32.dll(GetKernelBase获取kernel基址
	pVirtualProtect = (PVirtualProtect)MyGetProcAddress(GetKernelBase(), "VirtualProtect");
	pLoadLibraryA = (PLoadLibraryA)MyGetProcAddress(GetKernelBase(), "LoadLibraryA");
	pVirtualProtect = (PVirtualProtect)MyGetProcAddress(GetKernelBase(), "VirtualProtect");
	pGetMoudleHandleA = (PGetMoudleHandleA)MyGetProcAddress(GetKernelBase(), "GetModuleHandleA");
	pExitProcess = (PExitProcess)MyGetProcAddress(GetKernelBase(), "ExitProcess");
	// 2 有pLoadLibraryA后,可任意获取其他dll
	DWORD user32Base = (DWORD)pLoadLibraryA((char*)"user32.dll");
	// 3 user32.dll(pLoadLibraryA 获取user基址
	pRegisterClassEx = (PRegisterClassEx)MyGetProcAddress(user32Base, "RegisterClassExW");
	pCreateWindowEx = (PCreateWindowEx)MyGetProcAddress(user32Base, "CreateWindowExW");
	pUpdateWindow = (PUpdateWindow)MyGetProcAddress(user32Base, "UpdateWindow");
	pShowWindow = (PShowWindow)MyGetProcAddress(user32Base, "ShowWindow");
	pGetMessage = (PGetMessage)MyGetProcAddress(user32Base, "GetMessageW");
	pTranslateMessage = (PTranslateMessage)MyGetProcAddress(user32Base, "TranslateMessage");
	pDispatchMessageW = (PDispatchMessageW)MyGetProcAddress(user32Base, "DispatchMessageW");
	pGetWindowTextW = (PGetWindowTextW)MyGetProcAddress(user32Base, "GetWindowTextW");
	pSendMessageW = (PSendMessageW)MyGetProcAddress(user32Base, "SendMessageW");
	pDefWindowProcW = (PDefWindowProcW)MyGetProcAddress(user32Base, "DefWindowProcW");
	pPostQuitMessage = (PPostQuitMessage)MyGetProcAddress(user32Base, "PostQuitMessage");
	pFindWindowW = (PFindWindowW)MyGetProcAddress(user32Base, "FindWindowW");
	pMessageBoxW = (PMessageBoxW)MyGetProcAddress(user32Base, "MessageBoxW");
}

// 自定义字符串比较函数
int MyStrCmp(const wchar_t * src, const wchar_t * dst)
{
	int ret = 0;
	while (!(ret = *(wchar_t *)src - *(wchar_t *)dst) && *dst)
		++src, ++dst;
	if (ret < 0)
		ret = -1;
	else if (ret > 0)
		ret = 1;
	return(ret);
}

// 弹出密码框
void AlertPassBox()
{
	// 获取本程序实例句柄
	g_hInstance = (HINSTANCE)pGetMoudleHandleA(NULL);
	// 1 创建并设置窗口类的关键字段
	WNDCLASSEX WndClass;
	WndClass.cbSize = sizeof(WNDCLASSEX);
	WndClass.hInstance = g_hInstance;//实例句柄
	WndClass.cbWndExtra = WndClass.cbClsExtra = NULL;
	WndClass.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	WndClass.hIcon = NULL;
	WndClass.hIconSm = NULL;
	WndClass.hCursor = NULL;
	WndClass.style = CS_VREDRAW | CS_HREDRAW;
	WndClass.lpszMenuName = NULL;
	WndClass.lpfnWndProc = (WNDPROC)WndPrco;		//回调函数
	WndClass.lpszClassName = TEXT("MyPack");//窗口类名
	// 2 注册窗口类
	pRegisterClassEx(&WndClass);
	// 3 创建出具体的窗口
	HWND hWnd = pCreateWindowEx(0, TEXT("MyPack"), TEXT("请输入密码"),WS_OVERLAPPED | WS_VISIBLE,
		100, 100, 300, 200, NULL, NULL, g_hInstance, NULL);
	//4 显示并更新窗口
	pShowWindow(hWnd, SW_SHOW);
	pUpdateWindow(hWnd);
	// 5 消息循环
	MSG msg = { 0 };
	while (pGetMessage(&msg, NULL, NULL, NULL))
	{
		pTranslateMessage(&msg);
		pDispatchMessageW(&msg);
	}
	return;
}

// 窗口回调函数
LRESULT CALLBACK WndPrco(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_CREATE:// 窗口创建,添加控件
	{
		HWND hBit = pCreateWindowEx(0, L"static", L"密码", WS_CHILD | WS_VISIBLE,
			50, 50, 30, 20, hWnd, (HMENU)10004, g_hInstance, NULL);
		hEdit = pCreateWindowEx(0, L"edit", L"", WS_CHILD | WS_VISIBLE | WS_BORDER,
			100, 50, 120, 20, hWnd, (HMENU)10003, g_hInstance, NULL);
		pCreateWindowEx(0, L"button", L"确定", WS_CHILD | WS_VISIBLE,
			50, 100, 60, 30, hWnd, (HMENU)10001, g_hInstance, NULL);
		pCreateWindowEx(0, L"button", L"取消", WS_CHILD | WS_VISIBLE,
			150, 100, 60, 30, hWnd, (HMENU)10002, g_hInstance, NULL);
		IsPassCorrect = FALSE;
		break;
	}
	case  WM_COMMAND:// 消息处理
	{
		WORD wHigh = HIWORD(wParam);
		WORD wLow = LOWORD(wParam);
		switch (wLow)
		{
		case 10001:// 确定按钮,验证密码
		{
			TCHAR GetKey[10] = { 0 };
			pGetWindowTextW(hEdit, GetKey, 10);
			if (MyStrCmp(GetKey, L"123") == 0)//设置pass=123
			{
				//密码正确,则运行
				IsPassCorrect = TRUE;
				pSendMessageW(hWnd, WM_CLOSE, NULL, NULL);
			}
			else
			{
				//密码不匹配退出程序
				pExitProcess(1);
			}
			break;
		}
		case 10002://取消按钮,结束进程
		{
			pExitProcess(1);
			break;
		}
		default:
			break;
		}
		break;
	}
	case WM_CLOSE:case WM_QUIT:case WM_DESTROY:
	{
		// 密码正确,则正常退出
		if (IsPassCorrect)
		{
			pPostQuitMessage(0);
		}
		// 密码错误,则关闭进程
		else
		{
			pExitProcess(1);
		}
	}
	default:
		// 返回给默认处理函数
		return pDefWindowProcW(hWnd, msg, wParam, lParam);
	}
	return 0;
}

// 跳转至原始OEP
__declspec(naked) void JmpOEP()
{
	__asm
	{
		mov ebx, dword ptr fs : [0x30];	// 获取PEB
		mov ebx, dword ptr[ebx + 0x08];	// 获取加载基址ImageBase
		add ebx, shareData.origOEP;		// RVA+基址= 原始OEP
		jmp ebx;						// 跳转原始OEP
	}
}

// 壳代码起始函数(没有名称粉碎/导出/裸函数)
extern "C" __declspec(dllexport) __declspec(naked) void Start()
{
	GetAPIAddr();//运行前先获取必要的API地址
	DecodeSection();//解密/解压缩区段
	AlertPassBox();// 弹出密码框
	JmpOEP();//壳代码执行完毕,跳往真实OEP
}
