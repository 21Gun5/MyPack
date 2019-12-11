//// MyStub.cpp : 定义 DLL 应用程序的导出函数
//#include "stdafx.h"
//#include "MyStub.h"
//#include <windows.h>
//
//// 提供壳代码的Stub部分,通常用于:解压缩/解密'修复重定位表'修复/加密IAT表'调用TLS函数等
//
//// 合并data rdata 到text段, 将text改成可读可写可执行
//#pragma comment(linker,"/merge:.data=.text")
//#pragma comment(linker,"/merge:.rdata=.text")
//#pragma comment(linker, "/section:.text,RWE")
//
//// 导出一个全局变量来共享数据
//extern "C" __declspec(dllexport)SHAREDATA shareData = { 0 };
//
//// 密码框相关变量(函数外定义,全局化
//HINSTANCE g_hInstance;	//窗口实例句柄
//HWND hEdit;				//密码输入窗口
//BOOL IsPassCorrect;		//密码是否正确
//
//// 定义函数指针变量(函数外定义,全局化
////PGetProcAddress MyGetProcAddress;
//FnGetProcAddress MyGetProcAddress;
//PLoadLibraryA pLoadLibraryA;
//PVirtualProtect pVirtualProtect;
//PGetMoudleHandleA pGetMoudleHandleA;
//PRegisterClassEx pRegisterClassEx;
//PCreateWindowEx pCreateWindowEx;
//PUpdateWindow pUpdateWindow;
//PShowWindow pShowWindow;
//PGetMessage pGetMessage;
//PTranslateMessage pTranslateMessage;
//PDispatchMessageW pDispatchMessageW;
//PGetWindowTextW pGetWindowTextW;
//PExitProcess pExitProcess;
//PSendMessageW pSendMessageW;
//PDefWindowProcW pDefWindowProcW;
//PPostQuitMessage pPostQuitMessage;
//PFindWindowW pFindWindowW;
//PMessageBoxW pMessageBoxW;
//PVirtualAlloc pVirtualAlloc;
//PRtlMoveMemory pRtlMoveMemory;
//
//// 解密区段
//void DecodeSection()
//{
//	// 1 获取待解密区段的起始位置
//	DWORD oldProtect;
//	__asm
//	{
//		mov ebx, dword ptr fs : [0x30];	// 获取PEB
//		mov ebx, dword ptr[ebx + 0x08];	// 获取加载基址ImageBase
//		add shareData.rva, ebx;// RVA+基址= 区段VA(执行后,名rva实va
//	}
//	// 2 解密前先修改其访问属性(可写
//	pVirtualProtect((LPVOID)shareData.rva, shareData.size, PAGE_READWRITE, &oldProtect);
//	// 3 循环,逐位解密
//	for (int i = 0; i < shareData.size; ++i)
//	{
//		((BYTE*)shareData.rva)[i] ^= shareData.key;
//	}
//	// 4 解密写入后,将属性恢复
//	pVirtualProtect((LPVOID)shareData.rva, shareData.size, oldProtect, &oldProtect);
//}
//
//// 获取kernel32.dll基址
//__declspec(naked) long GetKernelBase()
//{
//	__asm
//	{
//		// 按照加载顺序
//		mov eax, dword ptr fs : [0x30]
//		mov eax, dword ptr[eax + 0x0C]
//		mov eax, dword ptr[eax + 0x0C]
//		mov eax, dword ptr[eax]
//		mov eax, dword ptr[eax]
//		mov eax, dword ptr[eax + 0x18]
//		ret
//	}
//}
//
////// 自定义获取函数地址函数
////DWORD MyGetProcAddress(DWORD Module, LPCSTR funcName)
////{
////	// 1 获取DOS头 NT头
////	auto DosHeader = (PIMAGE_DOS_HEADER)Module;
////	auto NtHeader = (PIMAGE_NT_HEADERS)(Module + DosHeader->e_lfanew);
////	// 2 获取导出表
////	DWORD ExportRva = NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
////	auto ExportTable = (PIMAGE_EXPORT_DIRECTORY)(Module + ExportRva);
////	// 3 获取ENT EOT EAT
////	auto ENT = (DWORD*)(ExportTable->AddressOfNames + Module);
////	auto EAT = (DWORD*)(ExportTable->AddressOfFunctions + Module);
////	auto EOT = (WORD*)(ExportTable->AddressOfNameOrdinals + Module);
////	// 4 遍历ENT
////	for (DWORD i = 0; i < ExportTable->NumberOfNames; ++i)
////	{
////		// 5 根据函数名称找地址(三表关系
////		char* name = (char*)(ENT[i] + Module);
////		if (!strcmp(name, funcName))
////			return EAT[EOT[i]] + Module;
////	}
////	return -1;
////}
//
//
////// 获取任意API地址
////void GetAPIAddr()
////{
////	_asm
////	{
////		pushad;
////		//获取kernel32.dll的加载基址;
////		// 1. 找到PEB的首地址;
////		mov eax, fs:[0x30]; eax = > peb首地址;
////		// 2. 得到PEB.Ldr的值;
////		mov eax, [eax + 0ch]; eax = > PEB.Ldr的值;
////		mov eax, [eax + 0ch]; eax = > PEB.Ldr的值;
////		// 3. 得到_PEB_LDR_DATA.InLoadOrderMoudleList.Flink的值, 实际得到的就是主模块节点的首地址;
////		mov eax, [eax]; //eax = > _PEB_LDR_DATA.InLoadOrderMoudleList.Flink(NTDLL);
////		// 4. 再获取下一个;
////		mov eax, [eax]; //_LDR_DATA_TABLE_ENTRY.InLoadOrderMoudleList.Flink(kernel32), ;
////		mov eax, [eax + 018h]; _LDR_DATA_TABLE_ENTRY.DllBase;
////		//mov hKernel32, eax;
////		// 遍历导出表;
////		// 1. dos头-- > nt头-- > 扩展头-- > 数据目录表;
////		mov ebx, [eax + 03ch]; //eax = > 偏移到NT头;
////		add ebx, eax; //ebx = > NT头的首地址;
////		add ebx, 078h; //ebx = >
////		// 2. 得到导出表的RVA;
////		mov ebx, [ebx];
////		add ebx, eax; //ebx == > 导出表首地址(VA);
////		// 3. 遍历名称表找到GetProcAddress;
////		// 3.1 找到名称表的首地址;
////		lea ecx, [ebx + 020h];
////		mov ecx, [ecx]; // ecx => 名称表的首地址(rva);
////		add ecx, eax; // ecx => 名称表的首地址(va);
////		xor edx, edx; // 作为index来使用.
////		// 3.2 遍历名称表;
////	_WHILE:;
////		mov esi, [ecx + edx * 4];// esi = > 名称的rva;
////		lea esi, [esi + eax]; //esi = > 名称首地址;
////		cmp dword ptr[esi], 050746547h; //47657450 726F6341 64647265 7373;
////		jne _LOOP;
////		cmp dword ptr[esi + 4], 041636f72h;
////		jne _LOOP;
////		cmp dword ptr[esi + 8], 065726464h;
////		jne _LOOP;
////		cmp word  ptr[esi + 0ch], 07373h;
////		jne _LOOP;
////		//; 找到之后;
////		mov edi, [ebx + 024h]//; edi = > 名称的序号表的rva;
////			add edi, eax;// edi = > 名称的序号表的va;
////		mov di, [edi + edx * 2];// 序号表是2字节的元素, 因此是 * 2;
////		//; edi保存的是GetProcAddress的在;
////		//; 地址表中的下标;
////		and edi, 0FFFFh;
////		//; 得到地址表首地址;
////		mov edx, [ebx + 01ch];// edx = > 地址表的rva;
////		add edx, eax; //edx = > 地址表的va;
////		mov edi, [edx + edi * 4]; //edi = > GetProcAddress的rva;
////		add edi, eax; //; edx = > GetProcAddress的va;
////		mov MyGetProcAddress, edi;
////		jmp _ENDWHILE;
////	_LOOP://;
////		inc edx; // ++index;
////		jmp _WHILE;
////	_ENDWHILE:;
////		popad;
////	}
////
////
////	// kernel32.dll(GetKernelBase获取kernel基址
////	HMODULE kernelBase = (HMODULE)GetKernelBase();
////	pVirtualProtect = (PVirtualProtect)MyGetProcAddress(kernelBase, "VirtualProtect");
////	pLoadLibraryA = (PLoadLibraryA)MyGetProcAddress(kernelBase, "LoadLibraryA");
////	pVirtualProtect = (PVirtualProtect)MyGetProcAddress(kernelBase, "VirtualProtect");
////	pGetMoudleHandleA = (PGetMoudleHandleA)MyGetProcAddress(kernelBase, "GetModuleHandleA");
////	pExitProcess = (PExitProcess)MyGetProcAddress(kernelBase, "ExitProcess");
////	pVirtualAlloc = (PVirtualAlloc)MyGetProcAddress(kernelBase, "VirtualAlloc");
////	pRtlMoveMemory = (PRtlMoveMemory)MyGetProcAddress(kernelBase, "RtlMoveMemory");
////
////	//DWORD ntBase = (DWORD)pLoadLibraryA((char*)"ntdll.dll");
////	//pRtlMoveMemory = (PRtlMoveMemory)MyGetProcAddress(ntBase, "RtlMoveMemory");
////
////	// user32.dll(pLoadLibraryA 获取user基址
////	HMODULE user32Base = (HMODULE)pLoadLibraryA((char*)"user32.dll");
////	pRegisterClassEx = (PRegisterClassEx)MyGetProcAddress(user32Base, "RegisterClassExW");
////	pCreateWindowEx = (PCreateWindowEx)MyGetProcAddress(user32Base, "CreateWindowExW");
////	pUpdateWindow = (PUpdateWindow)MyGetProcAddress(user32Base, "UpdateWindow");
////	pShowWindow = (PShowWindow)MyGetProcAddress(user32Base, "ShowWindow");
////	pGetMessage = (PGetMessage)MyGetProcAddress(user32Base, "GetMessageW");
////	pTranslateMessage = (PTranslateMessage)MyGetProcAddress(user32Base, "TranslateMessage");
////	pDispatchMessageW = (PDispatchMessageW)MyGetProcAddress(user32Base, "DispatchMessageW");
////	pGetWindowTextW = (PGetWindowTextW)MyGetProcAddress(user32Base, "GetWindowTextW");
////	pSendMessageW = (PSendMessageW)MyGetProcAddress(user32Base, "SendMessageW");
////	pDefWindowProcW = (PDefWindowProcW)MyGetProcAddress(user32Base, "DefWindowProcW");
////	pPostQuitMessage = (PPostQuitMessage)MyGetProcAddress(user32Base, "PostQuitMessage");
////	pFindWindowW = (PFindWindowW)MyGetProcAddress(user32Base, "FindWindowW");
////	pMessageBoxW = (PMessageBoxW)MyGetProcAddress(user32Base, "MessageBoxW");
////}
//
//
//
//// 自定义字符串比较函数
//int MyStrCmp(const wchar_t * src, const wchar_t * dst)
//{
//	int ret = 0;
//	while (!(ret = *(wchar_t *)src - *(wchar_t *)dst) && *dst)
//		++src, ++dst;
//	if (ret < 0)
//		ret = -1;
//	else if (ret > 0)
//		ret = 1;
//	return(ret);
//}
//
//// 弹出密码框
//void AlertPassBox()
//{
//	// 获取本程序实例句柄
//	g_hInstance = (HINSTANCE)pGetMoudleHandleA(NULL);
//	// 1 创建并设置窗口类的关键字段
//	WNDCLASSEX WndClass;
//	WndClass.cbSize = sizeof(WNDCLASSEX);// 大小
//	WndClass.hInstance = g_hInstance;//实例句柄
//	WndClass.lpfnWndProc = (WNDPROC)WndPrco;//回调函数
//	WndClass.lpszClassName = TEXT("MyPack");//窗口类名
//	WndClass.cbWndExtra = WndClass.cbClsExtra = NULL;
//	WndClass.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
//	WndClass.hIcon = NULL;
//	WndClass.hIconSm = NULL;
//	WndClass.hCursor = NULL;
//	WndClass.style = CS_VREDRAW | CS_HREDRAW;
//	WndClass.lpszMenuName = NULL;
//	// 2 注册窗口类
//	pRegisterClassEx(&WndClass);
//	// 3 创建出具体的窗口
//	HWND hWnd = pCreateWindowEx(0, TEXT("MyPack"), TEXT("请输入密码"), WS_OVERLAPPED | WS_VISIBLE,
//		100, 100, 300, 200, NULL, NULL, g_hInstance, NULL);
//	//4 显示并更新窗口
//	pShowWindow(hWnd, SW_SHOW);
//	pUpdateWindow(hWnd);
//	// 5 消息循环
//	MSG msg = { 0 };
//	while (pGetMessage(&msg, NULL, NULL, NULL))
//	{
//		pTranslateMessage(&msg);
//		pDispatchMessageW(&msg);
//	}
//	return;
//}
//
//// 窗口回调函数
//LRESULT CALLBACK WndPrco(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
//{
//	switch (msg)
//	{
//	case WM_CREATE:// 窗口创建,添加控件
//	{
//		HWND hBit = pCreateWindowEx(0, L"static", L"密码", WS_CHILD | WS_VISIBLE,
//			50, 50, 30, 20, hWnd, (HMENU)10004, g_hInstance, NULL);
//		hEdit = pCreateWindowEx(0, L"edit", L"", WS_CHILD | WS_VISIBLE | WS_BORDER,
//			100, 50, 120, 20, hWnd, (HMENU)10003, g_hInstance, NULL);
//		pCreateWindowEx(0, L"button", L"确定", WS_CHILD | WS_VISIBLE,
//			50, 100, 60, 30, hWnd, (HMENU)10001, g_hInstance, NULL);
//		pCreateWindowEx(0, L"button", L"取消", WS_CHILD | WS_VISIBLE,
//			150, 100, 60, 30, hWnd, (HMENU)10002, g_hInstance, NULL);
//		IsPassCorrect = FALSE;
//		break;
//	}
//	case  WM_COMMAND:// 消息处理
//	{
//		WORD wHigh = HIWORD(wParam);
//		WORD wLow = LOWORD(wParam);
//		switch (wLow)
//		{
//		case 10001:// 确定按钮,验证密码
//		{
//			TCHAR GetKey[10] = { 0 };
//			pGetWindowTextW(hEdit, GetKey, 10);
//			if (MyStrCmp(GetKey, L"123") == 0)//设置pass=123
//			{
//				//密码正确,则运行
//				IsPassCorrect = TRUE;
//				pSendMessageW(hWnd, WM_CLOSE, NULL, NULL);
//			}
//			else
//			{
//				//密码不匹配退出程序
//				pExitProcess(1);
//			}
//			break;
//		}
//		case 10002://取消按钮,结束进程
//		{
//			pExitProcess(1);
//			break;
//		}
//		default:
//			break;
//		}
//		break;
//	}
//	case WM_CLOSE:case WM_QUIT:case WM_DESTROY:
//	{
//		// 密码正确,则正常退出
//		if (IsPassCorrect)
//		{
//			pPostQuitMessage(0);
//		}
//		// 密码错误,则关闭进程
//		else
//		{
//			pExitProcess(1);
//		}
//	}
//	default:
//		// 返回给默认处理函数
//		return pDefWindowProcW(hWnd, msg, wParam, lParam);
//	}
//	return 0;
//}
//
//// 跳转至原始OEP
//__declspec(naked) void JmpOEP()
//{
//	__asm
//	{
//		mov ebx, dword ptr fs : [0x30];	// 获取PEB
//		mov ebx, dword ptr[ebx + 0x08];	// 获取加载基址ImageBase
//		add ebx, shareData.origOEP;		// RVA+基址= 原始OEP
//		jmp ebx;						// 跳转原始OEP
//	}
//}
//
//
//PIMAGE_DOS_HEADER GetDosHeader(DWORD fileBase)
//{
//	return (PIMAGE_DOS_HEADER)fileBase;
//}
//PIMAGE_NT_HEADERS GetNtHeader(DWORD fileBase)
//{
//	return (PIMAGE_NT_HEADERS)(fileBase + GetDosHeader(fileBase)->e_lfanew);
//}
//PIMAGE_FILE_HEADER GetFileHeader(DWORD fileBase)
//{
//	return &GetNtHeader(fileBase)->FileHeader;
//}
//PIMAGE_OPTIONAL_HEADER GetOptHeader(DWORD fileBase)
//{
//	return &GetNtHeader(fileBase)->OptionalHeader;
//}
//
//// 替换函数地址(用于加密IAT
//DWORD ReplaceFuncAddr(DWORD funcAddr)
//{
//	// 申请内存空间,其首地址作为函数新地址
//	DWORD dwNewMem = (DWORD)pVirtualAlloc(NULL, 0x20, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
//
//	// 加密函数地址(^ 0x15151515
//	DWORD dwEncryptFunAddr = 0;
//	dwEncryptFunAddr = funcAddr ^ 0x11121314;
//	// 解密IAT的ShellCode(带有花指令
//	DWORD OpCode[] = {
//					0xE8, 0x01, 0x00, 0x00,
//					0x00, 0xE9, 0x58, 0xEB,
//					0x01, 0xE8, 0xB8, 0x85,
//					0xEE, 0xCB, 0x60, 0xEB,
//					0x01, 0x15, 0x35, 0x14,
//					0x13, 0x12, 0x11, 0xEB,
//					0x01, 0xFF, 0x50, 0xEB,
//					0x02, 0xFF, 0x15, 0xC3
//	};
//	// 把函数地址写入到解密的ShellCode中
//	OpCode[11] = dwEncryptFunAddr;					// 0x85
//	OpCode[12] = dwEncryptFunAddr >> 0x08;			// 0xEE
//	OpCode[13] = dwEncryptFunAddr >> 0x10;			// 0xCB
//	OpCode[14] = dwEncryptFunAddr >> 0x18;			// 0x60
//
//	// 将数据拷贝到申请的内存
//	pRtlMoveMemory((LPVOID)dwNewMem, OpCode, 0x20);
//	// 返回新的函数地址
//	return dwNewMem;
//}
//
//// 加密IAT
//void EncodeIAT()
//{
//	// 获取加载基址(exe源程序
//	DWORD exeFileBase = (DWORD)pGetMoudleHandleA(NULL);
//	// 设置可写的访问属性
//	DWORD oldProtect = 0;
//	pVirtualProtect((LPVOID)exeFileBase, 0x400, PAGE_READWRITE, &oldProtect);
//	// 获取导入表地址 = 偏移 + 基址
//	IMAGE_IMPORT_DESCRIPTOR* pImport = (IMAGE_IMPORT_DESCRIPTOR*)(GetOptHeader(exeFileBase)->DataDirectory[1].VirtualAddress + exeFileBase);
//	// 遍历所有导入表(有多个,以0结尾
//	IMAGE_THUNK_DATA* pIAT = NULL;
//	IMAGE_THUNK_DATA* pINT = NULL;
//	DWORD dllBase = 0;// 导入的dll的基址
//	while (pImport->FirstThunk != 0)
//	{
//		// 获取导入表重要字段
//		pIAT = (IMAGE_THUNK_DATA*)(pImport->FirstThunk + exeFileBase);
//		pINT = (IMAGE_THUNK_DATA*)(pImport->OriginalFirstThunk + exeFileBase);
//		char * dllName = (char*)(pImport->Name + exeFileBase);
//		// 加载dll获取句柄(即基址
//		dllBase = (DWORD)pLoadLibraryA(dllName);
//		// 遍历INT,获取地址后填充IAT
//		while (pINT->u1.Ordinal != 0)
//		{
//			DWORD funcAddr = 0;// 函数地址
//			IMAGE_IMPORT_BY_NAME* pImpByName = 0;//函数名结构体
//			// 导出方式:序号
//			if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal))
//			{
//				funcAddr = (DWORD)MyGetProcAddress((HMODULE)dllBase, (char*)(pINT->u1.Ordinal & 0xFFFF));
//			}
//			// 导出方式:名称
//			else
//			{
//				pImpByName = (IMAGE_IMPORT_BY_NAME*)(pINT->u1.Function + exeFileBase);
//				funcAddr = (DWORD)MyGetProcAddress((HMODULE)dllBase, (char*)pImpByName->Name);
//			}
//			// 修改IAT内容(修改之前先修改为写属性,后恢复
//			DWORD oldProtect2 = 0;
//			pVirtualProtect(&pIAT->u1.Function, sizeof(pIAT->u1.Function), PAGE_READWRITE, &oldProtect2);
//			//pIAT->u1.Function = 0;// 修改IAT
//			pIAT->u1.Function = ReplaceFuncAddr(funcAddr);// 修改IAT(替换函数地址
//			pVirtualProtect(&pIAT->u1.Function, sizeof(pIAT->u1.Function), oldProtect2, &oldProtect2);
//			// 下一个函数
//			++pINT;
//			++pIAT;
//		}
//		// 下一个dll
//		++pImport;
//	}
//	// 恢复原有属性
//	pVirtualProtect((LPVOID)exeFileBase, 0x400, oldProtect, &oldProtect);
//}
//
//
//// 壳代码起始函数(没有名称粉碎/导出/裸函数)
//extern "C" __declspec(dllexport) __declspec(naked) void Start()
//{
//	GetAPIAddr();//运行前先获取必要的API地址
//	DecodeSection();//解密/解压缩区段
//	//AlertPassBox();// 弹出密码框
//	EncodeIAT();// 加密IAT
//	JmpOEP();//壳代码执行完毕,跳往真实OEP
//}

#include "stdafx.h"
#include <windows.h>
#include "MyStub.h"

// 提供壳代码的Stub部分,通常用于:解压缩/解密'修复重定位表'修复/加密IAT表'调用TLS函数等

// 合并data rdata 到text段, 将text改成可读可写可执行
#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")


PIMAGE_DOS_HEADER GetDosHeader(DWORD fileBase)
{
	return (PIMAGE_DOS_HEADER)fileBase;
}
PIMAGE_NT_HEADERS GetNtHeader(DWORD fileBase)
{
	return (PIMAGE_NT_HEADERS)(fileBase + GetDosHeader(fileBase)->e_lfanew);
}
PIMAGE_FILE_HEADER GetFileHeader(DWORD fileBase)
{
	return &GetNtHeader(fileBase)->FileHeader;
}
PIMAGE_OPTIONAL_HEADER GetOptHeader(DWORD fileBase)
{
	return &GetNtHeader(fileBase)->OptionalHeader;
}

//导出一个全局变量
extern "C" __declspec(dllexport)SHAREDATA shareData = { 0 };

// 密码框相关变量(函数外定义,全局化
HINSTANCE g_hInstance;	//窗口实例句柄
HWND hEdit;				//密码输入窗口
BOOL IsPassCorrect;		//密码是否正确

// 定义函数指针变量(函数外定义,全局化
FnGetProcAddress MyGetProcAddress;
FnLoadLibraryA MyLoadLibraryA;
FnVirtualProtect MyVirtualProtect;
fnGetMoudleHandleA pfnGetMoudleHandleA;
fnRegisterClassEx pfnRegisterClassEx;
fnCreateWindowEx pfnCreateWindowEx;
fnUpdateWindow pfnUpdateWindow;
fnShowWindow pfnShowWindow;
fnGetMessage pfnGetMessage;
fnTranslateMessage pfnTranslateMessage;
fnDispatchMessageW pfnDispatchMessageW;
fnGetWindowTextW pfnGetWindowTextW;
fnExitProcess pfnExitProcess;
fnSendMessageW pfnSendMessageW;
fnDefWindowProcW pfnDefWindowProcW;
fnPostQuitMessage pfnPostQuitMessage;
fnFindWindowW pfnFindWindowW;
fnMessageBoxW pfnMessageBoxW;
fnBeginPaint pfnBeginPaint;
fnEndPaint pfnEndPaint;
FnVirtualAlloc pfnVirtualAlloc;
FnRtlMoveMemory pfnRtlMoveMemory;

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
	MyVirtualProtect((LPVOID)shareData.rva, shareData.size, PAGE_READWRITE, &oldProtect);
	// 3 循环,逐位解密
	for (int i = 0; i < shareData.size; ++i)
	{
		((BYTE*)shareData.rva)[i] ^= shareData.key;
	}
	// 4 解密写入后,将属性恢复
	MyVirtualProtect((LPVOID)shareData.rva, shareData.size, oldProtect, &oldProtect);
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

//// 自定义获取函数地址函数
//void* MyGetProcAddress(HMODULE Module, const char* funcName)
//{
//	// 1 获取DOS头 NT头
//	auto DosHeader = (PIMAGE_DOS_HEADER)Module;
//	auto NtHeader = (PIMAGE_NT_HEADERS)(Module + DosHeader->e_lfanew);
//	// 2 获取导出表
//	DWORD ExportRva = NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
//	auto ExportTable = (PIMAGE_EXPORT_DIRECTORY)(Module + ExportRva);
//	// 3 获取ENT EOT EAT
//	auto ENT = (DWORD*)(ExportTable->AddressOfNames + Module);
//	auto EAT = (DWORD*)(ExportTable->AddressOfFunctions + Module);
//	auto EOT = (WORD*)(ExportTable->AddressOfNameOrdinals + Module);
//	// 4 遍历ENT
//	for (DWORD i = 0; i < ExportTable->NumberOfNames; ++i)
//	{
//		// 5 根据函数名称找地址(三表关系
//		char* name = (char*)(ENT[i] + Module);
//		if (!strcmp(name, funcName))
//			return EAT[EOT[i]] + Module;
//	}
//	return NULL;
//}

// 获取需要的API地址
void GetAPIAddr()
{
	// 获取MyGetProcAddress//here
	_asm
	{
		pushad;
		//获取kernel32.dll的加载基址;
		// 1. 找到PEB的首地址;
		mov eax, fs:[0x30]; eax = > peb首地址;
		// 2. 得到PEB.Ldr的值;
		mov eax, [eax + 0ch]; eax = > PEB.Ldr的值;
		mov eax, [eax + 0ch]; eax = > PEB.Ldr的值;
		// 3. 得到_PEB_LDR_DATA.InLoadOrderMoudleList.Flink的值, 实际得到的就是主模块节点的首地址;
		mov eax, [eax]; eax = > _PEB_LDR_DATA.InLoadOrderMoudleList.Flink(NTDLL);
		// 4. 再获取下一个;
		mov eax, [eax]; _LDR_DATA_TABLE_ENTRY.InLoadOrderMoudleList.Flink(kernel32), ;
		mov eax, [eax + 018h]; _LDR_DATA_TABLE_ENTRY.DllBase;
		//mov hKernel32, eax;
		// 遍历导出表;
		// 1. dos头-- > nt头-- > 扩展头-- > 数据目录表;
		mov ebx, [eax + 03ch]; //eax = > 偏移到NT头;
		add ebx, eax; //ebx = > NT头的首地址;
		add ebx, 078h; //ebx = >
		// 2. 得到导出表的RVA;
		mov ebx, [ebx];
		add ebx, eax; //ebx == > 导出表首地址(VA);
		// 3. 遍历名称表找到GetProcAddress;
		// 3.1 找到名称表的首地址;
		lea ecx, [ebx + 020h];
		mov ecx, [ecx]; // ecx => 名称表的首地址(rva);
		add ecx, eax; // ecx => 名称表的首地址(va);
		xor edx, edx; // 作为index来使用.
		// 3.2 遍历名称表;
	_WHILE:;
		mov esi, [ecx + edx * 4];// esi = > 名称的rva;
		lea esi, [esi + eax]; //esi = > 名称首地址;
		cmp dword ptr[esi], 050746547h; //47657450 726F6341 64647265 7373;
		jne _LOOP;
		cmp dword ptr[esi + 4], 041636f72h;
		jne _LOOP;
		cmp dword ptr[esi + 8], 065726464h;
		jne _LOOP;
		cmp word  ptr[esi + 0ch], 07373h;
		jne _LOOP;
		//; 找到之后;
		mov edi, [ebx + 024h]//; edi = > 名称的序号表的rva;
		add edi, eax;// edi = > 名称的序号表的va;
		mov di, [edi + edx * 2];// 序号表是2字节的元素, 因此是 * 2;
		//; edi保存的是GetProcAddress的在;
		//; 地址表中的下标;
		and edi, 0FFFFh;
		//; 得到地址表首地址;
		mov edx, [ebx + 01ch];// edx = > 地址表的rva;
		add edx, eax; //edx = > 地址表的va;
		mov edi, [edx + edi * 4]; //edi = > GetProcAddress的rva;
		add edi, eax; //; edx = > GetProcAddress的va;
		mov MyGetProcAddress, edi;
		jmp _ENDWHILE;
	_LOOP://;
		inc edx; // ++index;
		jmp _WHILE;
	_ENDWHILE:;
		popad;
	}

	//Kernel32
	HMODULE hKernel32 = (HMODULE)GetKernelBase();
	MyLoadLibraryA = (FnLoadLibraryA)MyGetProcAddress(hKernel32, "LoadLibraryA");
	MyVirtualProtect = (FnVirtualProtect)MyGetProcAddress(hKernel32, "VirtualProtect");
	pfnGetMoudleHandleA = (fnGetMoudleHandleA)MyGetProcAddress(hKernel32, "GetModuleHandleA");
	pfnExitProcess = (fnExitProcess)MyGetProcAddress(hKernel32, "ExitProcess");
	pfnVirtualAlloc = (FnVirtualAlloc)MyGetProcAddress(hKernel32, "VirtualAlloc");
	pfnRtlMoveMemory = (FnRtlMoveMemory)MyGetProcAddress(hKernel32, "RtlMoveMemory");
	// User32
	HMODULE hUser32 = (HMODULE)MyLoadLibraryA((char*)"user32.dll");
	pfnRegisterClassEx = (fnRegisterClassEx)MyGetProcAddress(hUser32, "RegisterClassExW");
	pfnCreateWindowEx = (fnCreateWindowEx)MyGetProcAddress(hUser32, "CreateWindowExW");
	pfnUpdateWindow = (fnUpdateWindow)MyGetProcAddress(hUser32, "UpdateWindow");
	pfnShowWindow = (fnShowWindow)MyGetProcAddress(hUser32, "ShowWindow");
	pfnGetMessage = (fnGetMessage)MyGetProcAddress(hUser32, "GetMessageW");
	pfnTranslateMessage = (fnTranslateMessage)MyGetProcAddress(hUser32, "TranslateMessage");
	pfnDispatchMessageW = (fnDispatchMessageW)MyGetProcAddress(hUser32, "DispatchMessageW");
	pfnGetWindowTextW = (fnGetWindowTextW)MyGetProcAddress(hUser32, "GetWindowTextW");
	pfnSendMessageW = (fnSendMessageW)MyGetProcAddress(hUser32, "SendMessageW");
	pfnDefWindowProcW = (fnDefWindowProcW)MyGetProcAddress(hUser32, "DefWindowProcW");
	pfnPostQuitMessage = (fnPostQuitMessage)MyGetProcAddress(hUser32, "PostQuitMessage");
	pfnFindWindowW = (fnFindWindowW)MyGetProcAddress(hUser32, "FindWindowW");
	pfnMessageBoxW = (fnMessageBoxW)MyGetProcAddress(hUser32, "MessageBoxW");
	pfnBeginPaint = (fnBeginPaint)MyGetProcAddress(hUser32, "BeginPaint");
	pfnEndPaint = (fnEndPaint)MyGetProcAddress(hUser32, "EndPaint");
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
	g_hInstance = (HINSTANCE)pfnGetMoudleHandleA(NULL);
	// 1 创建并设置窗口类的关键字段
	WNDCLASSEX WndClass;
	WndClass.cbSize = sizeof(WNDCLASSEX);// 大小
	WndClass.hInstance = g_hInstance;//实例句柄
	WndClass.lpfnWndProc = (WNDPROC)WndPrco;//回调函数
	WndClass.lpszClassName = TEXT("MyPack");//窗口类名
	WndClass.cbWndExtra = WndClass.cbClsExtra = NULL;
	WndClass.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	WndClass.hIcon = NULL;
	WndClass.hIconSm = NULL;
	WndClass.hCursor = NULL;
	WndClass.style = CS_VREDRAW | CS_HREDRAW;
	WndClass.lpszMenuName = NULL;
	// 2 注册窗口类
	pfnRegisterClassEx(&WndClass);
	// 3 创建出具体的窗口
	HWND hWnd = pfnCreateWindowEx(0, TEXT("MyPack"), TEXT("请输入密码"), WS_OVERLAPPED | WS_VISIBLE,
		100, 100, 300, 200, NULL, NULL, g_hInstance, NULL);
	//4 显示并更新窗口
	pfnShowWindow(hWnd, SW_SHOW);
	pfnUpdateWindow(hWnd);
	// 5 消息循环
	MSG msg = { 0 };
	while (pfnGetMessage(&msg, NULL, NULL, NULL))
	{
		pfnTranslateMessage(&msg);
		pfnDispatchMessageW(&msg);
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
		HWND hBit = pfnCreateWindowEx(0, L"static", L"密码", WS_CHILD | WS_VISIBLE,
			50, 50, 30, 20, hWnd, (HMENU)10004, g_hInstance, NULL);
		hEdit = pfnCreateWindowEx(0, L"edit", L"", WS_CHILD | WS_VISIBLE | WS_BORDER,
			100, 50, 120, 20, hWnd, (HMENU)10003, g_hInstance, NULL);
		pfnCreateWindowEx(0, L"button", L"确定", WS_CHILD | WS_VISIBLE,
			50, 100, 60, 30, hWnd, (HMENU)10001, g_hInstance, NULL);
		pfnCreateWindowEx(0, L"button", L"取消", WS_CHILD | WS_VISIBLE,
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
			pfnGetWindowTextW(hEdit, GetKey, 10);
			if (MyStrCmp(GetKey, L"123") == 0)//设置pass=123
			{
				//密码正确,则运行
				IsPassCorrect = TRUE;
				pfnSendMessageW(hWnd, WM_CLOSE, NULL, NULL);
			}
			else
			{
				//密码不匹配退出程序
				pfnExitProcess(1);
			}
			break;
		}
		case 10002://取消按钮,结束进程
		{
			pfnExitProcess(1);
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
			pfnPostQuitMessage(0);
		}
		// 密码错误,则关闭进程
		else
		{
			pfnExitProcess(1);
		}
	}
	default:
		// 返回给默认处理函数
		return pfnDefWindowProcW(hWnd, msg, wParam, lParam);
	}
	return 0;
}

// 替换函数地址(用于加密IAT
DWORD ReplaceFuncAddr(DWORD dwFunAddr)
{
	// 申请内存空间,其首地址作为函数新地址
	DWORD dwNewMem = (DWORD)pfnVirtualAlloc(NULL, 0x20, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// 加密函数地址(^ 0x15151515
	DWORD dwEncryptFunAddr = dwFunAddr ^ 0x15151515;
	// 解密IAT的ShellCode(带有花指令;必须BYTE类型
	BYTE OpCode[] = {
					0xE8, 0x01, 0x00, 0x00,
					0x00, 0xE9, 0x58, 0xEB,
					0x01, 0xE8, 0xB8, 0x85,
					0xEE, 0xCB, 0x60, 0xEB,
					0x01, 0x15, 0x35, 0x15,
					0x15, 0x15, 0x15, 0xEB,
					0x01, 0xFF, 0x50, 0xEB,
					0x02, 0xFF, 0x15, 0xC3
	};
	// 把函数地址写入到解密的ShellCode中
	OpCode[11] = dwEncryptFunAddr;					// 0x85
	OpCode[12] = dwEncryptFunAddr >> 0x08;			// 0xEE
	OpCode[13] = dwEncryptFunAddr >> 0x10;			// 0xCB
	OpCode[14] = dwEncryptFunAddr >> 0x18;			// 0x60
	// 将数据拷贝到申请的内存
	pfnRtlMoveMemory((LPVOID)dwNewMem, OpCode, 0x20);
	// 返回新的函数地址
	return dwNewMem;
}
// 加密IAT
void EncodeIAT()
{
	// 获取加载基址(exe源程序
	DWORD exeFileBase = (DWORD)pfnGetMoudleHandleA(NULL);
	// 设置可写的访问属性
	DWORD oldProtect = 0;
	MyVirtualProtect((LPVOID)exeFileBase, 0x400, PAGE_READWRITE, &oldProtect);
	// 获取导入表地址 = 偏移 + 基址
	IMAGE_IMPORT_DESCRIPTOR* pImport = (IMAGE_IMPORT_DESCRIPTOR*)(GetOptHeader(exeFileBase)->DataDirectory[1].VirtualAddress + exeFileBase);
	// 遍历所有导入表(有多个,以0结尾
	IMAGE_THUNK_DATA* pIAT = NULL;
	IMAGE_THUNK_DATA* pINT = NULL;
	DWORD dllBase = 0;// 导入的dll的基址
	while (pImport->FirstThunk != 0)
	{
		// 获取导入表重要字段
		pIAT = (IMAGE_THUNK_DATA*)(pImport->FirstThunk + exeFileBase);
		pINT = (IMAGE_THUNK_DATA*)(pImport->OriginalFirstThunk + exeFileBase);
		char * dllName = (char*)(pImport->Name + exeFileBase);
		// 加载dll获取句柄(即基址
		dllBase = (DWORD)MyLoadLibraryA(dllName);
		// 遍历INT,获取地址后填充IAT
		while (pINT->u1.Ordinal != 0)
		{
			DWORD funcAddr = 0;// 函数地址
			IMAGE_IMPORT_BY_NAME* pImpByName = 0;//函数名结构体
			// 导出方式:序号
			if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal))
			{
				funcAddr = (DWORD)MyGetProcAddress((HMODULE)dllBase, (char*)(pINT->u1.Ordinal & 0xFFFF));
			}
			// 导出方式:名称
			else
			{
				pImpByName = (IMAGE_IMPORT_BY_NAME*)(pINT->u1.Function + exeFileBase);
				funcAddr = (DWORD)MyGetProcAddress((HMODULE)dllBase, (char*)pImpByName->Name);
			}
			// 修改IAT内容(修改之前先修改为写属性,后恢复
			DWORD oldProtect2 = 0;
			MyVirtualProtect(&pIAT->u1.Function, sizeof(pIAT->u1.Function), PAGE_READWRITE, &oldProtect2);
			//pIAT->u1.Function = 0;// 修改IAT
			pIAT->u1.Function = ReplaceFuncAddr(funcAddr);// 修改IAT(替换函数地址
			MyVirtualProtect(&pIAT->u1.Function, sizeof(pIAT->u1.Function), oldProtect2, &oldProtect2);
			// 下一个函数
			++pINT;
			++pIAT;
		}
		// 下一个dll
		++pImport;
	}
	// 恢复原有属性
	MyVirtualProtect((LPVOID)exeFileBase, 0x400, oldProtect, &oldProtect);
}

// 跳转至原始OEP
__declspec(naked) void JmpOEP()
{
	__asm
	{
		mov ebx, dword ptr fs : [0x30];	// 获取PEB
		mov ebx, dword ptr[ebx + 0x08];	// 获取加载基址ImageBase
		//add ebx, shareData.origOEP;		// RVA+基址= 原始OEP
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
	EncodeIAT();// 加密IAT
	JmpOEP();//壳代码执行完毕,跳往真实OEP
}
