#include "stub.h"
#include "AES.h"
#include "lz4.h"

// 合并data/rdata到text段, 将text改成可读可写可执行
#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")

// 导出一个全局变量来共享数据
extern "C" __declspec(dllexport)SHAREDATA ShareData = { 0 };

// 定义函数
DefApiFun(GetProcAddress);
DefApiFun(LoadLibraryA);
DefApiFun(VirtualAlloc);
DefApiFun(VirtualProtect);
DefApiFun(VirtualFree);
DefApiFun(CreateWindowExA);
DefApiFun(ExitProcess);
DefApiFun(DefWindowProcA);
DefApiFun(GetStockObject);
DefApiFun(RegisterClassExA);
DefApiFun(ShowWindow);
DefApiFun(UpdateWindow);
DefApiFun(GetMessageA);
DefApiFun(TranslateMessage);
DefApiFun(DispatchMessageA);
DefApiFun(GetWindowTextA);
DefApiFun(PostQuitMessage);
DefApiFun(MessageBoxA);

// 获取PE头信息
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

// 获取当前加载基址
__declspec(naked) long getcurmodule()
{
	_asm {
		mov eax, dword ptr fs : [0x30]
		; PEB 中偏移为 0x08 保存的是加载基址
		mov eax, dword ptr[ebx + 0x08]
		ret;
	}
}

// 获取函数
DWORD MyGetProcAddress(DWORD Module, LPCSTR FunName)
{
	// 获取 Dos 头和 Nt 头
	auto DosHeader = (PIMAGE_DOS_HEADER)Module;
	auto NtHeader = (PIMAGE_NT_HEADERS)(Module + DosHeader->e_lfanew);
	// 获取导出表结构
	DWORD ExportRva = NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
	auto ExportTable = (PIMAGE_EXPORT_DIRECTORY)(Module + ExportRva);
	// 找到导出名称表、序号表、地址表
	auto NameTable = (DWORD*)(ExportTable->AddressOfNames + Module);
	auto FuncTable = (DWORD*)(ExportTable->AddressOfFunctions + Module);
	auto OrdinalTable = (WORD*)(ExportTable->AddressOfNameOrdinals + Module);
	// 遍历找名字
	for (DWORD i = 0; i < ExportTable->NumberOfNames; ++i)
	{
		// 获取名字
		char* Name = (char*)(NameTable[i] + Module);
		if (!strcmp(Name, FunName))
			return FuncTable[OrdinalTable[i]] + Module;
	}
	return -1;
}

// 获取 kernel32.dll 的基址
__declspec(naked) long getkernelbase()
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

// 解密区段
long XorDecryptSection()
{
	DWORD OldProtect;
	__asm
	{
		; 获取当前程序的 PEB 信息
		mov ebx, dword ptr fs : [0x30]
		; PEB 中偏移为 0x08 保存的是加载基址
		mov ebx, dword ptr[ebx + 0x08]
		; 将加载基址和 oep 相加
		add ShareData.rva, ebx
	}
	My_VirtualProtect((LPVOID)ShareData.rva, ShareData.size, PAGE_READWRITE, &OldProtect);
	//pVirtualProtect((LPVOID)ShareData.rva, ShareData.size, PAGE_READWRITE, &OldProtect);
	// 执行完了第一个汇编指令之后 ShareData.rva 就是 va 了
	for (int i = 0; i < ShareData.size; ++i)
		((BYTE*)ShareData.rva)[i] ^= ShareData.key;
	//pVirtualProtect((LPVOID)ShareData.rva, ShareData.size, OldProtect, &OldProtect);
	My_VirtualProtect((LPVOID)ShareData.rva, ShareData.size, OldProtect, &OldProtect);
}

// 跳转到原始的 oep
__declspec(naked) long JmpOEP()
{
	__asm
	{
		; 获取当前程序的 PEB 信息
		mov ebx, dword ptr fs : [0x30]
		; PEB 中偏移为 0x08 保存的是加载基址
		mov ebx, dword ptr[ebx + 0x08]
		; 将加载基址和 oep 相加
		add ebx, ShareData.OldOep
		; 跳转到原始 oep 处
		jmp ebx
	}
}

// 获取想要用到的函数
void GetAPIAddr()
{
	// 所有函数都在这里获取
	//pVirtualProtect = (PVirtualProtect)MyGetProcAddress(getkernelbase(), "VirtualProtect");
	//My_VirtualProtect = (PVirtualProtect)MyGetProcAddress(getkernelbase(), "VirtualProtect");
	My_VirtualProtect = (decltype(VirtualProtect)*)MyGetProcAddress(getkernelbase(), "VirtualProtect");
	My_GetProcAddress = (decltype(GetProcAddress)*)MyGetProcAddress(getkernelbase(), "GetProcAddress");
	My_LoadLibraryA = (decltype(LoadLibraryA)*)MyGetProcAddress(getkernelbase(), "LoadLibraryA");
	My_VirtualAlloc = (decltype(VirtualAlloc)*)MyGetProcAddress(getkernelbase(), "VirtualAlloc");
	My_VirtualFree = (decltype(VirtualFree)*)MyGetProcAddress(getkernelbase(), "VirtualFree");

	DWORD huser = (DWORD)My_LoadLibraryA("user32.dll");
	SetAPI(huser, CreateWindowExA);
	SetAPI(huser, DefWindowProcA);
	SetAPI(huser, RegisterClassExA);
	SetAPI(huser, ShowWindow);
	SetAPI(huser, UpdateWindow);
	SetAPI(huser, GetMessageA);
	SetAPI(huser, TranslateMessage);
	SetAPI(huser, DispatchMessageA);
	SetAPI(huser, GetWindowTextA);
	SetAPI(huser, PostQuitMessage);
	SetAPI(huser, MessageBoxA);

	DWORD hGdi = (DWORD)My_LoadLibraryA("gdi32.dll");
	SetAPI(hGdi, GetStockObject);
}

// 	修复原始程序重定位
void FixOldReloc()
{
	// 获取当前加载基址
	long hModule = getcurmodule();
	DWORD OldProtect;

	// 获取重定位表
	PIMAGE_BASE_RELOCATION RealocTable =
		(PIMAGE_BASE_RELOCATION)(ShareData.oldRelocRva + hModule);

	// 如果 SizeOfBlock 不为空，就说明存在重定位块
	while (RealocTable->SizeOfBlock)
	{
		// 如果重定位的数据在代码段，就需要修改访问属性
		My_VirtualProtect((LPVOID)(RealocTable->VirtualAddress + hModule),
			0x1000, PAGE_READWRITE, &OldProtect);

		// 获取重定位项数组的首地址和重定位项的数量
		int count = (RealocTable->SizeOfBlock - 8) / 2;
		TypeOffset* to = (TypeOffset*)(RealocTable + 1);

		// 遍历每一个重定位项
		for (int i = 0; i < count; ++i)
		{
			// 如果 type 的值为 3 我们才需要关注
			if (to[i].Type == 3)
			{
				// 获取到需要重定位的地址所在的位置
				DWORD* addr = (DWORD*)(hModule + RealocTable->VirtualAddress + to[i].Offset);
				// 使用这个地址，计算出新的重定位后的数据
				*addr = *addr - ShareData.oldImageBase + hModule;

			}
		}

		// 还原原区段的的保护属性
		My_VirtualProtect((LPVOID)(RealocTable->VirtualAddress + hModule),
			0x1000, OldProtect, &OldProtect);

		// 找到下一个重定位块
		RealocTable = (PIMAGE_BASE_RELOCATION)
			((DWORD)RealocTable + RealocTable->SizeOfBlock);
	}
}

// 解压缩区段
void UncompressSection()
{
	// 1.待解压的位置
	char * pSrc = (char*)(ShareData.FrontCompressRva + getcurmodule());

	//2. 申请空间
	char* pBuff = (char*)My_VirtualAlloc(0, ShareData.FrontCompressSize,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	//3. 解压缩
	LZ4_uncompress_unknownOutputSize(
		pSrc,/*压缩后的数据*/
		pBuff, /*解压出来的数据*/
		ShareData.LaterCompressSize,/*压缩后的大小*/
		ShareData.FrontCompressSize/*压缩前的大小*/);

	//4.修改属性
	DWORD OldProtect;
	My_VirtualProtect(pSrc, ShareData.FrontCompressSize, PAGE_EXECUTE_READWRITE, &OldProtect);

	//5.写入原始数据
	memcpy(pSrc, pBuff, ShareData.FrontCompressSize);

	//6.恢复属性
	My_VirtualProtect(pSrc, ShareData.FrontCompressSize, OldProtect, &OldProtect);


	//7.释放空间
	//MyVirtualFree(pBuff, 0, MEM_RELEASE);

}

void AESDecryptAllSection()
{
	//获取当前程序的基址
	DWORD dwBase = getcurmodule();

	CAES aes(ShareData.key1);
	//循环解密所有区段
	DWORD old = 0;
	for (int i = 0; i < ShareData.index; i++)
	{
		//拿到所有区段的首地址和大小
		unsigned char* pSection = (unsigned char*)ShareData.data[i][0] + dwBase;
		DWORD dwSectionSize = ShareData.data[i][1];

		//修改区段属性
		My_VirtualProtect(pSection, dwSectionSize, PAGE_EXECUTE_READWRITE, &old);

		//解密代码段
		aes.InvCipher(pSection, dwSectionSize);

		//把属性修改回去
		My_VirtualProtect(pSection, dwSectionSize, old, &old);
	}
}

// 恢复数据目录表信息
void RecoverDataDirTab()
{
	// 1 获取当前程序基址
	//char* dwBase = (char*)pfnGetMoudleHandleA(NULL);
	DWORD dwBase = getcurmodule();
	// 2 遍历数据目录表
	DWORD dwNumOfDataDir = ShareData.dwNumOfDataDir;
	DWORD dwOldAttr = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = (GetOptHeader(dwBase)->DataDirectory);
	for (DWORD i = 0; i < dwNumOfDataDir; i++)
	{
		// 3 资源表无需修改
		if (i == 2)
		{
			pDataDirectory++;
			continue;
		}
		// 4 修改属性为可写
		My_VirtualProtect(pDataDirectory, 0x8, PAGE_EXECUTE_READWRITE, &dwOldAttr);
		// 5 恢复数据目录表项
		pDataDirectory->VirtualAddress = ShareData.dwDataDir[i][0];
		pDataDirectory->Size = ShareData.dwDataDir[i][1];
		// 6 恢复原属性
		My_VirtualProtect(pDataDirectory, 0x8, dwOldAttr, &dwOldAttr);
		// 7 表项指针+1,继续遍历
		pDataDirectory++;
	}
}

// 静态反调试
void StaticAntiDebug()
{
	bool BeingDugged = false;
	__asm
	{
		mov eax, DWORD ptr fs : [0x30];//获取peb
		mov al, byte ptr ds : [eax + 0x02];//获取peb.beingdugged
		mov BeingDugged, al;
	}
	if (BeingDugged)
	{
		My_MessageBoxA(NULL, "调试状态", "警告", MB_OK);
		My_ExitProcess(1);
	}
}

// 加密IAT
void EncodeIAT()
{
	// 1 获取当前模块基址
	long Module = getcurmodule();
	//_asm {
	//	mov ebx, dword ptr fs : [0x30];
	//	; PEB 中偏移为 0x08 保存的是加载基址
	//	mov ebx, dword ptr[ebx + 0x08]
	//	mov Module, ebx;
	//}

	// 2 加密IAT(中转站: mov eax 123;jmp eax=jmp 123
	//	//00FE12B2 | 50				| push eax	|
	//	//00FE12B3 | 58				| pop eax	| push eip; jmp xxxxxxxxx
	//	//00FE12B4 | 60				| pushad	|
	//	//00FE12B5 | 61				| popad		|
	//	//00FE12B6 | B8 11111111	| mov eax, 11111111 |
	//	//00FE12BB | FFE0			| jmp eax |
	char shellcode[] = { "\x50\x58\x60\x61\xB8\x11\x11\x11\x11\xFF\xE0" };
	// 3 获取导入表地址=偏移+基址
	PIMAGE_IMPORT_DESCRIPTOR pImport =(PIMAGE_IMPORT_DESCRIPTOR)(Module + ShareData.ImportRva);
	// 4 循环遍历导入表(以0结尾
	while (pImport->Name)
	{
		// 5 加载相关dll
		char * dllName = (char*)(pImport->Name + Module);
		HMODULE Mod = My_LoadLibraryA(dllName);
		// 6 获取INT/IAT地址
		DWORD * pInt = (DWORD *)(pImport->OriginalFirstThunk + Module);
		DWORD * pIat = (DWORD *)(pImport->FirstThunk + Module);
		// 7 循环遍历INT(以0结尾
		while (*pInt)// 其指向THUNK结构体,内部是联合体,不管哪个字段有效,都表示一个地址罢了
		{
			// 8 获取API地址
			IMAGE_IMPORT_BY_NAME * FunName = (IMAGE_IMPORT_BY_NAME*)(*pInt + Module);
			LPVOID Fun = My_GetProcAddress(Mod, FunName->Name);
			// 9 申请空间保存"中转站"代码,并将真实地址写入
			char * pbuff =(char*)My_VirtualAlloc(0, 100, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			memcpy(pbuff, shellcode, sizeof(shellcode));// 假地址保存"中转站"代码
			*(DWORD*)&pbuff[5] = (DWORD)Fun;// mov eax,真实地址,jmp eax=jmp 真实地址
			// 10 向IAT填充假地址(可中转到真地址
			DWORD old;
			My_VirtualProtect(pIat, 4, PAGE_EXECUTE_READWRITE, &old);// 可写属性
			*pIat = (DWORD)pbuff;// 不必管联合体字段,直接赋值到*p即可
			My_VirtualProtect(pIat, 4, old, &old);// 恢复原属性
			// 11 下个INT/IAT
			pInt++;
			pIat++;
		}

		// 12 下一个导入表
		pImport++;
	}

}

// 回调函数
LRESULT CALLBACK MyWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
	// 保存编辑框句柄
	static HWND Edithwnd = 0;

	switch (msg)
	{
	case WM_CREATE:
	{
		// 创建窗口
		HINSTANCE instance = (HINSTANCE)getcurmodule();

		//HWND hBit = pfnCreateWindowEx(0, L"static", L"密码", WS_CHILD | WS_VISIBLE,
		//	50, 50, 30, 20, hWnd, (HMENU)10004, g_hInstance, NULL);
		//hEdit = pfnCreateWindowEx(0, L"edit", L"", WS_CHILD | WS_VISIBLE | WS_BORDER,
		//	100, 50, 120, 20, hWnd, (HMENU)10003, g_hInstance, NULL);
		//pfnCreateWindowEx(0, L"button", L"确定", WS_CHILD | WS_VISIBLE,
		//	50, 100, 60, 30, hWnd, (HMENU)10001, g_hInstance, NULL);
		//pfnCreateWindowEx(0, L"button", L"取消", WS_CHILD | WS_VISIBLE,
		//	150, 100, 60, 30, hWnd, (HMENU)10002, g_hInstance, NULL);


		Edithwnd = My_CreateWindowExA(0, "edit", NULL, WS_VISIBLE | WS_CHILD | WS_BORDER, 100, 50, 120, 20,
			hwnd, (HMENU)0x1000, instance, 0);
		My_CreateWindowExA(0, "button", "确定", WS_VISIBLE | WS_CHILD, 50, 100, 60, 30, hwnd, (HMENU)0x1001, instance, 0);
		My_CreateWindowExA(0, "button", "取消", WS_VISIBLE | WS_CHILD, 150, 100, 60, 30, hwnd, (HMENU)0x1002, instance, 0);
		HWND hBit = My_CreateWindowExA(0, "static", "密码", WS_CHILD | WS_VISIBLE, 50, 50, 30, 20, hwnd, (HMENU)1003, instance, NULL);

		//Edithwnd = My_CreateWindowExA(0, "edit", NULL, WS_VISIBLE | WS_CHILD | WS_BORDER, 20, 20, 100, 20,
		//	hwnd, (HMENU)0x1000, instance, 0);
		//My_CreateWindowExA(0, "button", "确定", WS_VISIBLE | WS_CHILD, 30, 50, 50, 20,hwnd, (HMENU)0x1001, instance, 0);



		break;
	}
	case WM_COMMAND:
	{
		// 按钮点击事件
		if (wparam == 0x1001)
		{
			char buff[100];
			// 获取文本
			My_GetWindowTextA(Edithwnd, buff, 100);
			if (!strcmp(buff, "123"))
			{
				//退出窗口
				My_PostQuitMessage(0);
				My_ShowWindow(hwnd, SW_HIDE);
				break;
			}
		}

		break;
	}

	}

	return My_DefWindowProcA(hwnd, msg, wparam, lparam);
}

// 显示窗口
void AlertPassWindow()
{
	// 0 创建窗口类
	WNDCLASSEXA ws = { sizeof(ws) };
	ws.style = CS_HREDRAW | CS_VREDRAW;
	ws.hInstance = (HINSTANCE)getcurmodule();
	ws.lpfnWndProc = MyWndProc;
	ws.hbrBackground = (HBRUSH)My_GetStockObject(WHITE_BRUSH);
	ws.lpszClassName = "MyPack";

	//1 .注册窗口类
	My_RegisterClassExA(&ws);

	//2. 创建窗口
	HWND hwnd = My_CreateWindowExA(0,
		"MyPack",
		"MyPack",
		WS_OVERLAPPEDWINDOW,
		100, 100, 300, 200, NULL, NULL,
		(HINSTANCE)getcurmodule(), NULL);

	//3 . 显示更新
	My_ShowWindow(hwnd, SW_SHOW);
	My_UpdateWindow(hwnd);

	//4. 消息循环
	MSG msg;
	while (My_GetMessageA(&msg, 0, 0, 0))
	{
		//5. 转换消息 分发消息 
		My_TranslateMessage(&msg);
		My_DispatchMessageA(&msg);
	}

}

// 混淆执行函数
void _stdcall ConfuseExecute(DWORD funcAddr)
{
	// 混淆+花指令来执行funcAddr
	_asm
	{
		jmp code1;

	code2:
		_emit 0xeb; // jmp指令
		_emit 0x04; // jmp的偏移；本身2，4+2=6(首地址+6，尾地址+4)

		// 3EFF9458 EB023412 : EB02=jmp 2
		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x123402EB]; // 3EFF9458 EB023412，jmp 4到EB02 = jmp 2(跳过3412)

		// jmp 2到此												  
		_emit 0xe8;// call 指令
		_emit 0x00;// 后4字节表偏移=0
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;

		// call 0 到此
		_emit 0xeb;// jmp
		_emit 0x0e;// jmp e

		// 为0x0e充数(11字节
		PUSH 0x0;// 6A 00
		PUSH 0x0;// 6A 00
		MOV EAX, DWORD PTR FS : [0];//64A1 00000000
		PUSH EAX; // 50

		// 3EFF9458 83C01950 : 58=pop eax、83C019=add eax,0x19、50=push eax
		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x5019C083];//3EFF9458 83C01950，jmp e到58=pop eax

		// 执行函数
		push funcAddr;	// 压入待执行函数
		retn;				// pop eip，执行栈顶的函数

		// 执行完函数后,跳往结束
		jmp over;

		// 加一层跳转
	code1:
		jmp code2;

		//空,结束
	over:
	}
}

// 全部壳功能代码(传入混淆函数来执行
void PackCode()
{
	// 执行具体的函数(再经过一次混淆
	ConfuseExecute((DWORD)GetAPIAddr);			// 获取函数的API地址
	//ConfuseExecute((DWORD)xorsection);		// 解密代码段(异或
	ConfuseExecute((DWORD)AESDecryptAllSection);	// 解密代码段(AES
	ConfuseExecute((DWORD)UncompressSection);		// 解压缩区段
	ConfuseExecute((DWORD)StaticAntiDebug);	// 反调试
	ConfuseExecute((DWORD)AlertPassWindow);	// 恢复数据目录表
	//ConfuseExecute((DWORD)ShowMyWindows);	// 恢复数据目录表//
	ConfuseExecute((DWORD)FixOldReloc);		// 修复原始程序重定位
	ConfuseExecute((DWORD)EncodeIAT);		// 加密IAT
	//ConfuseExecute((DWORD)CallTls);			// 执行TLS回调函数//here
}

// 壳代码起始函数
extern "C" __declspec(dllexport) __declspec(naked) void start()
{
	// 花指令
	_asm
	{
		PUSH - 1
		PUSH 0
		PUSH 0
		MOV EAX, DWORD PTR FS : [0]
		PUSH EAX
		MOV DWORD PTR FS : [0], ESP
		SUB ESP, 0x68
		PUSH EBX
		PUSH ESI
		PUSH EDI
		POP EAX
		POP EAX
		POP EAX
		ADD ESP, 0x68
		POP EAX
		MOV DWORD PTR FS : [0], EAX
		POP EAX
		POP EAX
		POP EAX
		POP EAX
		MOV EBP, EAX
	}

	// 混淆执行
	ConfuseExecute((DWORD)PackCode);

	// 正常执行
	//getapi();//获取函数的API地址
	//// 解密(解压缩)区段
	//xorsection();
	////DecryptSection();//解密代码段
	//uncompress();// 解压缩区段
	////RecoverDataDirTab();//恢复数据目录表
	////StaticAntiDebug();//反调试
	////AlertPassBox();//密码弹框
	//ShowMyWindows();//密码弹框
	//FixOldReloc();// 修复原始程序重定位
	//EncodeIat();//加密IAT

	JmpOEP();// 跳转到原始 oep
}
