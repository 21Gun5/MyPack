#include "stub.h"
#include "AES.h"
// 提供壳代码的Stub部分,通常用于:解压缩/解密'修复重定位表'修复/加密IAT表'调用TLS函数等

// 合并data rdata 到text段, 将text改成可读可写可执行
#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
#pragma comment(linker,"/section:.text,RWE")

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

//定义函数指针和变量
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

void Decrypt()
{
	//获取当前程序的基址
	DWORD dwBase = (DWORD)pfnGetMoudleHandleA(NULL);

	AES aes(shareData.key);
	//循环解密所有区段
	DWORD old = 0;
	for (int i = 0; i < shareData.index - 1; i++)
	{
		//拿到所有区段的首地址和大小
		unsigned char* pSection = (unsigned char*)shareData.data[i][0] + dwBase;
		DWORD dwSectionSize = shareData.data[i][1];

		//修改区段属性
		MyVirtualProtect(pSection, dwSectionSize, PAGE_EXECUTE_READWRITE, &old);

		//解密代码段
		aes.InvCipher(pSection, dwSectionSize);

		//把属性修改回去
		MyVirtualProtect(pSection, dwSectionSize, old, &old);
	}
}

void GetApis()
{
	HMODULE hKernel32;

	_asm
	{
		pushad;
		; //获取kernel32.dll的加载基址;
		;// 1. 找到PEB的首地址;
		mov eax, fs:[0x30]; eax = > peb首地址;
		; 2. 得到PEB.Ldr的值;
		mov eax, [eax + 0ch]; eax = > PEB.Ldr的值;
		mov eax, [eax + 0ch]; eax = > PEB.Ldr的值;
		; 3. 得到_PEB_LDR_DATA.InLoadOrderMoudleList.Flink的值, 实际得到的就是主模块节点的首地址;
		mov eax, [eax]; eax = > _PEB_LDR_DATA.InLoadOrderMoudleList.Flink(NTDLL);
		; 4. 再获取下一个;
		mov eax, [eax]; _LDR_DATA_TABLE_ENTRY.InLoadOrderMoudleList.Flink(kernel32), ;
		mov eax, [eax + 018h]; _LDR_DATA_TABLE_ENTRY.DllBase;
		mov hKernel32, eax;;
		; 遍历导出表;
		; 1. dos头-- > nt头-- > 扩展头-- > 数据目录表;
		mov ebx, [eax + 03ch]; eax = > 偏移到NT头;
		add ebx, eax; ebx = > NT头的首地址;
		add ebx, 078h; ebx = >
			; 2. 得到导出表的RVA;
		mov ebx, [ebx];
		add ebx, eax; ebx == > 导出表首地址(VA);
		; 3. 遍历名称表找到GetProcAddress;
		; 3.1 找到名称表的首地址;
		lea ecx, [ebx + 020h];
		mov ecx, [ecx]; // ecx => 名称表的首地址(rva);
		add ecx, eax; // ecx => 名称表的首地址(va);
		xor edx, edx; // 作为index来使用.
		; 3.2 遍历名称表;
	_WHILE:;
		mov esi, [ecx + edx * 4]; esi = > 名称的rva;
		lea esi, [esi + eax]; esi = > 名称首地址;
		cmp dword ptr[esi], 050746547h; 47657450 726F6341 64647265 7373;
		jne _LOOP;
		cmp dword ptr[esi + 4], 041636f72h;
		jne _LOOP;
		cmp dword ptr[esi + 8], 065726464h;
		jne _LOOP;
		cmp word  ptr[esi + 0ch], 07373h;
		jne _LOOP;
		; 找到之后;
		mov edi, [ebx + 024h]; edi = > 名称的序号表的rva;
		add edi, eax; edi = > 名称的序号表的va;

		mov di, [edi + edx * 2]; 序号表是2字节的元素, 因此是 * 2;
		; edi保存的是GetProcAddress的在;
		; 地址表中的下标;
		and edi, 0FFFFh;
		; 得到地址表首地址;
		mov edx, [ebx + 01ch]; edx = > 地址表的rva;
		add edx, eax; edx = > 地址表的va;
		mov edi, [edx + edi * 4]; edi = > GetProcAddress的rva;
		add edi, eax; ; edx = > GetProcAddress的va;
		mov MyGetProcAddress, edi;
		jmp _ENDWHILE;
	_LOOP:;
		inc edx; // ++index;
		jmp _WHILE;
	_ENDWHILE:;
		popad;
	}
	//给函数指针变量赋值
	//Kernel32
	MyLoadLibraryA = (FnLoadLibraryA)MyGetProcAddress(hKernel32, "LoadLibraryA");
	MyVirtualProtect = (FnVirtualProtect)MyGetProcAddress(hKernel32, "VirtualProtect");
	pfnGetMoudleHandleA = (fnGetMoudleHandleA)MyGetProcAddress(hKernel32, "GetModuleHandleA");
	pfnExitProcess = (fnExitProcess)MyGetProcAddress(hKernel32, "ExitProcess");
	pfnVirtualAlloc = (FnVirtualAlloc)MyGetProcAddress(hKernel32, "VirtualAlloc");
	pfnRtlMoveMemory = (FnRtlMoveMemory)MyGetProcAddress(hKernel32, "RtlMoveMemory");
	HMODULE hUser32 = (HMODULE)MyLoadLibraryA((char*)"user32.dll");

	//User32
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

//here
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
//// 获取需要的API地址
//void GetApis()
//{
//	// 获取MyGetProcAddress//here
//	_asm
//	{
//		pushad;
//		//获取kernel32.dll的加载基址;
//		// 1. 找到PEB的首地址;
//		mov eax, fs:[0x30]; eax = > peb首地址;
//		// 2. 得到PEB.Ldr的值;
//		mov eax, [eax + 0ch]; eax = > PEB.Ldr的值;
//		mov eax, [eax + 0ch]; eax = > PEB.Ldr的值;
//		// 3. 得到_PEB_LDR_DATA.InLoadOrderMoudleList.Flink的值, 实际得到的就是主模块节点的首地址;
//		mov eax, [eax]; eax = > _PEB_LDR_DATA.InLoadOrderMoudleList.Flink(NTDLL);
//		// 4. 再获取下一个;
//		mov eax, [eax]; _LDR_DATA_TABLE_ENTRY.InLoadOrderMoudleList.Flink(kernel32), ;
//		mov eax, [eax + 018h]; _LDR_DATA_TABLE_ENTRY.DllBase;
//		//mov hKernel32, eax;
//		// 遍历导出表;
//		// 1. dos头-- > nt头-- > 扩展头-- > 数据目录表;
//		mov ebx, [eax + 03ch]; //eax = > 偏移到NT头;
//		add ebx, eax; //ebx = > NT头的首地址;
//		add ebx, 078h; //ebx = >
//		// 2. 得到导出表的RVA;
//		mov ebx, [ebx];
//		add ebx, eax; //ebx == > 导出表首地址(VA);
//		// 3. 遍历名称表找到GetProcAddress;
//		// 3.1 找到名称表的首地址;
//		lea ecx, [ebx + 020h];
//		mov ecx, [ecx]; // ecx => 名称表的首地址(rva);
//		add ecx, eax; // ecx => 名称表的首地址(va);
//		xor edx, edx; // 作为index来使用.
//		// 3.2 遍历名称表;
//	_WHILE:;
//		mov esi, [ecx + edx * 4];// esi = > 名称的rva;
//		lea esi, [esi + eax]; //esi = > 名称首地址;
//		cmp dword ptr[esi], 050746547h; //47657450 726F6341 64647265 7373;
//		jne _LOOP;
//		cmp dword ptr[esi + 4], 041636f72h;
//		jne _LOOP;
//		cmp dword ptr[esi + 8], 065726464h;
//		jne _LOOP;
//		cmp word  ptr[esi + 0ch], 07373h;
//		jne _LOOP;
//		//; 找到之后;
//		mov edi, [ebx + 024h]//; edi = > 名称的序号表的rva;
//			add edi, eax;// edi = > 名称的序号表的va;
//		mov di, [edi + edx * 2];// 序号表是2字节的元素, 因此是 * 2;
//		//; edi保存的是GetProcAddress的在;
//		//; 地址表中的下标;
//		and edi, 0FFFFh;
//		//; 得到地址表首地址;
//		mov edx, [ebx + 01ch];// edx = > 地址表的rva;
//		add edx, eax; //edx = > 地址表的va;
//		mov edi, [edx + edi * 4]; //edi = > GetProcAddress的rva;
//		add edi, eax; //; edx = > GetProcAddress的va;
//		mov MyGetProcAddress, edi;
//		jmp _ENDWHILE;
//	_LOOP://;
//		inc edx; // ++index;
//		jmp _WHILE;
//	_ENDWHILE:;
//		popad;
//	}
//
//	//Kernel32
//	HMODULE hKernel32 = (HMODULE)GetKernelBase();
//	MyLoadLibraryA = (FnLoadLibraryA)MyGetProcAddress(hKernel32, "LoadLibraryA");
//	MyVirtualProtect = (FnVirtualProtect)MyGetProcAddress(hKernel32, "VirtualProtect");
//	pfnGetMoudleHandleA = (fnGetMoudleHandleA)MyGetProcAddress(hKernel32, "GetModuleHandleA");
//	pfnExitProcess = (fnExitProcess)MyGetProcAddress(hKernel32, "ExitProcess");
//	pfnVirtualAlloc = (FnVirtualAlloc)MyGetProcAddress(hKernel32, "VirtualAlloc");
//	pfnRtlMoveMemory = (FnRtlMoveMemory)MyGetProcAddress(hKernel32, "RtlMoveMemory");
//	// User32
//	HMODULE hUser32 = (HMODULE)MyLoadLibraryA((char*)"user32.dll");
//	pfnRegisterClassEx = (fnRegisterClassEx)MyGetProcAddress(hUser32, "RegisterClassExW");
//	pfnCreateWindowEx = (fnCreateWindowEx)MyGetProcAddress(hUser32, "CreateWindowExW");
//	pfnUpdateWindow = (fnUpdateWindow)MyGetProcAddress(hUser32, "UpdateWindow");
//	pfnShowWindow = (fnShowWindow)MyGetProcAddress(hUser32, "ShowWindow");
//	pfnGetMessage = (fnGetMessage)MyGetProcAddress(hUser32, "GetMessageW");
//	pfnTranslateMessage = (fnTranslateMessage)MyGetProcAddress(hUser32, "TranslateMessage");
//	pfnDispatchMessageW = (fnDispatchMessageW)MyGetProcAddress(hUser32, "DispatchMessageW");
//	pfnGetWindowTextW = (fnGetWindowTextW)MyGetProcAddress(hUser32, "GetWindowTextW");
//	pfnSendMessageW = (fnSendMessageW)MyGetProcAddress(hUser32, "SendMessageW");
//	pfnDefWindowProcW = (fnDefWindowProcW)MyGetProcAddress(hUser32, "DefWindowProcW");
//	pfnPostQuitMessage = (fnPostQuitMessage)MyGetProcAddress(hUser32, "PostQuitMessage");
//	pfnFindWindowW = (fnFindWindowW)MyGetProcAddress(hUser32, "FindWindowW");
//	pfnMessageBoxW = (fnMessageBoxW)MyGetProcAddress(hUser32, "MessageBoxW");
//}


////////////////////////////////// 弹密码框 //////////////////////////////////
HINSTANCE g_hInstance;	//密码窗口实例句柄
HWND hEdit;				//输入密码窗口
BOOL bSuccess;			//密码验证	
//窗口消息回调函数
LRESULT CALLBACK WndPrco(HWND, UINT, WPARAM, LPARAM);
int MyWcscmp(const wchar_t * src, const wchar_t * dst)
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
void AlertPasswordBox()
{
	//注册窗口类
	g_hInstance = (HINSTANCE)pfnGetMoudleHandleA(NULL);
	WNDCLASSEX ws;
	ws.cbSize = sizeof(WNDCLASSEX);
	ws.hInstance = g_hInstance;
	ws.cbWndExtra = ws.cbClsExtra = NULL;
	ws.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	ws.hIcon = NULL;
	ws.hIconSm = NULL;
	ws.hCursor = NULL;
	ws.style = CS_VREDRAW | CS_HREDRAW;
	ws.lpszMenuName = NULL;
	ws.lpfnWndProc = (WNDPROC)WndPrco;		//	回调函数
	ws.lpszClassName = TEXT("MyPack");
	pfnRegisterClassEx(&ws);
	//创建窗口
	HWND hWnd = pfnCreateWindowEx(0, TEXT("MyPack"), TEXT("请输入密码"), WS_OVERLAPPED | WS_VISIBLE,
		100, 100, 300, 200, NULL, NULL, g_hInstance, NULL);
	//更新窗口
	//pfnUpdateWindow(hWnd);
	pfnShowWindow(hWnd, SW_SHOW);
	//消息处理
	MSG msg = { 0 };
	while (pfnGetMessage(&msg, NULL, NULL, NULL))
	{
		pfnTranslateMessage(&msg);
		pfnDispatchMessageW(&msg);
	}
}
LRESULT CALLBACK WndPrco(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	HDC hdc;
	PAINTSTRUCT ps;
	switch (msg)
	{
	case WM_CREATE:
	{
		HWND hBit = pfnCreateWindowEx(0, L"static", L"密码", WS_CHILD | WS_VISIBLE,
			50, 50, 30, 20, hWnd, (HMENU)10004, g_hInstance, NULL);
		hEdit = pfnCreateWindowEx(0, L"edit", L"", WS_CHILD | WS_VISIBLE | WS_BORDER,
			100, 50, 120, 20, hWnd, (HMENU)10003, g_hInstance, NULL);
		pfnCreateWindowEx(0, L"button", L"确定", WS_CHILD | WS_VISIBLE,
			50, 100, 60, 30, hWnd, (HMENU)10001, g_hInstance, NULL);
		pfnCreateWindowEx(0, L"button", L"取消", WS_CHILD | WS_VISIBLE,
			150, 100, 60, 30, hWnd, (HMENU)10002, g_hInstance, NULL);
		bSuccess = FALSE;
		break;
	}
	case  WM_COMMAND:
	{
		WORD wHigh = HIWORD(wParam);
		WORD wLow = LOWORD(wParam);
		switch (wLow)
		{
		case 10001:
		{
			TCHAR GetKey[10] = { 0 };
			pfnGetWindowTextW(hEdit, GetKey, 10);
			//如果密码等于123
			if (MyWcscmp(GetKey, L"123") == 0)
			{
				bSuccess = TRUE;
				//如果密码匹配 正常运行
				pfnSendMessageW(hWnd, WM_CLOSE, NULL, NULL);
			}
			else
			{
				//密码不匹配退出程序
				pfnExitProcess(1);
			}
			break;
		}
		case 10002:		//取消按钮
		{
			pfnExitProcess(1);
			break;
		}

		default:
			break;
		}
		break;
	}
	case WM_PAINT:
	{
		hdc = pfnBeginPaint(hWnd, &ps);
		// TODO:  在此添加任意绘图代码...
		pfnEndPaint(hWnd, &ps);
		break;
	}
	case WM_CLOSE:case WM_QUIT:case WM_DESTROY:
	{
		if (bSuccess)
		{
			pfnPostQuitMessage(0);
		}
		else
		{
			pfnExitProcess(1);
		}
	}

	default:
		return pfnDefWindowProcW(hWnd, msg, wParam, lParam);
	}
	return 0;
}
////////////////////////////////// 弹密码框 //////////////////////////////////

void SetFileHeaderProtect(bool nWrite)
{
	//获取当前程序的加载基址
	DWORD ImageBase = (DWORD)pfnGetMoudleHandleA(NULL);
	DWORD nOldProtect = 0;
	if (nWrite)
		MyVirtualProtect((LPVOID)ImageBase, 0x400, PAGE_EXECUTE_READWRITE, &nOldProtect);
	else
		MyVirtualProtect((LPVOID)ImageBase, 0x400, nOldProtect, &nOldProtect);
}
void AntiDebug()
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
		pfnMessageBoxW(NULL, L"镇定一下 你被调试了", L"注意", MB_OK);
	}

}
void FixImportTable_Normal()
{
	//设置文件属性为可写
	SetFileHeaderProtect(true);
	//获取当前程序的加载基址
	DWORD ImageBase = (DWORD)pfnGetMoudleHandleA(NULL);

	IMAGE_THUNK_DATA* pInt = NULL;
	IMAGE_THUNK_DATA* pIat = NULL;
	SIZE_T impAddress = 0;
	HMODULE	hImpModule = 0;
	DWORD dwOldProtect = 0;
	IMAGE_IMPORT_BY_NAME* pImpName = 0;

	if (!GetOptHeader(ImageBase)->DataDirectory[1].VirtualAddress)return;

	//导入表=导入表偏移+加载基址
	IMAGE_IMPORT_DESCRIPTOR* pImp = (IMAGE_IMPORT_DESCRIPTOR*)(GetOptHeader(ImageBase)->DataDirectory[1].VirtualAddress + ImageBase);


	while (pImp->Name)
	{
		//IAT=偏移加加载基址
		pIat = (IMAGE_THUNK_DATA*)(pImp->FirstThunk + ImageBase);
		if (pImp->OriginalFirstThunk == 0) // 如果不存在INT则使用IAT
		{
			pInt = pIat;
		}
		else
		{
			pInt = (IMAGE_THUNK_DATA*)(pImp->OriginalFirstThunk + ImageBase);
		}

		// 加载dll
		hImpModule = (HMODULE)MyLoadLibraryA((char*)(pImp->Name + ImageBase));
		//导入函数地址
		while (pInt->u1.Function)
		{
			//判断导入的方式、序号还是名称
			if (!IMAGE_SNAP_BY_ORDINAL(pInt->u1.Ordinal))
			{
				pImpName = (IMAGE_IMPORT_BY_NAME*)(pInt->u1.Function + ImageBase);
				impAddress = (SIZE_T)MyGetProcAddress(hImpModule, (char*)pImpName->Name);
			}
			else
			{
				impAddress = (SIZE_T)MyGetProcAddress(hImpModule, (char*)(pInt->u1.Function & 0xFFFF));
			}

			MyVirtualProtect(&pIat->u1.Function, sizeof(pIat->u1.Function), PAGE_READWRITE, &dwOldProtect);


			pIat->u1.Function = impAddress;
			MyVirtualProtect(&pIat->u1.Function, sizeof(pIat->u1.Function), dwOldProtect, &dwOldProtect);
			++pInt;
			++pIat;
		}
		++pImp;
	}
	SetFileHeaderProtect(false);
}
void RecoverDataDir()
{
	//获取当前程序的加载基址
	char* dwBase = (char*)pfnGetMoudleHandleA(NULL);
	//获取数据目录表的个数
	DWORD dwNumOfDataDir = shareData.dwNumOfDataDir;

	DWORD dwOldAttr = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = (GetOptHeader((DWORD)dwBase)->DataDirectory);
	//遍历数据目录表
	for (DWORD i = 0; i < dwNumOfDataDir; i++)
	{
		if (i == 2)
		{
			pDataDirectory++;
			continue;
		}

		//修改属性为可读可写
		MyVirtualProtect(pDataDirectory, 0x8, PAGE_EXECUTE_READWRITE, &dwOldAttr);

		//还原数据目录表项
		pDataDirectory->VirtualAddress = shareData.dwDataDir[i][0];
		pDataDirectory->Size = shareData.dwDataDir[i][1];

		//把属性修改回去
		MyVirtualProtect(pDataDirectory, 0x8, dwOldAttr, &dwOldAttr);

		pDataDirectory++;
	}
}
void CallTls()
{
	//获取当前程序的加载基址
	DWORD dwBase = (DWORD)pfnGetMoudleHandleA(NULL);
	//获取Tls表
	DWORD dwTlsRva = GetOptHeader(dwBase)->DataDirectory[9].VirtualAddress;
	if (dwTlsRva != 0)
	{
		PIMAGE_TLS_DIRECTORY pTlsTab = (PIMAGE_TLS_DIRECTORY)(dwTlsRva + dwBase);
		if (pTlsTab->AddressOfCallBacks == 0)
		{
			return;
		}
		DWORD nTlsCallBacks = *(DWORD*)pTlsTab->AddressOfCallBacks;
		__asm
		{
			cmp nTlsCallBacks, 0
			je ENDCALL
			push 0
			push 1
			push dwBase
			call nTlsCallBacks
			ENDCALL :
		}
	}

}


DWORD EncryptFun(DWORD dwFunAddr)
{
	// 1.申请内存空间
	DWORD dwNewMem = (DWORD)pfnVirtualAlloc(NULL, 0x20, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// 2.加密函数地址
	//DWORD dwEncryptFunAddr = dwFunAddr ^ 0x15151515;
	DWORD dwEncryptFunAddr = 0;
	_asm
	{
		push eax;
		mov eax, dwFunAddr;
		xor eax, 0x15151515;
		mov dwEncryptFunAddr, eax;
		pop eax;
	}

	// 3.对OpCode[11]处的地址进行改写
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
	OpCode[11] = dwEncryptFunAddr;					// 0x85
	OpCode[12] = dwEncryptFunAddr >> 0x08;			// 0xEE
	OpCode[13] = dwEncryptFunAddr >> 0x10;			// 0xCB
	OpCode[14] = dwEncryptFunAddr >> 0x18;			// 0x60

	// 4.将数据拷贝到申请的内存
	pfnRtlMoveMemory((LPVOID)dwNewMem, OpCode, 0x20);

	// 5.返回新的函数地址
	return dwNewMem;
}
void EncodeIAT()
{
	//设置文件属性为可写
	SetFileHeaderProtect(true);
	//获取当前程序的加载基址
	DWORD ImageBase = (DWORD)pfnGetMoudleHandleA(NULL);

	IMAGE_THUNK_DATA* pInt = NULL;
	IMAGE_THUNK_DATA* pIat = NULL;
	SIZE_T impAddress = 0;
	HMODULE	hImpModule = 0;
	DWORD dwOldProtect = 0;
	IMAGE_IMPORT_BY_NAME* pImpName = 0;

	if (!GetOptHeader(ImageBase)->DataDirectory[1].VirtualAddress)return;

	//导入表=导入表偏移+加载基址
	IMAGE_IMPORT_DESCRIPTOR* pImp = (IMAGE_IMPORT_DESCRIPTOR*)(GetOptHeader(ImageBase)->DataDirectory[1].VirtualAddress + ImageBase);


	while (pImp->Name)
	{
		//IAT=偏移加加载基址
		pIat = (IMAGE_THUNK_DATA*)(pImp->FirstThunk + ImageBase);
		if (pImp->OriginalFirstThunk == 0) // 如果不存在INT则使用IAT
		{
			pInt = pIat;
		}
		else
		{
			pInt = (IMAGE_THUNK_DATA*)(pImp->OriginalFirstThunk + ImageBase);
		}

		// 加载dll
		hImpModule = (HMODULE)MyLoadLibraryA((char*)(pImp->Name + ImageBase));
		//导入函数地址
		while (pInt->u1.Function)
		{
			//判断导入的方式、序号还是名称
			if (!IMAGE_SNAP_BY_ORDINAL(pInt->u1.Ordinal))
			{
				pImpName = (IMAGE_IMPORT_BY_NAME*)(pInt->u1.Function + ImageBase);
				impAddress = (SIZE_T)MyGetProcAddress(hImpModule, (char*)pImpName->Name);
			}
			else
			{
				impAddress = (SIZE_T)MyGetProcAddress(hImpModule, (char*)(pInt->u1.Function & 0xFFFF));
			}

			MyVirtualProtect(&pIat->u1.Function, sizeof(pIat->u1.Function), PAGE_READWRITE, &dwOldProtect);


			pIat->u1.Function = EncryptFun(impAddress);
			MyVirtualProtect(&pIat->u1.Function, sizeof(pIat->u1.Function), dwOldProtect, &dwOldProtect);
			++pInt;
			++pIat;
		}
		++pImp;
	}
	SetFileHeaderProtect(false);
}

////here
//////////////////////////////////// 加密IAT //////////////////////////////////
//// 替换函数地址(用于加密IAT
//DWORD ReplaceFuncAddr(DWORD dwFunAddr)
//{
//	// 申请内存空间,其首地址作为函数新地址
//	DWORD dwNewMem = (DWORD)pfnVirtualAlloc(NULL, 0x20, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//
//	// 加密函数地址(^ 0x15151515
//	DWORD dwEncryptFunAddr = dwFunAddr ^ 0x15151515;
//	// 解密IAT的ShellCode(带有花指令;必须BYTE类型
//	BYTE OpCode[] = {
//					0xE8, 0x01, 0x00, 0x00,
//					0x00, 0xE9, 0x58, 0xEB,
//					0x01, 0xE8, 0xB8, 0x85,
//					0xEE, 0xCB, 0x60, 0xEB,
//					0x01, 0x15, 0x35, 0x15,
//					0x15, 0x15, 0x15, 0xEB,
//					0x01, 0xFF, 0x50, 0xEB,
//					0x02, 0xFF, 0x15, 0xC3
//	};
//	// 把函数地址写入到解密的ShellCode中
//	OpCode[11] = dwEncryptFunAddr;					// 0x85
//	OpCode[12] = dwEncryptFunAddr >> 0x08;			// 0xEE
//	OpCode[13] = dwEncryptFunAddr >> 0x10;			// 0xCB
//	OpCode[14] = dwEncryptFunAddr >> 0x18;			// 0x60
//	// 将数据拷贝到申请的内存
//	pfnRtlMoveMemory((LPVOID)dwNewMem, OpCode, 0x20);
//	// 返回新的函数地址
//	return dwNewMem;
//}
//// 加密IAT
//void EncodeIAT()
//{
//	// 获取加载基址(exe源程序
//	DWORD exeFileBase = (DWORD)fnGetMoudleHandleA(NULL);
//	// 设置可写的访问属性
//	DWORD oldProtect = 0;
//	MyVirtualProtect((LPVOID)exeFileBase, 0x400, PAGE_READWRITE, &oldProtect);
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
//		dllBase = (DWORD)MyLoadLibraryA(dllName);
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
//			MyVirtualProtect(&pIAT->u1.Function, sizeof(pIAT->u1.Function), PAGE_READWRITE, &oldProtect2);
//			//pIAT->u1.Function = 0;// 修改IAT
//			pIAT->u1.Function = ReplaceFuncAddr(funcAddr);// 修改IAT(替换函数地址
//			MyVirtualProtect(&pIAT->u1.Function, sizeof(pIAT->u1.Function), oldProtect2, &oldProtect2);
//			// 下一个函数
//			++pINT;
//			++pIAT;
//		}
//		// 下一个dll
//		++pImport;
//	}
//	// 恢复原有属性
//	MyVirtualProtect((LPVOID)exeFileBase, 0x400, oldProtect, &oldProtect);
//}
//////////////////////////////////// 加密IAT //////////////////////////////////



// 跳转至原始OEP
__declspec(naked) void JmpOEP()
{
	__asm
	{
		mov ebx, dword ptr fs : [0x30];	// 获取PEB
		mov ebx, dword ptr[ebx + 0x08];	// 获取加载基址ImageBase
		add ebx, shareData.srcOep;		// RVA+基址= 原始OEP
		jmp ebx;						// 跳转原始OEP
	}
}

//void _stdcall FusedFunc(DWORD funcAddress)
//{
//	_asm
//	{
//		jmp label1
//		label2 :
//		_emit 0xeb; //跳到下面的call
//		_emit 0x04;
//		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x123402EB]; //执行EB 02  也就是跳到下一句
//
//														  //	call Init;// 获取一些基本函数的地址
//
//														  // call下一条,用于获得eip
//		_emit 0xE8;
//		_emit 0x00;
//		_emit 0x00;
//		_emit 0x00;
//		_emit 0x00;
//		//-------跳到下面的call
//		_emit 0xEB;
//		_emit 0x0E;
//
//		//-------花
//		PUSH 0x0;
//		PUSH 0x0;
//		MOV EAX, DWORD PTR FS : [0];
//		PUSH EAX;
//		//-------花
//
//
//		// fused:
//		//作用push下一条语句的地址
//		//pop eax;
//		//add eax, 0x1b;
//		/*push eax;*/
//		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x5019C083];
//
//		push funcAddress; //这里如果是参数传入的需要注意上面的add eax,??的??
//		retn;
//
//		jmp label3
//
//			// 花
//			_emit 0xE8;
//		_emit 0x00;
//		_emit 0x00;
//		_emit 0x00;
//		_emit 0x00;
//		// 花
//
//
//	label1:
//		jmp label2
//			label3 :
//	}
//}
//// 壳程序
//int g_num11 = 10;
//void AllFunc()
//{
//	// 递归执行10次后执行壳程序
//	if (!g_num11)
//	{
//		_asm
//		{
//			nop
//			mov   ebp, esp
//			push - 1
//			push   0
//			push   0
//			mov   eax, fs:[0]
//			push   eax
//			mov   fs : [0], esp
//			sub   esp, 0x68
//			push   ebx
//			push   esi
//			push   edi
//			pop   eax
//			pop   eax
//			pop   eax
//			add   esp, 0x68
//			pop   eax
//			mov   fs : [0], eax
//			pop   eax
//
//			sub g_num11, 1
//
//			pop   eax
//			pop   eax
//			pop   eax
//			mov   ebp, eax
//
//			push AllFunc
//			call FusedFunc
//		}
//	}
//
//
//	//获取函数的API地址
//	FusedFunc((DWORD)GetApis);
//
//	//解密代码段
//	FusedFunc((DWORD)Decrypt);
//
//	//恢复数据目录表
//	FusedFunc((DWORD)RecoverDataDir);
//
//	//修复IAT
//	FusedFunc((DWORD)FixImportTable_Normal);
//
//	//反调试
//	FusedFunc((DWORD)AntiDebug);
//
//	//密码弹框
//	FusedFunc((DWORD)AlertPasswordBox);
//
//	//加密IAT
//	FusedFunc((DWORD)EncodeIAT);
//
//	//调用Tls回调函数
//	FusedFunc((DWORD)CallTls);
//
//}

// 混淆执行传入的函数
void _stdcall FusedFunc(DWORD funcAddr)
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
void AllFunc()
{
	// 执行具体的函数(再经过一次混淆
	FusedFunc((DWORD)GetApis);//获取函数的API地址
	FusedFunc((DWORD)Decrypt);	//解密代码段
	FusedFunc((DWORD)RecoverDataDir);	//恢复数据目录表
	FusedFunc((DWORD)FixImportTable_Normal);
	FusedFunc((DWORD)AntiDebug);
	FusedFunc((DWORD)AlertPasswordBox);	//密码弹框
	FusedFunc((DWORD)EncodeIAT);	//加密IAT
}

//extern "C" __declspec(dllexport) __declspec(naked) void Start()
//{
//
//	// 花指令
//	_asm
//	{
//		PUSH - 1
//		PUSH 0
//		PUSH 0
//		MOV EAX, DWORD PTR FS : [0]
//		PUSH EAX
//		MOV DWORD PTR FS : [0], ESP
//		SUB ESP, 0x68
//		PUSH EBX
//		PUSH ESI
//		PUSH EDI
//		POP EAX
//		POP EAX
//		POP EAX
//		ADD ESP, 0x68
//		POP EAX
//		MOV DWORD PTR FS : [0], EAX
//		POP EAX
//		POP EAX
//		POP EAX
//		POP EAX
//		MOV EBP, EAX
//	}
//
//	// 执行壳
//	FusedFunc((DWORD)AllFunc);
//
//	////获取函数的API地址
//	//GetApis();
//	////解密代码段
//	//Decrypt();
//	////恢复数据目录表
//	//RecoverDataDir();
//	////修复IAT
//	//FixImportTable_Normal();
//	////反调试
//	//AntiDebug();
//	////密码弹框
//	//AlertPasswordBox();
//	////调用Tls回调函数
//	//CallTls();
//	////加密IAT
//	//EncodeIAT();
//
//	////跳转到原始OEP
//	JmpOEP();
//	//__asm
//	//{
//	//	mov eax, shareData.srcOep;
//	//	add eax, 0x400000
//	//		jmp eax
//	//}
//}

// 壳代码起始函数(没有名称粉碎/导出/裸函数)
extern "C" __declspec(dllexport) __declspec(naked) void Start()
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
	FusedFunc((DWORD)AllFunc);

	//// 正常执行
	//GetAPIAddr();//获取函数的API地址
	//DecodeSection();//解密代码段
	//RecoverDataDir();//恢复数据目录表
	////FixImportTable_Normal();//修复IAT
	////AntiDebug();//反调试
	//AlertPassBox();//密码弹框
	////CallTls();//调用Tls回调函数
	//EncodeIAT();//加密IAT


	JmpOEP();//壳代码执行完毕,跳往真实OEP
}