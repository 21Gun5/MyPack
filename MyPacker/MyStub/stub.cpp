#include "stub.h"
#include "AES.h"
// �ṩ�Ǵ����Stub����,ͨ������:��ѹ��/����'�޸��ض�λ��'�޸�/����IAT��'����TLS������

// �ϲ�data rdata ��text��, ��text�ĳɿɶ���д��ִ��
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

//����һ��ȫ�ֱ���
extern "C" __declspec(dllexport)SHAREDATA shareData = { 0 };

//���庯��ָ��ͱ���
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
	//��ȡ��ǰ����Ļ�ַ
	DWORD dwBase = (DWORD)pfnGetMoudleHandleA(NULL);

	AES aes(shareData.key);
	//ѭ��������������
	DWORD old = 0;
	for (int i = 0; i < shareData.index - 1; i++)
	{
		//�õ��������ε��׵�ַ�ʹ�С
		unsigned char* pSection = (unsigned char*)shareData.data[i][0] + dwBase;
		DWORD dwSectionSize = shareData.data[i][1];

		//�޸���������
		MyVirtualProtect(pSection, dwSectionSize, PAGE_EXECUTE_READWRITE, &old);

		//���ܴ����
		aes.InvCipher(pSection, dwSectionSize);

		//�������޸Ļ�ȥ
		MyVirtualProtect(pSection, dwSectionSize, old, &old);
	}
}

void GetApis()
{
	HMODULE hKernel32;

	_asm
	{
		pushad;
		; //��ȡkernel32.dll�ļ��ػ�ַ;
		;// 1. �ҵ�PEB���׵�ַ;
		mov eax, fs:[0x30]; eax = > peb�׵�ַ;
		; 2. �õ�PEB.Ldr��ֵ;
		mov eax, [eax + 0ch]; eax = > PEB.Ldr��ֵ;
		mov eax, [eax + 0ch]; eax = > PEB.Ldr��ֵ;
		; 3. �õ�_PEB_LDR_DATA.InLoadOrderMoudleList.Flink��ֵ, ʵ�ʵõ��ľ�����ģ��ڵ���׵�ַ;
		mov eax, [eax]; eax = > _PEB_LDR_DATA.InLoadOrderMoudleList.Flink(NTDLL);
		; 4. �ٻ�ȡ��һ��;
		mov eax, [eax]; _LDR_DATA_TABLE_ENTRY.InLoadOrderMoudleList.Flink(kernel32), ;
		mov eax, [eax + 018h]; _LDR_DATA_TABLE_ENTRY.DllBase;
		mov hKernel32, eax;;
		; ����������;
		; 1. dosͷ-- > ntͷ-- > ��չͷ-- > ����Ŀ¼��;
		mov ebx, [eax + 03ch]; eax = > ƫ�Ƶ�NTͷ;
		add ebx, eax; ebx = > NTͷ���׵�ַ;
		add ebx, 078h; ebx = >
			; 2. �õ��������RVA;
		mov ebx, [ebx];
		add ebx, eax; ebx == > �������׵�ַ(VA);
		; 3. �������Ʊ��ҵ�GetProcAddress;
		; 3.1 �ҵ����Ʊ���׵�ַ;
		lea ecx, [ebx + 020h];
		mov ecx, [ecx]; // ecx => ���Ʊ���׵�ַ(rva);
		add ecx, eax; // ecx => ���Ʊ���׵�ַ(va);
		xor edx, edx; // ��Ϊindex��ʹ��.
		; 3.2 �������Ʊ�;
	_WHILE:;
		mov esi, [ecx + edx * 4]; esi = > ���Ƶ�rva;
		lea esi, [esi + eax]; esi = > �����׵�ַ;
		cmp dword ptr[esi], 050746547h; 47657450 726F6341 64647265 7373;
		jne _LOOP;
		cmp dword ptr[esi + 4], 041636f72h;
		jne _LOOP;
		cmp dword ptr[esi + 8], 065726464h;
		jne _LOOP;
		cmp word  ptr[esi + 0ch], 07373h;
		jne _LOOP;
		; �ҵ�֮��;
		mov edi, [ebx + 024h]; edi = > ���Ƶ���ű��rva;
		add edi, eax; edi = > ���Ƶ���ű��va;

		mov di, [edi + edx * 2]; ��ű���2�ֽڵ�Ԫ��, ����� * 2;
		; edi�������GetProcAddress����;
		; ��ַ���е��±�;
		and edi, 0FFFFh;
		; �õ���ַ���׵�ַ;
		mov edx, [ebx + 01ch]; edx = > ��ַ���rva;
		add edx, eax; edx = > ��ַ���va;
		mov edi, [edx + edi * 4]; edi = > GetProcAddress��rva;
		add edi, eax; ; edx = > GetProcAddress��va;
		mov MyGetProcAddress, edi;
		jmp _ENDWHILE;
	_LOOP:;
		inc edx; // ++index;
		jmp _WHILE;
	_ENDWHILE:;
		popad;
	}
	//������ָ�������ֵ
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
//// ��ȡkernel32.dll��ַ
//__declspec(naked) long GetKernelBase()
//{
//	__asm
//	{
//		// ���ռ���˳��
//		mov eax, dword ptr fs : [0x30]
//		mov eax, dword ptr[eax + 0x0C]
//		mov eax, dword ptr[eax + 0x0C]
//		mov eax, dword ptr[eax]
//		mov eax, dword ptr[eax]
//		mov eax, dword ptr[eax + 0x18]
//		ret
//	}
//}
//// ��ȡ��Ҫ��API��ַ
//void GetApis()
//{
//	// ��ȡMyGetProcAddress//here
//	_asm
//	{
//		pushad;
//		//��ȡkernel32.dll�ļ��ػ�ַ;
//		// 1. �ҵ�PEB���׵�ַ;
//		mov eax, fs:[0x30]; eax = > peb�׵�ַ;
//		// 2. �õ�PEB.Ldr��ֵ;
//		mov eax, [eax + 0ch]; eax = > PEB.Ldr��ֵ;
//		mov eax, [eax + 0ch]; eax = > PEB.Ldr��ֵ;
//		// 3. �õ�_PEB_LDR_DATA.InLoadOrderMoudleList.Flink��ֵ, ʵ�ʵõ��ľ�����ģ��ڵ���׵�ַ;
//		mov eax, [eax]; eax = > _PEB_LDR_DATA.InLoadOrderMoudleList.Flink(NTDLL);
//		// 4. �ٻ�ȡ��һ��;
//		mov eax, [eax]; _LDR_DATA_TABLE_ENTRY.InLoadOrderMoudleList.Flink(kernel32), ;
//		mov eax, [eax + 018h]; _LDR_DATA_TABLE_ENTRY.DllBase;
//		//mov hKernel32, eax;
//		// ����������;
//		// 1. dosͷ-- > ntͷ-- > ��չͷ-- > ����Ŀ¼��;
//		mov ebx, [eax + 03ch]; //eax = > ƫ�Ƶ�NTͷ;
//		add ebx, eax; //ebx = > NTͷ���׵�ַ;
//		add ebx, 078h; //ebx = >
//		// 2. �õ��������RVA;
//		mov ebx, [ebx];
//		add ebx, eax; //ebx == > �������׵�ַ(VA);
//		// 3. �������Ʊ��ҵ�GetProcAddress;
//		// 3.1 �ҵ����Ʊ���׵�ַ;
//		lea ecx, [ebx + 020h];
//		mov ecx, [ecx]; // ecx => ���Ʊ���׵�ַ(rva);
//		add ecx, eax; // ecx => ���Ʊ���׵�ַ(va);
//		xor edx, edx; // ��Ϊindex��ʹ��.
//		// 3.2 �������Ʊ�;
//	_WHILE:;
//		mov esi, [ecx + edx * 4];// esi = > ���Ƶ�rva;
//		lea esi, [esi + eax]; //esi = > �����׵�ַ;
//		cmp dword ptr[esi], 050746547h; //47657450 726F6341 64647265 7373;
//		jne _LOOP;
//		cmp dword ptr[esi + 4], 041636f72h;
//		jne _LOOP;
//		cmp dword ptr[esi + 8], 065726464h;
//		jne _LOOP;
//		cmp word  ptr[esi + 0ch], 07373h;
//		jne _LOOP;
//		//; �ҵ�֮��;
//		mov edi, [ebx + 024h]//; edi = > ���Ƶ���ű��rva;
//			add edi, eax;// edi = > ���Ƶ���ű��va;
//		mov di, [edi + edx * 2];// ��ű���2�ֽڵ�Ԫ��, ����� * 2;
//		//; edi�������GetProcAddress����;
//		//; ��ַ���е��±�;
//		and edi, 0FFFFh;
//		//; �õ���ַ���׵�ַ;
//		mov edx, [ebx + 01ch];// edx = > ��ַ���rva;
//		add edx, eax; //edx = > ��ַ���va;
//		mov edi, [edx + edi * 4]; //edi = > GetProcAddress��rva;
//		add edi, eax; //; edx = > GetProcAddress��va;
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


////////////////////////////////// ������� //////////////////////////////////
HINSTANCE g_hInstance;	//���봰��ʵ�����
HWND hEdit;				//�������봰��
BOOL bSuccess;			//������֤	
//������Ϣ�ص�����
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
	//ע�ᴰ����
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
	ws.lpfnWndProc = (WNDPROC)WndPrco;		//	�ص�����
	ws.lpszClassName = TEXT("MyPack");
	pfnRegisterClassEx(&ws);
	//��������
	HWND hWnd = pfnCreateWindowEx(0, TEXT("MyPack"), TEXT("����������"), WS_OVERLAPPED | WS_VISIBLE,
		100, 100, 300, 200, NULL, NULL, g_hInstance, NULL);
	//���´���
	//pfnUpdateWindow(hWnd);
	pfnShowWindow(hWnd, SW_SHOW);
	//��Ϣ����
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
		HWND hBit = pfnCreateWindowEx(0, L"static", L"����", WS_CHILD | WS_VISIBLE,
			50, 50, 30, 20, hWnd, (HMENU)10004, g_hInstance, NULL);
		hEdit = pfnCreateWindowEx(0, L"edit", L"", WS_CHILD | WS_VISIBLE | WS_BORDER,
			100, 50, 120, 20, hWnd, (HMENU)10003, g_hInstance, NULL);
		pfnCreateWindowEx(0, L"button", L"ȷ��", WS_CHILD | WS_VISIBLE,
			50, 100, 60, 30, hWnd, (HMENU)10001, g_hInstance, NULL);
		pfnCreateWindowEx(0, L"button", L"ȡ��", WS_CHILD | WS_VISIBLE,
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
			//����������123
			if (MyWcscmp(GetKey, L"123") == 0)
			{
				bSuccess = TRUE;
				//�������ƥ�� ��������
				pfnSendMessageW(hWnd, WM_CLOSE, NULL, NULL);
			}
			else
			{
				//���벻ƥ���˳�����
				pfnExitProcess(1);
			}
			break;
		}
		case 10002:		//ȡ����ť
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
		// TODO:  �ڴ���������ͼ����...
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
////////////////////////////////// ������� //////////////////////////////////

void SetFileHeaderProtect(bool nWrite)
{
	//��ȡ��ǰ����ļ��ػ�ַ
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
		mov eax, DWORD ptr fs : [0x30];//��ȡpeb
		mov al, byte ptr ds : [eax + 0x02];//��ȡpeb.beingdugged
		mov BeingDugged, al;
	}
	if (BeingDugged)
	{
		pfnMessageBoxW(NULL, L"��һ�� �㱻������", L"ע��", MB_OK);
	}

}
void FixImportTable_Normal()
{
	//�����ļ�����Ϊ��д
	SetFileHeaderProtect(true);
	//��ȡ��ǰ����ļ��ػ�ַ
	DWORD ImageBase = (DWORD)pfnGetMoudleHandleA(NULL);

	IMAGE_THUNK_DATA* pInt = NULL;
	IMAGE_THUNK_DATA* pIat = NULL;
	SIZE_T impAddress = 0;
	HMODULE	hImpModule = 0;
	DWORD dwOldProtect = 0;
	IMAGE_IMPORT_BY_NAME* pImpName = 0;

	if (!GetOptHeader(ImageBase)->DataDirectory[1].VirtualAddress)return;

	//�����=�����ƫ��+���ػ�ַ
	IMAGE_IMPORT_DESCRIPTOR* pImp = (IMAGE_IMPORT_DESCRIPTOR*)(GetOptHeader(ImageBase)->DataDirectory[1].VirtualAddress + ImageBase);


	while (pImp->Name)
	{
		//IAT=ƫ�ƼӼ��ػ�ַ
		pIat = (IMAGE_THUNK_DATA*)(pImp->FirstThunk + ImageBase);
		if (pImp->OriginalFirstThunk == 0) // ���������INT��ʹ��IAT
		{
			pInt = pIat;
		}
		else
		{
			pInt = (IMAGE_THUNK_DATA*)(pImp->OriginalFirstThunk + ImageBase);
		}

		// ����dll
		hImpModule = (HMODULE)MyLoadLibraryA((char*)(pImp->Name + ImageBase));
		//���뺯����ַ
		while (pInt->u1.Function)
		{
			//�жϵ���ķ�ʽ����Ż�������
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
	//��ȡ��ǰ����ļ��ػ�ַ
	char* dwBase = (char*)pfnGetMoudleHandleA(NULL);
	//��ȡ����Ŀ¼��ĸ���
	DWORD dwNumOfDataDir = shareData.dwNumOfDataDir;

	DWORD dwOldAttr = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = (GetOptHeader((DWORD)dwBase)->DataDirectory);
	//��������Ŀ¼��
	for (DWORD i = 0; i < dwNumOfDataDir; i++)
	{
		if (i == 2)
		{
			pDataDirectory++;
			continue;
		}

		//�޸�����Ϊ�ɶ���д
		MyVirtualProtect(pDataDirectory, 0x8, PAGE_EXECUTE_READWRITE, &dwOldAttr);

		//��ԭ����Ŀ¼����
		pDataDirectory->VirtualAddress = shareData.dwDataDir[i][0];
		pDataDirectory->Size = shareData.dwDataDir[i][1];

		//�������޸Ļ�ȥ
		MyVirtualProtect(pDataDirectory, 0x8, dwOldAttr, &dwOldAttr);

		pDataDirectory++;
	}
}
void CallTls()
{
	//��ȡ��ǰ����ļ��ػ�ַ
	DWORD dwBase = (DWORD)pfnGetMoudleHandleA(NULL);
	//��ȡTls��
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
	// 1.�����ڴ�ռ�
	DWORD dwNewMem = (DWORD)pfnVirtualAlloc(NULL, 0x20, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// 2.���ܺ�����ַ
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

	// 3.��OpCode[11]���ĵ�ַ���и�д
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

	// 4.�����ݿ�����������ڴ�
	pfnRtlMoveMemory((LPVOID)dwNewMem, OpCode, 0x20);

	// 5.�����µĺ�����ַ
	return dwNewMem;
}
void EncodeIAT()
{
	//�����ļ�����Ϊ��д
	SetFileHeaderProtect(true);
	//��ȡ��ǰ����ļ��ػ�ַ
	DWORD ImageBase = (DWORD)pfnGetMoudleHandleA(NULL);

	IMAGE_THUNK_DATA* pInt = NULL;
	IMAGE_THUNK_DATA* pIat = NULL;
	SIZE_T impAddress = 0;
	HMODULE	hImpModule = 0;
	DWORD dwOldProtect = 0;
	IMAGE_IMPORT_BY_NAME* pImpName = 0;

	if (!GetOptHeader(ImageBase)->DataDirectory[1].VirtualAddress)return;

	//�����=�����ƫ��+���ػ�ַ
	IMAGE_IMPORT_DESCRIPTOR* pImp = (IMAGE_IMPORT_DESCRIPTOR*)(GetOptHeader(ImageBase)->DataDirectory[1].VirtualAddress + ImageBase);


	while (pImp->Name)
	{
		//IAT=ƫ�ƼӼ��ػ�ַ
		pIat = (IMAGE_THUNK_DATA*)(pImp->FirstThunk + ImageBase);
		if (pImp->OriginalFirstThunk == 0) // ���������INT��ʹ��IAT
		{
			pInt = pIat;
		}
		else
		{
			pInt = (IMAGE_THUNK_DATA*)(pImp->OriginalFirstThunk + ImageBase);
		}

		// ����dll
		hImpModule = (HMODULE)MyLoadLibraryA((char*)(pImp->Name + ImageBase));
		//���뺯����ַ
		while (pInt->u1.Function)
		{
			//�жϵ���ķ�ʽ����Ż�������
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
//////////////////////////////////// ����IAT //////////////////////////////////
//// �滻������ַ(���ڼ���IAT
//DWORD ReplaceFuncAddr(DWORD dwFunAddr)
//{
//	// �����ڴ�ռ�,���׵�ַ��Ϊ�����µ�ַ
//	DWORD dwNewMem = (DWORD)pfnVirtualAlloc(NULL, 0x20, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//
//	// ���ܺ�����ַ(^ 0x15151515
//	DWORD dwEncryptFunAddr = dwFunAddr ^ 0x15151515;
//	// ����IAT��ShellCode(���л�ָ��;����BYTE����
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
//	// �Ѻ�����ַд�뵽���ܵ�ShellCode��
//	OpCode[11] = dwEncryptFunAddr;					// 0x85
//	OpCode[12] = dwEncryptFunAddr >> 0x08;			// 0xEE
//	OpCode[13] = dwEncryptFunAddr >> 0x10;			// 0xCB
//	OpCode[14] = dwEncryptFunAddr >> 0x18;			// 0x60
//	// �����ݿ�����������ڴ�
//	pfnRtlMoveMemory((LPVOID)dwNewMem, OpCode, 0x20);
//	// �����µĺ�����ַ
//	return dwNewMem;
//}
//// ����IAT
//void EncodeIAT()
//{
//	// ��ȡ���ػ�ַ(exeԴ����
//	DWORD exeFileBase = (DWORD)fnGetMoudleHandleA(NULL);
//	// ���ÿ�д�ķ�������
//	DWORD oldProtect = 0;
//	MyVirtualProtect((LPVOID)exeFileBase, 0x400, PAGE_READWRITE, &oldProtect);
//	// ��ȡ������ַ = ƫ�� + ��ַ
//	IMAGE_IMPORT_DESCRIPTOR* pImport = (IMAGE_IMPORT_DESCRIPTOR*)(GetOptHeader(exeFileBase)->DataDirectory[1].VirtualAddress + exeFileBase);
//	// �������е����(�ж��,��0��β
//	IMAGE_THUNK_DATA* pIAT = NULL;
//	IMAGE_THUNK_DATA* pINT = NULL;
//	DWORD dllBase = 0;// �����dll�Ļ�ַ
//	while (pImport->FirstThunk != 0)
//	{
//		// ��ȡ�������Ҫ�ֶ�
//		pIAT = (IMAGE_THUNK_DATA*)(pImport->FirstThunk + exeFileBase);
//		pINT = (IMAGE_THUNK_DATA*)(pImport->OriginalFirstThunk + exeFileBase);
//		char * dllName = (char*)(pImport->Name + exeFileBase);
//		// ����dll��ȡ���(����ַ
//		dllBase = (DWORD)MyLoadLibraryA(dllName);
//		// ����INT,��ȡ��ַ�����IAT
//		while (pINT->u1.Ordinal != 0)
//		{
//			DWORD funcAddr = 0;// ������ַ
//			IMAGE_IMPORT_BY_NAME* pImpByName = 0;//�������ṹ��
//			// ������ʽ:���
//			if (IMAGE_SNAP_BY_ORDINAL(pINT->u1.Ordinal))
//			{
//				funcAddr = (DWORD)MyGetProcAddress((HMODULE)dllBase, (char*)(pINT->u1.Ordinal & 0xFFFF));
//			}
//			// ������ʽ:����
//			else
//			{
//				pImpByName = (IMAGE_IMPORT_BY_NAME*)(pINT->u1.Function + exeFileBase);
//				funcAddr = (DWORD)MyGetProcAddress((HMODULE)dllBase, (char*)pImpByName->Name);
//			}
//			// �޸�IAT����(�޸�֮ǰ���޸�Ϊд����,��ָ�
//			DWORD oldProtect2 = 0;
//			MyVirtualProtect(&pIAT->u1.Function, sizeof(pIAT->u1.Function), PAGE_READWRITE, &oldProtect2);
//			//pIAT->u1.Function = 0;// �޸�IAT
//			pIAT->u1.Function = ReplaceFuncAddr(funcAddr);// �޸�IAT(�滻������ַ
//			MyVirtualProtect(&pIAT->u1.Function, sizeof(pIAT->u1.Function), oldProtect2, &oldProtect2);
//			// ��һ������
//			++pINT;
//			++pIAT;
//		}
//		// ��һ��dll
//		++pImport;
//	}
//	// �ָ�ԭ������
//	MyVirtualProtect((LPVOID)exeFileBase, 0x400, oldProtect, &oldProtect);
//}
//////////////////////////////////// ����IAT //////////////////////////////////



// ��ת��ԭʼOEP
__declspec(naked) void JmpOEP()
{
	__asm
	{
		mov ebx, dword ptr fs : [0x30];	// ��ȡPEB
		mov ebx, dword ptr[ebx + 0x08];	// ��ȡ���ػ�ַImageBase
		add ebx, shareData.srcOep;		// RVA+��ַ= ԭʼOEP
		jmp ebx;						// ��תԭʼOEP
	}
}

//void _stdcall FusedFunc(DWORD funcAddress)
//{
//	_asm
//	{
//		jmp label1
//		label2 :
//		_emit 0xeb; //���������call
//		_emit 0x04;
//		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x123402EB]; //ִ��EB 02  Ҳ����������һ��
//
//														  //	call Init;// ��ȡһЩ���������ĵ�ַ
//
//														  // call��һ��,���ڻ��eip
//		_emit 0xE8;
//		_emit 0x00;
//		_emit 0x00;
//		_emit 0x00;
//		_emit 0x00;
//		//-------���������call
//		_emit 0xEB;
//		_emit 0x0E;
//
//		//-------��
//		PUSH 0x0;
//		PUSH 0x0;
//		MOV EAX, DWORD PTR FS : [0];
//		PUSH EAX;
//		//-------��
//
//
//		// fused:
//		//����push��һ�����ĵ�ַ
//		//pop eax;
//		//add eax, 0x1b;
//		/*push eax;*/
//		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x5019C083];
//
//		push funcAddress; //��������ǲ����������Ҫע�������add eax,??��??
//		retn;
//
//		jmp label3
//
//			// ��
//			_emit 0xE8;
//		_emit 0x00;
//		_emit 0x00;
//		_emit 0x00;
//		_emit 0x00;
//		// ��
//
//
//	label1:
//		jmp label2
//			label3 :
//	}
//}
//// �ǳ���
//int g_num11 = 10;
//void AllFunc()
//{
//	// �ݹ�ִ��10�κ�ִ�пǳ���
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
//	//��ȡ������API��ַ
//	FusedFunc((DWORD)GetApis);
//
//	//���ܴ����
//	FusedFunc((DWORD)Decrypt);
//
//	//�ָ�����Ŀ¼��
//	FusedFunc((DWORD)RecoverDataDir);
//
//	//�޸�IAT
//	FusedFunc((DWORD)FixImportTable_Normal);
//
//	//������
//	FusedFunc((DWORD)AntiDebug);
//
//	//���뵯��
//	FusedFunc((DWORD)AlertPasswordBox);
//
//	//����IAT
//	FusedFunc((DWORD)EncodeIAT);
//
//	//����Tls�ص�����
//	FusedFunc((DWORD)CallTls);
//
//}

// ����ִ�д���ĺ���
void _stdcall FusedFunc(DWORD funcAddr)
{
	// ����+��ָ����ִ��funcAddr
	_asm
	{
		jmp code1;

	code2:
		_emit 0xeb; // jmpָ��
		_emit 0x04; // jmp��ƫ�ƣ�����2��4+2=6(�׵�ַ+6��β��ַ+4)

		// 3EFF9458 EB023412 : EB02=jmp 2
		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x123402EB]; // 3EFF9458 EB023412��jmp 4��EB02 = jmp 2(����3412)

		// jmp 2����												  
		_emit 0xe8;// call ָ��
		_emit 0x00;// ��4�ֽڱ�ƫ��=0
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;

		// call 0 ����
		_emit 0xeb;// jmp
		_emit 0x0e;// jmp e

		// Ϊ0x0e����(11�ֽ�
		PUSH 0x0;// 6A 00
		PUSH 0x0;// 6A 00
		MOV EAX, DWORD PTR FS : [0];//64A1 00000000
		PUSH EAX; // 50

		// 3EFF9458 83C01950 : 58=pop eax��83C019=add eax,0x19��50=push eax
		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x5019C083];//3EFF9458 83C01950��jmp e��58=pop eax

		// ִ�к���
		push funcAddr;	// ѹ���ִ�к���
		retn;				// pop eip��ִ��ջ���ĺ���

		// ִ���꺯����,��������
		jmp over;

		// ��һ����ת
	code1:
		jmp code2;

		//��,����
	over:
	}
}
// ȫ���ǹ��ܴ���(�������������ִ��
void AllFunc()
{
	// ִ�о���ĺ���(�پ���һ�λ���
	FusedFunc((DWORD)GetApis);//��ȡ������API��ַ
	FusedFunc((DWORD)Decrypt);	//���ܴ����
	FusedFunc((DWORD)RecoverDataDir);	//�ָ�����Ŀ¼��
	FusedFunc((DWORD)FixImportTable_Normal);
	FusedFunc((DWORD)AntiDebug);
	FusedFunc((DWORD)AlertPasswordBox);	//���뵯��
	FusedFunc((DWORD)EncodeIAT);	//����IAT
}

//extern "C" __declspec(dllexport) __declspec(naked) void Start()
//{
//
//	// ��ָ��
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
//	// ִ�п�
//	FusedFunc((DWORD)AllFunc);
//
//	////��ȡ������API��ַ
//	//GetApis();
//	////���ܴ����
//	//Decrypt();
//	////�ָ�����Ŀ¼��
//	//RecoverDataDir();
//	////�޸�IAT
//	//FixImportTable_Normal();
//	////������
//	//AntiDebug();
//	////���뵯��
//	//AlertPasswordBox();
//	////����Tls�ص�����
//	//CallTls();
//	////����IAT
//	//EncodeIAT();
//
//	////��ת��ԭʼOEP
//	JmpOEP();
//	//__asm
//	//{
//	//	mov eax, shareData.srcOep;
//	//	add eax, 0x400000
//	//		jmp eax
//	//}
//}

// �Ǵ�����ʼ����(û�����Ʒ���/����/�㺯��)
extern "C" __declspec(dllexport) __declspec(naked) void Start()
{
	// ��ָ��
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

	// ����ִ��
	FusedFunc((DWORD)AllFunc);

	//// ����ִ��
	//GetAPIAddr();//��ȡ������API��ַ
	//DecodeSection();//���ܴ����
	//RecoverDataDir();//�ָ�����Ŀ¼��
	////FixImportTable_Normal();//�޸�IAT
	////AntiDebug();//������
	//AlertPassBox();//���뵯��
	////CallTls();//����Tls�ص�����
	//EncodeIAT();//����IAT


	JmpOEP();//�Ǵ���ִ�����,������ʵOEP
}