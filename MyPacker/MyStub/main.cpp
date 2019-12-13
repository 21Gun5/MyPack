#include "stub.h"
#include "AES.h"
#include "lz4.h"

// �ϲ�data/rdata��text��, ��text�ĳɿɶ���д��ִ��
#pragma comment(linker, "/merge:.data=.text") 
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")

// ����һ��ȫ�ֱ�������������
extern "C" __declspec(dllexport)SHAREDATA ShareData = { 0 };

// ���庯��
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

// ��ȡPEͷ��Ϣ
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

// ��ȡ��ǰ���ػ�ַ
__declspec(naked) long getcurmodule()
{
	_asm {
		mov eax, dword ptr fs : [0x30]
		; PEB ��ƫ��Ϊ 0x08 ������Ǽ��ػ�ַ
		mov eax, dword ptr[ebx + 0x08]
		ret;
	}
}

// ��ȡ����
DWORD MyGetProcAddress(DWORD Module, LPCSTR FunName)
{
	// ��ȡ Dos ͷ�� Nt ͷ
	auto DosHeader = (PIMAGE_DOS_HEADER)Module;
	auto NtHeader = (PIMAGE_NT_HEADERS)(Module + DosHeader->e_lfanew);
	// ��ȡ������ṹ
	DWORD ExportRva = NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
	auto ExportTable = (PIMAGE_EXPORT_DIRECTORY)(Module + ExportRva);
	// �ҵ��������Ʊ���ű���ַ��
	auto NameTable = (DWORD*)(ExportTable->AddressOfNames + Module);
	auto FuncTable = (DWORD*)(ExportTable->AddressOfFunctions + Module);
	auto OrdinalTable = (WORD*)(ExportTable->AddressOfNameOrdinals + Module);
	// ����������
	for (DWORD i = 0; i < ExportTable->NumberOfNames; ++i)
	{
		// ��ȡ����
		char* Name = (char*)(NameTable[i] + Module);
		if (!strcmp(Name, FunName))
			return FuncTable[OrdinalTable[i]] + Module;
	}
	return -1;
}

// ��ȡ kernel32.dll �Ļ�ַ
__declspec(naked) long getkernelbase()
{
	__asm
	{
		// ���ռ���˳��
		mov eax, dword ptr fs : [0x30]
		mov eax, dword ptr[eax + 0x0C]
		mov eax, dword ptr[eax + 0x0C]
		mov eax, dword ptr[eax]
		mov eax, dword ptr[eax]
		mov eax, dword ptr[eax + 0x18]
		ret
	}
}

// ��������
long XorDecryptSection()
{
	DWORD OldProtect;
	__asm
	{
		; ��ȡ��ǰ����� PEB ��Ϣ
		mov ebx, dword ptr fs : [0x30]
		; PEB ��ƫ��Ϊ 0x08 ������Ǽ��ػ�ַ
		mov ebx, dword ptr[ebx + 0x08]
		; �����ػ�ַ�� oep ���
		add ShareData.rva, ebx
	}
	My_VirtualProtect((LPVOID)ShareData.rva, ShareData.size, PAGE_READWRITE, &OldProtect);
	//pVirtualProtect((LPVOID)ShareData.rva, ShareData.size, PAGE_READWRITE, &OldProtect);
	// ִ�����˵�һ�����ָ��֮�� ShareData.rva ���� va ��
	for (int i = 0; i < ShareData.size; ++i)
		((BYTE*)ShareData.rva)[i] ^= ShareData.key;
	//pVirtualProtect((LPVOID)ShareData.rva, ShareData.size, OldProtect, &OldProtect);
	My_VirtualProtect((LPVOID)ShareData.rva, ShareData.size, OldProtect, &OldProtect);
}

// ��ת��ԭʼ�� oep
__declspec(naked) long JmpOEP()
{
	__asm
	{
		; ��ȡ��ǰ����� PEB ��Ϣ
		mov ebx, dword ptr fs : [0x30]
		; PEB ��ƫ��Ϊ 0x08 ������Ǽ��ػ�ַ
		mov ebx, dword ptr[ebx + 0x08]
		; �����ػ�ַ�� oep ���
		add ebx, ShareData.OldOep
		; ��ת��ԭʼ oep ��
		jmp ebx
	}
}

// ��ȡ��Ҫ�õ��ĺ���
void GetAPIAddr()
{
	// ���к������������ȡ
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

// 	�޸�ԭʼ�����ض�λ
void FixOldReloc()
{
	// ��ȡ��ǰ���ػ�ַ
	long hModule = getcurmodule();
	DWORD OldProtect;

	// ��ȡ�ض�λ��
	PIMAGE_BASE_RELOCATION RealocTable =
		(PIMAGE_BASE_RELOCATION)(ShareData.oldRelocRva + hModule);

	// ��� SizeOfBlock ��Ϊ�գ���˵�������ض�λ��
	while (RealocTable->SizeOfBlock)
	{
		// ����ض�λ�������ڴ���Σ�����Ҫ�޸ķ�������
		My_VirtualProtect((LPVOID)(RealocTable->VirtualAddress + hModule),
			0x1000, PAGE_READWRITE, &OldProtect);

		// ��ȡ�ض�λ��������׵�ַ���ض�λ�������
		int count = (RealocTable->SizeOfBlock - 8) / 2;
		TypeOffset* to = (TypeOffset*)(RealocTable + 1);

		// ����ÿһ���ض�λ��
		for (int i = 0; i < count; ++i)
		{
			// ��� type ��ֵΪ 3 ���ǲ���Ҫ��ע
			if (to[i].Type == 3)
			{
				// ��ȡ����Ҫ�ض�λ�ĵ�ַ���ڵ�λ��
				DWORD* addr = (DWORD*)(hModule + RealocTable->VirtualAddress + to[i].Offset);
				// ʹ�������ַ��������µ��ض�λ�������
				*addr = *addr - ShareData.oldImageBase + hModule;

			}
		}

		// ��ԭԭ���εĵı�������
		My_VirtualProtect((LPVOID)(RealocTable->VirtualAddress + hModule),
			0x1000, OldProtect, &OldProtect);

		// �ҵ���һ���ض�λ��
		RealocTable = (PIMAGE_BASE_RELOCATION)
			((DWORD)RealocTable + RealocTable->SizeOfBlock);
	}
}

// ��ѹ������
void UncompressSection()
{
	// 1.����ѹ��λ��
	char * pSrc = (char*)(ShareData.FrontCompressRva + getcurmodule());

	//2. ����ռ�
	char* pBuff = (char*)My_VirtualAlloc(0, ShareData.FrontCompressSize,
		MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	//3. ��ѹ��
	LZ4_uncompress_unknownOutputSize(
		pSrc,/*ѹ���������*/
		pBuff, /*��ѹ����������*/
		ShareData.LaterCompressSize,/*ѹ����Ĵ�С*/
		ShareData.FrontCompressSize/*ѹ��ǰ�Ĵ�С*/);

	//4.�޸�����
	DWORD OldProtect;
	My_VirtualProtect(pSrc, ShareData.FrontCompressSize, PAGE_EXECUTE_READWRITE, &OldProtect);

	//5.д��ԭʼ����
	memcpy(pSrc, pBuff, ShareData.FrontCompressSize);

	//6.�ָ�����
	My_VirtualProtect(pSrc, ShareData.FrontCompressSize, OldProtect, &OldProtect);


	//7.�ͷſռ�
	//MyVirtualFree(pBuff, 0, MEM_RELEASE);

}

void AESDecryptAllSection()
{
	//��ȡ��ǰ����Ļ�ַ
	DWORD dwBase = getcurmodule();

	CAES aes(ShareData.key1);
	//ѭ��������������
	DWORD old = 0;
	for (int i = 0; i < ShareData.index; i++)
	{
		//�õ��������ε��׵�ַ�ʹ�С
		unsigned char* pSection = (unsigned char*)ShareData.data[i][0] + dwBase;
		DWORD dwSectionSize = ShareData.data[i][1];

		//�޸���������
		My_VirtualProtect(pSection, dwSectionSize, PAGE_EXECUTE_READWRITE, &old);

		//���ܴ����
		aes.InvCipher(pSection, dwSectionSize);

		//�������޸Ļ�ȥ
		My_VirtualProtect(pSection, dwSectionSize, old, &old);
	}
}

// �ָ�����Ŀ¼����Ϣ
void RecoverDataDirTab()
{
	// 1 ��ȡ��ǰ�����ַ
	//char* dwBase = (char*)pfnGetMoudleHandleA(NULL);
	DWORD dwBase = getcurmodule();
	// 2 ��������Ŀ¼��
	DWORD dwNumOfDataDir = ShareData.dwNumOfDataDir;
	DWORD dwOldAttr = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = (GetOptHeader(dwBase)->DataDirectory);
	for (DWORD i = 0; i < dwNumOfDataDir; i++)
	{
		// 3 ��Դ�������޸�
		if (i == 2)
		{
			pDataDirectory++;
			continue;
		}
		// 4 �޸�����Ϊ��д
		My_VirtualProtect(pDataDirectory, 0x8, PAGE_EXECUTE_READWRITE, &dwOldAttr);
		// 5 �ָ�����Ŀ¼����
		pDataDirectory->VirtualAddress = ShareData.dwDataDir[i][0];
		pDataDirectory->Size = ShareData.dwDataDir[i][1];
		// 6 �ָ�ԭ����
		My_VirtualProtect(pDataDirectory, 0x8, dwOldAttr, &dwOldAttr);
		// 7 ����ָ��+1,��������
		pDataDirectory++;
	}
}

// ��̬������
void StaticAntiDebug()
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
		My_MessageBoxA(NULL, "����״̬", "����", MB_OK);
		My_ExitProcess(1);
	}
}

// ����IAT
void EncodeIAT()
{
	// 1 ��ȡ��ǰģ���ַ
	long Module = getcurmodule();
	//_asm {
	//	mov ebx, dword ptr fs : [0x30];
	//	; PEB ��ƫ��Ϊ 0x08 ������Ǽ��ػ�ַ
	//	mov ebx, dword ptr[ebx + 0x08]
	//	mov Module, ebx;
	//}

	// 2 ����IAT(��תվ: mov eax 123;jmp eax=jmp 123
	//	//00FE12B2 | 50				| push eax	|
	//	//00FE12B3 | 58				| pop eax	| push eip; jmp xxxxxxxxx
	//	//00FE12B4 | 60				| pushad	|
	//	//00FE12B5 | 61				| popad		|
	//	//00FE12B6 | B8 11111111	| mov eax, 11111111 |
	//	//00FE12BB | FFE0			| jmp eax |
	char shellcode[] = { "\x50\x58\x60\x61\xB8\x11\x11\x11\x11\xFF\xE0" };
	// 3 ��ȡ������ַ=ƫ��+��ַ
	PIMAGE_IMPORT_DESCRIPTOR pImport =(PIMAGE_IMPORT_DESCRIPTOR)(Module + ShareData.ImportRva);
	// 4 ѭ�����������(��0��β
	while (pImport->Name)
	{
		// 5 �������dll
		char * dllName = (char*)(pImport->Name + Module);
		HMODULE Mod = My_LoadLibraryA(dllName);
		// 6 ��ȡINT/IAT��ַ
		DWORD * pInt = (DWORD *)(pImport->OriginalFirstThunk + Module);
		DWORD * pIat = (DWORD *)(pImport->FirstThunk + Module);
		// 7 ѭ������INT(��0��β
		while (*pInt)// ��ָ��THUNK�ṹ��,�ڲ���������,�����ĸ��ֶ���Ч,����ʾһ����ַ����
		{
			// 8 ��ȡAPI��ַ
			IMAGE_IMPORT_BY_NAME * FunName = (IMAGE_IMPORT_BY_NAME*)(*pInt + Module);
			LPVOID Fun = My_GetProcAddress(Mod, FunName->Name);
			// 9 ����ռ䱣��"��תվ"����,������ʵ��ַд��
			char * pbuff =(char*)My_VirtualAlloc(0, 100, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			memcpy(pbuff, shellcode, sizeof(shellcode));// �ٵ�ַ����"��תվ"����
			*(DWORD*)&pbuff[5] = (DWORD)Fun;// mov eax,��ʵ��ַ,jmp eax=jmp ��ʵ��ַ
			// 10 ��IAT���ٵ�ַ(����ת�����ַ
			DWORD old;
			My_VirtualProtect(pIat, 4, PAGE_EXECUTE_READWRITE, &old);// ��д����
			*pIat = (DWORD)pbuff;// ���ع��������ֶ�,ֱ�Ӹ�ֵ��*p����
			My_VirtualProtect(pIat, 4, old, &old);// �ָ�ԭ����
			// 11 �¸�INT/IAT
			pInt++;
			pIat++;
		}

		// 12 ��һ�������
		pImport++;
	}

}

// �ص�����
LRESULT CALLBACK MyWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
	// ����༭����
	static HWND Edithwnd = 0;

	switch (msg)
	{
	case WM_CREATE:
	{
		// ��������
		HINSTANCE instance = (HINSTANCE)getcurmodule();

		//HWND hBit = pfnCreateWindowEx(0, L"static", L"����", WS_CHILD | WS_VISIBLE,
		//	50, 50, 30, 20, hWnd, (HMENU)10004, g_hInstance, NULL);
		//hEdit = pfnCreateWindowEx(0, L"edit", L"", WS_CHILD | WS_VISIBLE | WS_BORDER,
		//	100, 50, 120, 20, hWnd, (HMENU)10003, g_hInstance, NULL);
		//pfnCreateWindowEx(0, L"button", L"ȷ��", WS_CHILD | WS_VISIBLE,
		//	50, 100, 60, 30, hWnd, (HMENU)10001, g_hInstance, NULL);
		//pfnCreateWindowEx(0, L"button", L"ȡ��", WS_CHILD | WS_VISIBLE,
		//	150, 100, 60, 30, hWnd, (HMENU)10002, g_hInstance, NULL);


		Edithwnd = My_CreateWindowExA(0, "edit", NULL, WS_VISIBLE | WS_CHILD | WS_BORDER, 100, 50, 120, 20,
			hwnd, (HMENU)0x1000, instance, 0);
		My_CreateWindowExA(0, "button", "ȷ��", WS_VISIBLE | WS_CHILD, 50, 100, 60, 30, hwnd, (HMENU)0x1001, instance, 0);
		My_CreateWindowExA(0, "button", "ȡ��", WS_VISIBLE | WS_CHILD, 150, 100, 60, 30, hwnd, (HMENU)0x1002, instance, 0);
		HWND hBit = My_CreateWindowExA(0, "static", "����", WS_CHILD | WS_VISIBLE, 50, 50, 30, 20, hwnd, (HMENU)1003, instance, NULL);

		//Edithwnd = My_CreateWindowExA(0, "edit", NULL, WS_VISIBLE | WS_CHILD | WS_BORDER, 20, 20, 100, 20,
		//	hwnd, (HMENU)0x1000, instance, 0);
		//My_CreateWindowExA(0, "button", "ȷ��", WS_VISIBLE | WS_CHILD, 30, 50, 50, 20,hwnd, (HMENU)0x1001, instance, 0);



		break;
	}
	case WM_COMMAND:
	{
		// ��ť����¼�
		if (wparam == 0x1001)
		{
			char buff[100];
			// ��ȡ�ı�
			My_GetWindowTextA(Edithwnd, buff, 100);
			if (!strcmp(buff, "123"))
			{
				//�˳�����
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

// ��ʾ����
void AlertPassWindow()
{
	// 0 ����������
	WNDCLASSEXA ws = { sizeof(ws) };
	ws.style = CS_HREDRAW | CS_VREDRAW;
	ws.hInstance = (HINSTANCE)getcurmodule();
	ws.lpfnWndProc = MyWndProc;
	ws.hbrBackground = (HBRUSH)My_GetStockObject(WHITE_BRUSH);
	ws.lpszClassName = "MyPack";

	//1 .ע�ᴰ����
	My_RegisterClassExA(&ws);

	//2. ��������
	HWND hwnd = My_CreateWindowExA(0,
		"MyPack",
		"MyPack",
		WS_OVERLAPPEDWINDOW,
		100, 100, 300, 200, NULL, NULL,
		(HINSTANCE)getcurmodule(), NULL);

	//3 . ��ʾ����
	My_ShowWindow(hwnd, SW_SHOW);
	My_UpdateWindow(hwnd);

	//4. ��Ϣѭ��
	MSG msg;
	while (My_GetMessageA(&msg, 0, 0, 0))
	{
		//5. ת����Ϣ �ַ���Ϣ 
		My_TranslateMessage(&msg);
		My_DispatchMessageA(&msg);
	}

}

// ����ִ�к���
void _stdcall ConfuseExecute(DWORD funcAddr)
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
void PackCode()
{
	// ִ�о���ĺ���(�پ���һ�λ���
	ConfuseExecute((DWORD)GetAPIAddr);			// ��ȡ������API��ַ
	//ConfuseExecute((DWORD)xorsection);		// ���ܴ����(���
	ConfuseExecute((DWORD)AESDecryptAllSection);	// ���ܴ����(AES
	ConfuseExecute((DWORD)UncompressSection);		// ��ѹ������
	ConfuseExecute((DWORD)StaticAntiDebug);	// ������
	ConfuseExecute((DWORD)AlertPassWindow);	// �ָ�����Ŀ¼��
	//ConfuseExecute((DWORD)ShowMyWindows);	// �ָ�����Ŀ¼��//
	ConfuseExecute((DWORD)FixOldReloc);		// �޸�ԭʼ�����ض�λ
	ConfuseExecute((DWORD)EncodeIAT);		// ����IAT
	//ConfuseExecute((DWORD)CallTls);			// ִ��TLS�ص�����//here
}

// �Ǵ�����ʼ����
extern "C" __declspec(dllexport) __declspec(naked) void start()
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
	ConfuseExecute((DWORD)PackCode);

	// ����ִ��
	//getapi();//��ȡ������API��ַ
	//// ����(��ѹ��)����
	//xorsection();
	////DecryptSection();//���ܴ����
	//uncompress();// ��ѹ������
	////RecoverDataDirTab();//�ָ�����Ŀ¼��
	////StaticAntiDebug();//������
	////AlertPassBox();//���뵯��
	//ShowMyWindows();//���뵯��
	//FixOldReloc();// �޸�ԭʼ�����ض�λ
	//EncodeIat();//����IAT

	JmpOEP();// ��ת��ԭʼ oep
}
