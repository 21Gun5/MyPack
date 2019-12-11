#pragma once
#include <windows.h>

typedef struct _SHAREDATA
{
	DWORD srcOep;		//��ڵ�
	DWORD textScnRVA;	//�����RVA
	DWORD textScnSize;	//����εĴ�С

	unsigned char key[16] = {};//������Կ
	int index = 0;			  //���ܵ��������� �õ�ʱ����Ҫ-1
	int data[20][2];  //���ܵ�����RVA��Size	

	DWORD dwDataDir[20][2];  //����Ŀ¼���RVA��Size	
	DWORD dwNumOfDataDir;	//����Ŀ¼��ĸ���

	DWORD oep;
	DWORD nImportVirtual;
	DWORD nImportSize;
	DWORD nRelocVirtual;
	DWORD nRelocSize;
	DWORD nResourceVirtual;
	DWORD nResourceSize;
	DWORD nTlsVirtual;
	DWORD nTlsSize;

}SHAREDATA;

typedef struct DosStub
{
	DWORD nOldImageBass;//���ӿǳ�������ǰĬ�ϵļ��ػ�ַ
	DWORD nStubTextSectionRva;//���ڿ������text��Rva
	DWORD nStubRelocSectionRva;//�ǵ��ض�λ����text�κϲ����ڱ��ӿǳ����Rva

}DosSub;

// ���庯��ָ��ͱ���
typedef void* (WINAPI *FnGetProcAddress)(HMODULE, const char*);
typedef void* (WINAPI *FnLoadLibraryA)(char*);
typedef void* (WINAPI *FnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HMODULE(WINAPI *fnGetMoudleHandleA)(_In_ LPCWSTR lpMoudleName);
typedef ATOM(WINAPI *fnRegisterClassEx)(_In_ const WNDCLASSEX *lpwcx);
typedef HWND(WINAPI *fnCreateWindowEx)(_In_ DWORD dwExStyle, _In_opt_ LPCTSTR lpClassName, _In_opt_ LPCTSTR lpWindowName, _In_ DWORD dwStyle, _In_ int x, _In_ int y, _In_ int nWidth, _In_ int nHeight, _In_opt_ HWND hWndParent, _In_opt_ HMENU hMenu, _In_opt_ HINSTANCE hInstance, _In_opt_ LPVOID lpParam);
typedef BOOL(*fnUpdateWindow)(HWND hWnd);
typedef BOOL(WINAPI* fnShowWindow)(_In_ HWND hWnd, _In_ int nCmdShow);
typedef BOOL(WINAPI* fnGetMessage)(_Out_ LPMSG lpMsg, _In_opt_ HWND hWnd, _In_ UINT wMsgFilterMin, _In_ UINT wMsgFilterMax);
typedef BOOL(WINAPI* fnTranslateMessage)(_In_ CONST MSG *lpMsg);
typedef LRESULT(WINAPI* fnDispatchMessageW)(_In_ CONST MSG *lpMsg);
typedef int (WINAPI* fnGetWindowTextW)(_In_ HWND hWnd, _Out_writes_(nMaxCount) LPWSTR lpString, _In_ int nMaxCount);
typedef void (WINAPI* fnExitProcess)(_In_ UINT uExitCode);
typedef LRESULT(WINAPI* fnSendMessageW)(_In_ HWND hWnd, _In_ UINT Msg, _Pre_maybenull_ _Post_valid_ WPARAM wParam, _Pre_maybenull_ _Post_valid_ LPARAM lParam);
typedef LRESULT(WINAPI* fnDefWindowProcW)(_In_ HWND hWnd, _In_ UINT Msg, _In_ WPARAM wParam, _In_ LPARAM lParam);
typedef void (WINAPI* fnPostQuitMessage)(_In_ int nExitCode);
typedef HWND(WINAPI* fnFindWindowW)(_In_opt_ LPCWSTR lpClassName, _In_opt_ LPCWSTR lpWindowName);
typedef int (WINAPI* fnMessageBoxW)(_In_opt_ HWND hWnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType);
typedef HDC(WINAPI* fnBeginPaint)(_In_ HWND hWnd, _Out_ LPPAINTSTRUCT lpPaint);
typedef BOOL(WINAPI* fnEndPaint)(_In_ HWND hWnd, _In_ CONST PAINTSTRUCT *lpPaint);
typedef LPVOID(WINAPI* FnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef VOID(WINAPI* FnRtlMoveMemory)(LPVOID, LPVOID, SIZE_T);