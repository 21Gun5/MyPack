#pragma once

// ���ڹ������ݵĽṹ��
typedef struct _SHAREDATA
{
	long origOEP = 0;	//ԭʼOEP
	long rva = 0;		// ������λ�õ�RVA
	long size = 0;		// ���ܵĴ�С
	BYTE key = 0;		// ����ʱ��Կ
}SHAREDATA, PSHAREDATA;

// ��������ָ��
typedef void* (WINAPI *PLoadLibraryA)(char*);
typedef void* (WINAPI *PVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HMODULE(WINAPI *PGetMoudleHandleA)(_In_ LPCWSTR lpMoudleName);
typedef ATOM(WINAPI *PRegisterClassEx)(_In_ const WNDCLASSEX *lpwcx);
typedef BOOL(*PUpdateWindow)(HWND hWnd);
typedef BOOL(WINAPI* PShowWindow)(_In_ HWND hWnd, _In_ int nCmdShow);
typedef BOOL(WINAPI* PGetMessage)(_Out_ LPMSG lpMsg, _In_opt_ HWND hWnd, _In_ UINT wMsgFilterMin, _In_ UINT wMsgFilterMax);
typedef BOOL(WINAPI* PTranslateMessage)(_In_ CONST MSG *lpMsg);
typedef LRESULT(WINAPI* PDispatchMessageW)(_In_ CONST MSG *lpMsg);
typedef int (WINAPI* PGetWindowTextW)(_In_ HWND hWnd, _Out_writes_(nMaxCount) LPWSTR lpString, _In_ int nMaxCount);
typedef void (WINAPI* PExitProcess)(_In_ UINT uExitCode);
typedef LRESULT(WINAPI* PDefWindowProcW)(_In_ HWND hWnd, _In_ UINT Msg, _In_ WPARAM wParam, _In_ LPARAM lParam);
typedef void (WINAPI* PPostQuitMessage)(_In_ int nExitCode);
typedef HWND(WINAPI* PFindWindowW)(_In_opt_ LPCWSTR lpClassName, _In_opt_ LPCWSTR lpWindowName);
typedef int (WINAPI* PMessageBoxW)(_In_opt_ HWND hWnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType);
typedef HWND(WINAPI *PCreateWindowEx)(_In_ DWORD dwExStyle, _In_opt_ LPCTSTR lpClassName,_In_opt_ LPCTSTR lpWindowName, _In_ DWORD dwStyle,_In_ int x,_In_ int y,_In_ int nWidth,_In_ int nHeight,_In_opt_ HWND hWndParent, _In_opt_ HMENU hMenu,_In_opt_ HINSTANCE hInstance,_In_opt_ LPVOID lpParam);
typedef LRESULT(WINAPI* PSendMessageW)(_In_ HWND hWnd,_In_ UINT Msg,_Pre_maybenull_ _Post_valid_ WPARAM wParam, _Pre_maybenull_ _Post_valid_ LPARAM lParam);

// ������������ԭ��
LRESULT CALLBACK WndPrco(HWND, UINT, WPARAM, LPARAM);