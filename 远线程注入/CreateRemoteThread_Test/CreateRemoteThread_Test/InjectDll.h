#ifndef _INJECT_DLL_H_
#define _INJECT_DLL_H_


#include <Windows.h>


// ʹ�� CreateRemoteThread ʵ��Զ�߳�ע��
BOOL CreateRemoteThreadInjectDll(DWORD dwProcessId, char *pszDllFileName);


#endif