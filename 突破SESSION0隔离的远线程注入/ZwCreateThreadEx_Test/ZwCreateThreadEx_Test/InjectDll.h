#ifndef _INJECT_DLL_H_
#define _INJECT_DLL_H_


#include <Windows.h>


// ʹ�� ZwCreateThreadEx ʵ��Զ�߳�ע��
BOOL ZwCreateThreadExInjectDll(DWORD dwProcessId, char *pszDllFileName);


#endif