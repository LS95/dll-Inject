#ifndef _APC_INJECT_H_
#define _APC_INJECT_H_


#include <Windows.h>
#include <TlHelp32.h>


// ���ݽ������ƻ�ȡPID
DWORD GetProcessIdByProcessName(char *pszProcessName);

// ����PID��ȡ���е���Ӧ�߳�ID
BOOL GetAllThreadIdByProcessId(DWORD dwProcessId, DWORD **ppThreadId, DWORD *dwThreadIdLength);

// APCע��
BOOL ApcInjectDll(char *pszProcessName, char *pszDllName);


#endif