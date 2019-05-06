#include "stdafx.h"
#include "ApcInject.h"


void ShowError(char *pszText)
{
	char szErr[MAX_PATH] = { 0 };
	::wsprintf(szErr, "%s Error[%d]\n", pszText);
	::MessageBox(NULL, szErr, "ERROR", MB_OK | MB_ICONERROR);
}


// ���ݽ������ƻ�ȡPID
DWORD GetProcessIdByProcessName(char *pszProcessName)
{
	DWORD dwProcessId = 0;
	PROCESSENTRY32 pe32 = { 0 };
	HANDLE hSnapshot = NULL;
	BOOL bRet = FALSE;
	::RtlZeroMemory(&pe32, sizeof(pe32));
	pe32.dwSize = sizeof(pe32);

	// ��ȡ���̿���
	hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (NULL == hSnapshot)
	{
		ShowError("CreateToolhelp32Snapshot");
		return dwProcessId;
	}

	// ��ȡ��һ�����̿�����Ϣ
	bRet = ::Process32First(hSnapshot, &pe32);
	while (bRet)
	{
		// ��ȡ������Ϣ
		if (0 == ::lstrcmpi(pe32.szExeFile, pszProcessName))
		{
			dwProcessId = pe32.th32ProcessID;
			break;
		}

		// ������һ�����̿�����Ϣ
		bRet = ::Process32Next(hSnapshot, &pe32);
	}

	return dwProcessId;
}


// ����PID��ȡ���е���Ӧ�߳�ID
BOOL GetAllThreadIdByProcessId(DWORD dwProcessId, DWORD **ppThreadId, DWORD *pdwThreadIdLength)
{
	DWORD *pThreadId = NULL;
	DWORD dwThreadIdLength = 0;
	DWORD dwBufferLength = 1000;
	THREADENTRY32 te32 = { 0 };
	HANDLE hSnapshot = NULL;
	BOOL bRet = TRUE;

	do
	{
		// �����ڴ�
		pThreadId = new DWORD[dwBufferLength];
		if (NULL == pThreadId)
		{
			ShowError("new");
			bRet = FALSE;
			break;
		}
		::RtlZeroMemory(pThreadId, (dwBufferLength * sizeof(DWORD)));

		// ��ȡ�߳̿���
		::RtlZeroMemory(&te32, sizeof(te32));
		te32.dwSize = sizeof(te32);
		hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (NULL == hSnapshot)
		{
			ShowError("CreateToolhelp32Snapshot");
			bRet = FALSE;
			break;
		}

		// ��ȡ��һ���߳̿�����Ϣ
		bRet = ::Thread32First(hSnapshot, &te32);
		while (bRet)
		{
			// ��ȡ���̶�Ӧ���߳�ID
			if (te32.th32OwnerProcessID == dwProcessId)
			{
				pThreadId[dwThreadIdLength] = te32.th32ThreadID;
				dwThreadIdLength++;
			}

			// ������һ���߳̿�����Ϣ
			bRet = ::Thread32Next(hSnapshot, &te32);
		}

		// ����
		*ppThreadId = pThreadId;
		*pdwThreadIdLength = dwThreadIdLength;
		bRet = TRUE;

	} while (FALSE);

	if (FALSE == bRet)
	{
		if (pThreadId)
		{
			delete[]pThreadId;
			pThreadId = NULL;
		}
	}

	return bRet;
}


// APCע��
BOOL ApcInjectDll(char *pszProcessName, char *pszDllName)
{
	BOOL bRet = FALSE;
	DWORD dwProcessId = 0;
	DWORD *pThreadId = NULL;
	DWORD dwThreadIdLength = 0;
	HANDLE hProcess = NULL, hThread = NULL;
	PVOID pBaseAddress = NULL;
	PVOID pLoadLibraryAFunc = NULL;
	SIZE_T dwRet = 0, dwDllPathLen = 1 + ::lstrlen(pszDllName);
	DWORD i = 0;

	do
	{
		// ���ݽ������ƻ�ȡPID
		dwProcessId = GetProcessIdByProcessName(pszProcessName);
		if (0 >= dwProcessId)
		{
			bRet = FALSE;
			break;
		}

		// ����PID��ȡ���е���Ӧ�߳�ID
		bRet = GetAllThreadIdByProcessId(dwProcessId, &pThreadId, &dwThreadIdLength);
		if (FALSE == bRet)
		{
			bRet = FALSE;
			break;
		}

		// ��ע�����
		hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
		if (NULL == hProcess)
		{
			ShowError("OpenProcess");
			bRet = FALSE;
			break;
		}

		// ��ע����̿ռ������ڴ�
		pBaseAddress = ::VirtualAllocEx(hProcess, NULL, dwDllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (NULL == pBaseAddress)
		{
			ShowError("VirtualAllocEx");
			bRet = FALSE;
			break;
		}
		// ������Ŀռ���д��DLL·������ 
		::WriteProcessMemory(hProcess, pBaseAddress, pszDllName, dwDllPathLen, &dwRet);
		if (dwRet != dwDllPathLen)
		{
			ShowError("WriteProcessMemory");
			bRet = FALSE;
			break;
		}

		// ��ȡ LoadLibrary ��ַ
		pLoadLibraryAFunc = ::GetProcAddress(::GetModuleHandle("kernel32.dll"), "LoadLibraryA");
		if (NULL == pLoadLibraryAFunc)
		{
			ShowError("GetProcessAddress");
			bRet = FALSE;
			break;
		}

		// �����߳�, ����APC
		for (i = 0; i < dwThreadIdLength; i++)
		{
			// ���߳�
			hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, pThreadId[i]);
			if (hThread)
			{
				// ����APC
				::QueueUserAPC((PAPCFUNC)pLoadLibraryAFunc, hThread, (ULONG_PTR)pBaseAddress);
				// �ر��߳̾��
				::CloseHandle(hThread);
				hThread = NULL;
			}
		}

		bRet = TRUE;

	} while (FALSE);

	// �ͷ��ڴ�
	if (hProcess)
	{
		::CloseHandle(hProcess);
		hProcess = NULL;
	}
	if (pThreadId)
	{
		delete[]pThreadId;
		pThreadId = NULL;
	}

	return bRet;
}