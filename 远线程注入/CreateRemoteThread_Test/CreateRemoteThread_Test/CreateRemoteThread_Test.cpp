// CreateRemoteThread_Test.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "InjectDll.h"
#include "AdjustTokenPrivilegesTest.h"


int _tmain(int argc, _TCHAR* argv[])
{
	// ������ǰ��������Ȩ��
	EnbalePrivileges(::GetCurrentProcess(), SE_DEBUG_NAME);
	// Զ�߳�ע�� DLL
#ifndef _WIN64
	BOOL bRet = CreateRemoteThreadInjectDll(4316, "C:\\Users\\DemonGan\\Desktop\\CreateRemoteThread_Test\\Debug\\TestDll.dll");
#else 
	BOOL bRet = CreateRemoteThreadInjectDll(1144, "C:\\Users\\DemonGan\\Desktop\\CreateRemoteThread_Test\\x64\\Debug\\TestDll.dll");
#endif
	
	if (FALSE == bRet)
	{
		printf("Inject Dll Error.\n");
	}
	printf("Inject Dll OK.\n");
	system("pause");
	return 0;
}

