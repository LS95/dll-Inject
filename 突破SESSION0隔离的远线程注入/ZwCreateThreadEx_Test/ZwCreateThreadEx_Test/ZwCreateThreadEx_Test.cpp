// ZwCreateThreadEx_Test.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "InjectDll.h"
#include "AdjustTokenPrivilegesTest.h"


int _tmain(int argc, _TCHAR* argv[])
{
	int injectPID = 0;
	printf("please input PID:");
	scanf("%d", &injectPID);

	// ������ǰ��������Ȩ��
	EnbalePrivileges(::GetCurrentProcess(), SE_DEBUG_NAME);
	// Զ�߳�ע�� DLL
#ifndef _WIN64
	BOOL bRet = ZwCreateThreadExInjectDll(8080, "C:\\Users\\DemonGan\\Desktop\\ZwCreateThreadEx_Test\\Debug\\TestDll.dll");
	bRet = ZwCreateThreadExInjectDll(injectPID, "C:\\TestDll.dll");
#else 
	BOOL bRet = ZwCreateThreadExInjectDll(injectPID, "C:\\TestDll.dll");
#endif
	if (FALSE == bRet)
	{
		printf("Inject Dll Error.\n");
	}
	printf("Inject Dll OK.\n");
	system("pause");
	return 0;
}

