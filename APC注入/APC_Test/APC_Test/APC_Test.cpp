// APC_Test.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "ApcInject.h"


int _tmain(int argc, _TCHAR* argv[])
{
	BOOL bRet = FALSE;

	// APCע��
#ifdef _WIN64
	//bRet = ApcInjectDll("explorer.exe", "C:\\Users\\DemonGan\\Desktop\\APC_Test\\x64\\Debug\\TestDll.dll");
	bRet = ApcInjectDll("explorer.exe", "C:\\TestDll.dll");
#else
	//bRet = ApcInjectDll("explorer.exe", "C:\\Users\\DemonGan\\Desktop\\APC_Test\\Debug\\TestDll.dll");
	bRet = ApcInjectDll("explorer.exe", "C:\\TestDll.dll");
#endif
	if (bRet)
	{
		printf("APC Inject OK.\n");
	}
	else
	{
		printf("APC Inject ERROR.\n");
	}

	system("pause");
	return 0;
}

