#include "stdafx.h"
#include "AdjustTokenPrivilegesTest.h"


void EP_ShowError(char *pszText)
{
	char szErr[MAX_PATH] = {0};
	::wsprintf(szErr, "%s Error[%d]\n", pszText, ::GetLastError());
	::MessageBox(NULL, szErr, "ERROR", MB_OK);
}


BOOL EnbalePrivileges(HANDLE hProcess, char *pszPrivilegesName)
{
	HANDLE hToken = NULL;
	LUID luidValue = {0};
	TOKEN_PRIVILEGES tokenPrivileges = {0};
	BOOL bRet = FALSE;
	DWORD dwRet = 0;


	// �򿪽������Ʋ���ȡ���� TOKEN_ADJUST_PRIVILEGES Ȩ�޵Ľ������ƾ��
	bRet = ::OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (FALSE == bRet)
	{
		EP_ShowError("OpenProcessToken");
		return FALSE;
	}
	// ��ȡ����ϵͳ�� pszPrivilegesName ��Ȩ��LUIDֵ
	bRet = ::LookupPrivilegeValue(NULL, pszPrivilegesName, &luidValue);
	if (FALSE == bRet)
	{
		EP_ShowError("LookupPrivilegeValue");
		return FALSE;
	}
	// ��������Ȩ����Ϣ
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luidValue;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	// �����������Ʒ���Ȩ��
	bRet = ::AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, 0, NULL, NULL);
	if (FALSE == bRet)
	{
		EP_ShowError("AdjustTokenPrivileges");
		return FALSE;
	}
	else
	{
		// ���ݴ������ж��Ƿ���Ȩ�����óɹ�
		dwRet = ::GetLastError();
		if (ERROR_SUCCESS == dwRet)
		{
			return TRUE;
		}
		else if (ERROR_NOT_ALL_ASSIGNED == dwRet)
		{
			EP_ShowError("ERROR_NOT_ALL_ASSIGNED");
			return FALSE;
		}
	}

	return FALSE;
}