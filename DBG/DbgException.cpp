#include "stdafx.h"
#include "DbgException.h"



CDbgException::CDbgException()
{
}


CDbgException::~CDbgException()
{
}

//恢复软件断点原指令
DWORD CDbgException::OnExceptionCc(DEBUG_EVENT& dbgEvent, CUserCommand& userCommand)
{
	// 1.是你设置的软件断点
	// 把CC写回去
	// 设置1个单步
	// 设置1个标记位 保存要恢复的断点的索引
	if ((int)userCommand.m_vecInt3Info.size() > 0)
	{
		for (int i = 0; i < (int)userCommand.m_vecInt3Info.size(); ++i)
		{
			if (userCommand.m_vecInt3Info[i].dwAddress == (DWORD)dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress)
			{
				DWORD dwSize = 0;
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, dbgEvent.dwProcessId);
				WriteProcessMemory(hProcess, (LPVOID)(userCommand.m_vecInt3Info[i].dwAddress), &(userCommand.m_vecInt3Info[i].bContent), 1, &dwSize);
				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, NULL, dbgEvent.dwThreadId);
				CONTEXT ct = {};
				ct.ContextFlags = CONTEXT_ALL;// 指定要获取哪写寄存器的信息，很重要
				GetThreadContext(hThread, &ct);
				PEFLAGS pElg = (PEFLAGS)&ct.EFlags;
				--ct.Eip;
				pElg->TF = 1;
				userCommand.m_bIsSingle = FALSE;
				SetThreadContext(hThread, &ct);
				CloseHandle(hProcess);
				break;
			}
		}
	}
	return DBG_CONTINUE;
}

//单步异常
DWORD CDbgException::OnExceptionSingleStep(DEBUG_EVENT& dbgEvent, CUserCommand& userCommand)
{
	//设置内存断点
	if (!m_bIsMemroyEx) {
		userCommand.UserCommandBM(&dbgEvent, userCommand.m_dwBMAddress);
		m_bIsMemroyEx = TRUE;
		return -1;
	}
	//设置软件断点/硬件断点/条件断点
	if (!userCommand.m_bIsSingle || !m_bIsHardEx || userCommand.m_bIsCondition)
	{
		m_bIsHardEx = TRUE;
		//恢复硬件断点
		HANDLE hThread = OpenThread(PROCESS_ALL_ACCESS, 0, dbgEvent.dwThreadId);
		CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
		GetThreadContext(hThread, &ct);
		DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;

		if (pDr7->L0 == 0 && ct.Dr0 != 0)
		{
			pDr7->L0 = 1;
		}
		if (pDr7->L1 == 0 && ct.Dr1 != 0)
		{
			pDr7->L1 = 1;
		}
		if (pDr7->L2 == 0 && ct.Dr2 != 0)
		{
			pDr7->L2 = 1;
		}
		if (pDr7->L3 == 0 && ct.Dr3 != 0)
		{
			pDr7->L3 = 1;
		}
		//恢复软件断点
		userCommand.m_bIsSingle = TRUE;
		if (userCommand.m_vecInt3Info.size() > 0)
		{
			for (int i = 0; i < (int)userCommand.m_vecInt3Info.size(); ++i)
			{
				DWORD dwSize = 0;
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, dbgEvent.dwProcessId);
				BYTE cc = '\xcc';
				WriteProcessMemory(hProcess, (LPVOID)userCommand.m_vecInt3Info[i].dwAddress, &cc, 1, &dwSize);
				CloseHandle(hProcess);
			}
		}
		SetThreadContext(hThread, &ct);
		CloseHandle(hThread);
		//条件断点
		if (userCommand.m_bIsCondition)
		{
			HANDLE hThread = OpenThread(PROCESS_ALL_ACCESS, 0, dbgEvent.dwThreadId);
			CONTEXT ct = { CONTEXT_ALL };
			GetThreadContext(hThread, &ct);
			PEFLAGS pElg = (PEFLAGS)&ct.EFlags;
			pElg->TF = 1;
			SetThreadContext(hThread, &ct);
			CloseHandle(hThread);
			switch (userCommand.m_cCondition[1])
			{
			case'a':
			{
				switch (userCommand.m_cCondition[3]) {
				case'>':
					if (ct.Eax > userCommand.m_nNum) {
						return DBG_CONTINUE;
					}
					else {
						return -1;
					}
					break;
				case'<':
					if (ct.Eax < userCommand.m_nNum) {
						return DBG_CONTINUE;
					}
					else {
						return -1;
					}
					break;
				case'=':
					if (ct.Eax < userCommand.m_nNum) {
						return DBG_CONTINUE;
					}
					else {
						return -1;
					}
					break;
				}
			}
			break;
			case'c':
			{
				switch (userCommand.m_cCondition[3]) {
				case'>':
					if (ct.Ecx > userCommand.m_nNum) {
						return DBG_CONTINUE;
					}
					else {
						return -1;
					}
					break;
				case'<':
					if (ct.Ecx < userCommand.m_nNum) {
						return DBG_CONTINUE;
					}
					else {
						return -1;
					}
					break;
				case'=':
					if (ct.Ecx < userCommand.m_nNum) {
						return DBG_CONTINUE;
					}
					else {
						return -1;
					}
					break;
				}
			}
			break;
			}
			
		}
		return -1;
	}

	//恢复硬件断点原指令
	if (userCommand.m_vecHardExec.size() > 0)
	{
		HANDLE hThread = OpenThread(PROCESS_ALL_ACCESS, 0, dbgEvent.dwThreadId);
		CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
		GetThreadContext(hThread, &ct);
		DBG_REG6* pDr6 = (DBG_REG6*)&ct.Dr6;
		DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;
		PEFLAGS pElg = (PEFLAGS)&ct.EFlags;

		for (int i = 0; i < (int)userCommand.m_vecHardExec.size(); i++)
		{
			if (userCommand.m_vecHardExec[i] == (DWORD)dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress)
			{
				if (pDr6->B0 == 1)
				{
					pDr7->L0 = 0;
					pElg->TF = 1;
					userCommand.m_bIsSingle = FALSE;
				}
				if (pDr6->B1 == 1)
				{
					pDr7->L1 = 0;
					pElg->TF = 1;
					userCommand.m_bIsSingle = FALSE;
				}
				if (pDr6->B2 == 1)
				{
					pDr7->L2 = 0;
					pElg->TF = 1;
					userCommand.m_bIsSingle = FALSE;
				}
				if (pDr6->B3 == 1)
				{
					pDr7->L3 = 0;
					pElg->TF = 1;
					userCommand.m_bIsSingle = FALSE;
				}
				break;
			}
		}
		SetThreadContext(hThread, &ct);
		CloseHandle(hThread);
		m_bIsHardEx = FALSE;
		return DBG_CONTINUE;
	}
	return -1;
}

//内存断点
DWORD CDbgException::OnExceptionAccess(DEBUG_EVENT& dbgEvent, CUserCommand& userCommand)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, dbgEvent.dwProcessId);
	DWORD oldAccess;
	VirtualProtectEx(hProcess, (LPVOID)userCommand.m_dwBMAddress, sizeof(DWORD), userCommand.m_dwOldProtect, &oldAccess);

	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, NULL, dbgEvent.dwThreadId);
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// 指定要获取哪写寄存器的信息，很重要
	GetThreadContext(hThread, &ct);
	PEFLAGS pElg = (PEFLAGS)&ct.EFlags;
	m_bIsMemroyEx = FALSE;
	pElg->TF = 1;
	SetThreadContext(hThread, &ct);
	if ((DWORD)dbgEvent.u.Exception.ExceptionRecord.ExceptionInformation[1] == userCommand.m_dwBMAddress)
	{
		return DBG_CONTINUE;
	}
	CloseHandle(hProcess);
	CloseHandle(hThread);
	return -1;
}
