#include "stdafx.h"
#include "DbgEngine.h"


CDbgEngine::CDbgEngine()
{
}


CDbgEngine::~CDbgEngine()
{
}


void CDbgEngine::DebugMain(/*const TCHAR* pszFile*/)
{
	// 	if (pszFile == nullptr)
	// 	{
	// 		return false;
	// 	}
	WCHAR szPath[] = L"D:\\MFC Day003按钮自绘.exe";
	//创建调试进程
	BOOL bProc = FALSE;
	STARTUPINFO stcStartupInfo = { sizeof(STARTUPINFO) };
	bProc = CreateProcess(szPath, NULL, NULL, NULL, FALSE,
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
		NULL, NULL, &stcStartupInfo, &m_userCommand.m_stcProcInfo);
	//建立调试循环
	DEBUG_EVENT dbgEvent = { 0 };
	DWORD dwRetCode = DBG_CONTINUE;		//自己处理了才返回continue
	while (1)
	{
		//等待调试事件
		WaitForDebugEvent(&dbgEvent, -1);
		//分发调试事件
		dwRetCode = DispatchDbgEvent(dbgEvent);
		//回复调试子系统
		ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, dwRetCode);
	}
}

//处理调试事件
DWORD CDbgEngine::DispatchDbgEvent(DEBUG_EVENT& dbgEvent)
{
	DWORD dwReply = DBG_EXCEPTION_NOT_HANDLED;		//异常没有被处理

	//处理调试事件
	switch (dbgEvent.dwDebugEventCode)
	{
		//进程创建的调试事件
	case CREATE_PROCESS_DEBUG_EVENT:
		OnCreateProcess(dbgEvent);
		break;
		//-------异常的调试事件--------
	case EXCEPTION_DEBUG_EVENT:
		dwReply = OnException(dbgEvent);
		break;
	}
	return dwReply;
}

//进程创建事件
DWORD CDbgEngine::OnCreateProcess(DEBUG_EVENT& dbgEvent)
{
	// 保存进程信息，和主线程信息
	m_userCommand.m_stcProcInfo.dwProcessId = dbgEvent.dwProcessId;
	m_userCommand.m_stcProcInfo.dwThreadId = dbgEvent.dwThreadId;
	// 进程句柄，放心使用
	m_userCommand.m_stcProcInfo.hProcess = dbgEvent.u.CreateProcessInfo.hProcess;
	// 这个线程句柄谨慎使用
	m_userCommand.m_stcProcInfo.hThread = dbgEvent.u.CreateProcessInfo.hThread;
	//OEP
	m_userCommand.m_dwOEP = (DWORD)dbgEvent.u.CreateProcessInfo.lpStartAddress;

	return DBG_CONTINUE;
}

//异常调试事件
DWORD CDbgEngine::OnException(DEBUG_EVENT& dbgEvent)
{
	// 根据异常类型分别处理
	DWORD dwRet = DBG_CONTINUE;
	switch (dbgEvent.u.Exception.ExceptionRecord.ExceptionCode)
	{
	case EXCEPTION_BREAKPOINT:			//软件断点
		dwRet = m_dbgException.OnExceptionCc(dbgEvent, m_userCommand);
		break;
	case EXCEPTION_SINGLE_STEP:			//单步异常
		//判断是什么异常,如果是用户单步则不进入修复函数
		if (m_userCommand.m_bIsUserBrk)
		{
			m_userCommand.m_bIsUserBrk = FALSE;
			break;
		}
		else
		{
			dwRet = m_dbgException.OnExceptionSingleStep(dbgEvent, m_userCommand);
		}
		break;
	case EXCEPTION_ACCESS_VIOLATION:	//内存访问异常
		dwRet = m_dbgException.OnExceptionAccess(dbgEvent, m_userCommand);
		break;
	default:
		break;
	}
	//返回-1表示不等待用户输入
	if (dwRet == -1)
	{
		return DBG_CONTINUE;
	}
	m_userCommand.WaitforUserCommand(&dbgEvent);
	return dwRet;
}
