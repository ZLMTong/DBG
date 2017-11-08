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
	WCHAR szPath[] = L"D:\\MFC Day003��ť�Ի�.exe";
	//�������Խ���
	BOOL bProc = FALSE;
	STARTUPINFO stcStartupInfo = { sizeof(STARTUPINFO) };
	bProc = CreateProcess(szPath, NULL, NULL, NULL, FALSE,
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
		NULL, NULL, &stcStartupInfo, &m_userCommand.m_stcProcInfo);
	//��������ѭ��
	DEBUG_EVENT dbgEvent = { 0 };
	DWORD dwRetCode = DBG_CONTINUE;		//�Լ������˲ŷ���continue
	while (1)
	{
		//�ȴ������¼�
		WaitForDebugEvent(&dbgEvent, -1);
		//�ַ������¼�
		dwRetCode = DispatchDbgEvent(dbgEvent);
		//�ظ�������ϵͳ
		ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, dwRetCode);
	}
}

//��������¼�
DWORD CDbgEngine::DispatchDbgEvent(DEBUG_EVENT& dbgEvent)
{
	DWORD dwReply = DBG_EXCEPTION_NOT_HANDLED;		//�쳣û�б�����

	//��������¼�
	switch (dbgEvent.dwDebugEventCode)
	{
		//���̴����ĵ����¼�
	case CREATE_PROCESS_DEBUG_EVENT:
		OnCreateProcess(dbgEvent);
		break;
		//-------�쳣�ĵ����¼�--------
	case EXCEPTION_DEBUG_EVENT:
		dwReply = OnException(dbgEvent);
		break;
	}
	return dwReply;
}

//���̴����¼�
DWORD CDbgEngine::OnCreateProcess(DEBUG_EVENT& dbgEvent)
{
	// ���������Ϣ�������߳���Ϣ
	m_userCommand.m_stcProcInfo.dwProcessId = dbgEvent.dwProcessId;
	m_userCommand.m_stcProcInfo.dwThreadId = dbgEvent.dwThreadId;
	// ���̾��������ʹ��
	m_userCommand.m_stcProcInfo.hProcess = dbgEvent.u.CreateProcessInfo.hProcess;
	// ����߳̾������ʹ��
	m_userCommand.m_stcProcInfo.hThread = dbgEvent.u.CreateProcessInfo.hThread;
	//OEP
	m_userCommand.m_dwOEP = (DWORD)dbgEvent.u.CreateProcessInfo.lpStartAddress;

	return DBG_CONTINUE;
}

//�쳣�����¼�
DWORD CDbgEngine::OnException(DEBUG_EVENT& dbgEvent)
{
	// �����쳣���ͷֱ���
	DWORD dwRet = DBG_CONTINUE;
	switch (dbgEvent.u.Exception.ExceptionRecord.ExceptionCode)
	{
	case EXCEPTION_BREAKPOINT:			//����ϵ�
		dwRet = m_dbgException.OnExceptionCc(dbgEvent, m_userCommand);
		break;
	case EXCEPTION_SINGLE_STEP:			//�����쳣
		//�ж���ʲô�쳣,������û������򲻽����޸�����
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
	case EXCEPTION_ACCESS_VIOLATION:	//�ڴ�����쳣
		dwRet = m_dbgException.OnExceptionAccess(dbgEvent, m_userCommand);
		break;
	default:
		break;
	}
	//����-1��ʾ���ȴ��û�����
	if (dwRet == -1)
	{
		return DBG_CONTINUE;
	}
	m_userCommand.WaitforUserCommand(&dbgEvent);
	return dwRet;
}
