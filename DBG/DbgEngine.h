#pragma once
#include <windows.h>
#include "UserCommand.h"
#include "DbgException.h"

class CDbgEngine
{
public:
	CDbgEngine();
	~CDbgEngine();

	//��ѭ��
	void DebugMain(/*const TCHAR* pszFile*/);

	//��������¼�
	DWORD DispatchDbgEvent(DEBUG_EVENT& dbgEvent);

	//���̴����¼�
	DWORD OnCreateProcess(DEBUG_EVENT& dbgEvent);

	//�쳣�����¼�
	DWORD OnException(DEBUG_EVENT& dbgEvent);
	
private:
	CUserCommand m_userCommand;
	CDbgException m_dbgException;
};

