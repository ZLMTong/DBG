#pragma once
#include <windows.h>
#include "UserCommand.h"
#include "DbgException.h"

class CDbgEngine
{
public:
	CDbgEngine();
	~CDbgEngine();

	//主循环
	void DebugMain(/*const TCHAR* pszFile*/);

	//处理调试事件
	DWORD DispatchDbgEvent(DEBUG_EVENT& dbgEvent);

	//进程创建事件
	DWORD OnCreateProcess(DEBUG_EVENT& dbgEvent);

	//异常调试事件
	DWORD OnException(DEBUG_EVENT& dbgEvent);
	
private:
	CUserCommand m_userCommand;
	CDbgException m_dbgException;
};

