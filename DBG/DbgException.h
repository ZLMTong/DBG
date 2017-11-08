#pragma once
#include "MyType.h"
#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include <iostream>
#include "UserCommand.h"
using namespace std;

class CDbgException
{
public:
	CDbgException();
	~CDbgException();

	// 软件断点异常
	DWORD OnExceptionCc(DEBUG_EVENT& dbgEvent, CUserCommand& userCommand);
	// 单步异常
	DWORD OnExceptionSingleStep(DEBUG_EVENT& dbgEvent, CUserCommand& userCommand);
	// 内存访问异常
	DWORD OnExceptionAccess(DEBUG_EVENT& dbgEvent, CUserCommand& userCommand);

private:
	BOOL m_bIsMemroyEx = TRUE;					//判断是否为下内存断点的地址
	BOOL m_bIsHardEx = TRUE;					//判断硬件断点是否已修复
};

