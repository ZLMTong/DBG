// DBG.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "DbgEngine.h"


void DaemonProcess()
{

	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi = { 0 };
	CreateProcess(L"G:\\学习资料\\DBG\\DBG\\注入和HOOK任务管理器保存指定进程.exe",
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		&si,
		&pi);
}


int main()
{
	DaemonProcess();

	CDbgEngine m_dbgEngine;
	m_dbgEngine.DebugMain();
    return 0;
}

