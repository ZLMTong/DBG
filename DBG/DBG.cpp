// DBG.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "DbgEngine.h"


void DaemonProcess()
{

	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi = { 0 };
	CreateProcess(L"G:\\ѧϰ����\\DBG\\DBG\\ע���HOOK�������������ָ������.exe",
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

