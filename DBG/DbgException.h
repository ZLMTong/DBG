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

	// ����ϵ��쳣
	DWORD OnExceptionCc(DEBUG_EVENT& dbgEvent, CUserCommand& userCommand);
	// �����쳣
	DWORD OnExceptionSingleStep(DEBUG_EVENT& dbgEvent, CUserCommand& userCommand);
	// �ڴ�����쳣
	DWORD OnExceptionAccess(DEBUG_EVENT& dbgEvent, CUserCommand& userCommand);

private:
	BOOL m_bIsMemroyEx = TRUE;					//�ж��Ƿ�Ϊ���ڴ�ϵ�ĵ�ַ
	BOOL m_bIsHardEx = TRUE;					//�ж�Ӳ���ϵ��Ƿ����޸�
};

