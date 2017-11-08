#pragma once
#include <windows.h>
#include <atlstr.h>
#include <iostream>
#include <strsafe.h>
#include "MyType.h"
#include<vector>
#include <TlHelp32.h>
using namespace std;
#define MAX_INPUT 1024   // ����̨������󳤶�
#define  WCHAR_TO_CHAR(lpW_Char, lpChar) \
    WideCharToMultiByte(CP_ACP, NULL, lpW_Char, -1, lpChar, _countof(lpChar), NULL, FALSE);



class CUserCommand
{
public:

	typedef struct {
		DWORD dwAddress;    //�ϵ��ַ
		BYTE bContent;     //ԭָ���һ���ֽ�
	} BREAK_POINT;

	CUserCommand();
	~CUserCommand();

	// �ȴ��û������������
	DWORD WaitforUserCommand(LPDEBUG_EVENT pDbgEvent);

	/*------------------------�û�����------------------------*/
	// t����
	void UserCommandT(LPDEBUG_EVENT pDbgEvent);

	// b����->���ֶϵ�
	void UserCommandB(LPDEBUG_EVENT pDbgEvent,CHAR* pCommand);

	// u����
	void UserCommandU(LPDEBUG_EVENT pDbgEvt);

	//bp����ϵ�
	void UserCommandBP(LPDEBUG_EVENT pDbgEvent,DWORD dAddress);

	//bhӲ��ִ�жϵ�
	BOOL UserCommandBH(LPDEBUG_EVENT pDbgEvent, DWORD dAddress);

	//bm�ڴ�ϵ�
	void UserCommandBM(LPDEBUG_EVENT pDbgEvent,DWORD dAddress);

	//c->�����ϵ�
	void UserCommandC(LPDEBUG_EVENT pDbgEvent);

	// m->ģ������
	void UserCommandM(LPDEBUG_EVENT pDbgEvent);

	// 	//bhӲ����д�ϵ�
	// 	BOOL setBreakpoint_hardRW();
	/*------------------------�û�����------------------------*/

	/*------------------------���뵼����----------------------*/
	DWORD RVAToOffset(IMAGE_DOS_HEADER* pDos, DWORD dwRva);

	void WirteUpdataFileValue(CString strPath, char* szContext);

	void GetExportTableInfo();

	void GetImportTableInfo();
	/*------------------------���뵼����----------------------*/

	// ��ӡ�Ĵ�����Ϣ
	VOID ShowRegisterInfo(CONTEXT& ct);

	//ջ
	void UserCommandK(LPDEBUG_EVENT pDbgEvent);

	// ����ຯ��
	void DisasmAtAddr(DWORD dwAddr, DWORD dwCount = 10);
	UINT DBG_Disasm(HANDLE hProcess, LPVOID lpAddress, PWCHAR pOPCode, PWCHAR pASM, PWCHAR pComment);


	DWORD m_dwBPAddress = 0;					//����ϵ��ַ
	DWORD m_dwBMAddress = 0;					//�ڴ�ϵ��ַ
	DWORD m_dwBHAddress = 0;					//Ӳ���ϵ��ַ
	DWORD m_dwOldProtect;						//�ڴ�ϵ��ַ
	DWORD m_dwOEP;								//oep
	DWORD m_dwConditionAddress;					//�����ϵ��ַ
	BOOL  m_bIsUserBrk;							//�ж��Ƿ����û�T����
	BOOL  m_bIsSingle = TRUE;					//�ж��Ƿ�ָ��ϵ�
	BOOL  m_bIsCondition = FALSE;				//�Ƿ񴥷������ϵ�
	CHAR  m_cCondition[20] = {};				//�����ϵ�
	CHAR  m_dwConditionNum[8] = {};				//�����ϵ�
	INT   m_nNum;								//�����ϵ�
	vector<BREAK_POINT>m_vecInt3Info;			//����int3 �Ķϵ�
	vector<DWORD>m_vecHardExec;					//����Ӳ���ϵ�ĵ�ַ
	vector<MODULEENTRY32>m_vecModuleInfo;		//����ģ������
	PROCESS_INFORMATION m_stcProcInfo = { 0 };	//���Խ��̵���Ϣ

};

