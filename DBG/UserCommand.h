#pragma once
#include <windows.h>
#include <atlstr.h>
#include <iostream>
#include <strsafe.h>
#include "MyType.h"
#include<vector>
#include <TlHelp32.h>
using namespace std;
#define MAX_INPUT 1024   // 控制台命令最大长度
#define  WCHAR_TO_CHAR(lpW_Char, lpChar) \
    WideCharToMultiByte(CP_ACP, NULL, lpW_Char, -1, lpChar, _countof(lpChar), NULL, FALSE);



class CUserCommand
{
public:

	typedef struct {
		DWORD dwAddress;    //断点地址
		BYTE bContent;     //原指令第一个字节
	} BREAK_POINT;

	CUserCommand();
	~CUserCommand();

	// 等待用户输入调试命令
	DWORD WaitforUserCommand(LPDEBUG_EVENT pDbgEvent);

	/*------------------------用户命令------------------------*/
	// t命令
	void UserCommandT(LPDEBUG_EVENT pDbgEvent);

	// b命令->各种断点
	void UserCommandB(LPDEBUG_EVENT pDbgEvent,CHAR* pCommand);

	// u命令
	void UserCommandU(LPDEBUG_EVENT pDbgEvt);

	//bp软件断点
	void UserCommandBP(LPDEBUG_EVENT pDbgEvent,DWORD dAddress);

	//bh硬件执行断点
	BOOL UserCommandBH(LPDEBUG_EVENT pDbgEvent, DWORD dAddress);

	//bm内存断点
	void UserCommandBM(LPDEBUG_EVENT pDbgEvent,DWORD dAddress);

	//c->条件断点
	void UserCommandC(LPDEBUG_EVENT pDbgEvent);

	// m->模块命令
	void UserCommandM(LPDEBUG_EVENT pDbgEvent);

	// 	//bh硬件读写断点
	// 	BOOL setBreakpoint_hardRW();
	/*------------------------用户命令------------------------*/

	/*------------------------导入导出表----------------------*/
	DWORD RVAToOffset(IMAGE_DOS_HEADER* pDos, DWORD dwRva);

	void WirteUpdataFileValue(CString strPath, char* szContext);

	void GetExportTableInfo();

	void GetImportTableInfo();
	/*------------------------导入导出表----------------------*/

	// 打印寄存器信息
	VOID ShowRegisterInfo(CONTEXT& ct);

	//栈
	void UserCommandK(LPDEBUG_EVENT pDbgEvent);

	// 反汇编函数
	void DisasmAtAddr(DWORD dwAddr, DWORD dwCount = 10);
	UINT DBG_Disasm(HANDLE hProcess, LPVOID lpAddress, PWCHAR pOPCode, PWCHAR pASM, PWCHAR pComment);


	DWORD m_dwBPAddress = 0;					//软件断点地址
	DWORD m_dwBMAddress = 0;					//内存断点地址
	DWORD m_dwBHAddress = 0;					//硬件断点地址
	DWORD m_dwOldProtect;						//内存断点地址
	DWORD m_dwOEP;								//oep
	DWORD m_dwConditionAddress;					//条件断点地址
	BOOL  m_bIsUserBrk;							//判断是否是用户T单步
	BOOL  m_bIsSingle = TRUE;					//判断是否恢复断点
	BOOL  m_bIsCondition = FALSE;				//是否触发条件断点
	CHAR  m_cCondition[20] = {};				//条件断点
	CHAR  m_dwConditionNum[8] = {};				//条件断点
	INT   m_nNum;								//条件断点
	vector<BREAK_POINT>m_vecInt3Info;			//保存int3 的断点
	vector<DWORD>m_vecHardExec;					//保存硬件断点的地址
	vector<MODULEENTRY32>m_vecModuleInfo;		//保存模块名称
	PROCESS_INFORMATION m_stcProcInfo = { 0 };	//调试进程的信息

};

