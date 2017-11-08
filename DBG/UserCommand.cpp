#include "stdafx.h"
#include "UserCommand.h"
/*******************************/
#define BEA_ENGINE_STATIC
#define BEA_USE_STDCALL
#include "Bea/headers/BeaEngine.h"
#pragma comment(lib, "Bea/Win32/Lib/BeaEngine.lib")
#pragma comment(linker, "/NODEFAULTLIB:\"crt.lib\"")
/*******************************/


DWORD WINAPI  ExportTable(_In_ LPVOID lpParameter)
{
	CUserCommand* pThis = (CUserCommand*)lpParameter;
	pThis->GetExportTableInfo();
	return true;
}

CUserCommand::CUserCommand()
{
}


CUserCommand::~CUserCommand()
{
}

//输出寄存器信息
VOID CUserCommand::ShowRegisterInfo(CONTEXT& ct)
{
	printf("--------------------------------------------------------------------------------------------------------\n"
		"\tEAX = 0x%08x\tEBX = 0x%08x\tECX = 0x%08x\tEDX = 0x%08x\t\n"
		"\tESP = 0x%08x\tEBP = 0x%08x\tESI = 0x%08x\tEIP = 0x%08x\t\n"
		"\tDr0 = 0x%08x\tDr1 = 0x%08x\tDr2 = 0x%08x\tDr3 = 0x%08x\t\n"
		"--------------------------------------------------------------------------------------------------------\n",
		ct.Eax, ct.Ebx, ct.Ecx, ct.Edx, ct.Esp, ct.Ebp, ct.Esi, ct.Eip,
		ct.Dr0, ct.Dr1, ct.Dr2, ct.Dr3
		);
}

DWORD CUserCommand::WaitforUserCommand(LPDEBUG_EVENT pDbgEvent)
{
// 1.输出寄存器信息
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, pDbgEvent->dwThreadId);
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// all register
	GetThreadContext(hThread, &ct);
	CloseHandle(hThread);
	ShowRegisterInfo(ct);
	// 2.输出反汇编信息
	// 从!!!异常地址!!!开始反汇编5行信息，不要从eip开始
	DisasmAtAddr((DWORD)pDbgEvent->u.Exception.ExceptionRecord.ExceptionAddress, 5);
	// 3.等待用户命令
	// 等待用户命令
	CHAR szCommand[MAX_INPUT] = {};
	while (1) {
		cout << "请输入调试命令:";
		gets_s(szCommand, MAX_INPUT);
		switch (szCommand[0]) {
		case 'u':							// 反汇编 继续接受用户命令
			UserCommandU(pDbgEvent);
			break;
		case 't':							// 单步F7
			UserCommandT(pDbgEvent);
			return DBG_CONTINUE;
		case 'g':							// go
			UserCommandT(pDbgEvent);
			m_bIsSingle = FALSE;
			m_bIsUserBrk = FALSE;
			return DBG_CONTINUE;
		case 'b':
			/*
			bp 软件断点
			bm 内存断点
			bh 硬件断点
			bl 查询断点列表
			*/
			UserCommandB(pDbgEvent,szCommand);
			break;
		case 'k':							// 查看函数调用栈帧
			UserCommandK(pDbgEvent);
			break;
		case 'm':							// 查看模块信息
			UserCommandM(pDbgEvent);
			break;
		case 'o':
			UserCommandBP(pDbgEvent,m_dwOEP);
			return DBG_CONTINUE;
		case'e':
			CreateThread(NULL, NULL, ExportTable, this, NULL, NULL);
			break;
		case'i':
			GetImportTableInfo();
			break;
		case'c':
			printf("请输入条件:");
			scanf_s("%s", m_cCondition, _countof(m_cCondition));
			UserCommandC(pDbgEvent);
			scanf_s("%*[^\n]");
			scanf_s("%*c");
			break;
		default:
			printf("请输入正确的指令：\n");
			break;
		}
	}
	return DBG_CONTINUE;
}

//用户单步命令
void CUserCommand::UserCommandT(LPDEBUG_EVENT pDbgEvent)
{
	// 设置单步
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, NULL, pDbgEvent->dwThreadId);
	//获取线程环境块
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;		// 指定要获取哪写寄存器的信息，很重要
	GetThreadContext(hThread, &ct);
	PEFLAGS pElg = (PEFLAGS)&ct.EFlags;
	PDBG_REG6 pDr6 = (PDBG_REG6)&ct.Dr6;
	pElg->TF = 1;
	SetThreadContext(hThread, &ct);		//设置线程环境块
	CloseHandle(hThread);
	m_bIsUserBrk = TRUE;
	m_bIsSingle = TRUE;
}

//b->各种断点命令
void CUserCommand::UserCommandB(LPDEBUG_EVENT pDbgEvent,CHAR* pCommand)
{
	switch (pCommand[1])
	{
	case 'p':
	{
		printf("请输入地址:");
		scanf_s("%x", &m_dwBPAddress);
		UserCommandBP(pDbgEvent, m_dwBPAddress);
		scanf_s("%*[^\n]");
		scanf_s("%*c");
	}
	break;
	case'h':
	{
		printf("请输入地址:");
		scanf_s("%x", &m_dwBHAddress);
		if (!UserCommandBH(pDbgEvent, m_dwBHAddress))
		{
			printf("没有可用寄存器\n");
		}
		scanf_s("%*[^\n]");
		scanf_s("%*c");
	}
	break;
	case'm':
	{
		printf("请输入地址:");
		scanf_s("%x", &m_dwBMAddress);
		UserCommandBM(pDbgEvent, m_dwBMAddress);
		scanf_s("%*[^\n]");
		scanf_s("%*c");
	}
	break;
	case'l':
	{
		for (DWORD i = 0; i < m_vecInt3Info.size(); i++)
		{
			printf("%x\n", m_vecInt3Info[i].dwAddress);
		}
	}
	break;
	default:
		break;
	}
	m_bIsCondition = FALSE;
}

//u->反汇编
void CUserCommand::UserCommandU(LPDEBUG_EVENT pDbgEvt)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, NULL, pDbgEvt->dwThreadId);
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// 指定要获取哪写寄存器的信息，很重要
	GetThreadContext(hThread, &ct);
	DisasmAtAddr(ct.Eip, 10);
	SetThreadContext(hThread, &ct);
	CloseHandle(hThread);
}

//bp->设置软件断点
void CUserCommand::UserCommandBP(LPDEBUG_EVENT pDbgEvent,DWORD dAddress)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pDbgEvent->dwProcessId);
	DWORD dwSize = 0;
	BYTE oldByte;
	DWORD dwOldProtect = 0;
	//修改内存分页属性，改为可读可写
	if (!VirtualProtectEx(hProcess, (LPVOID)dAddress, sizeof(DWORD), PAGE_READWRITE, &dwOldProtect)){
		CloseHandle(hProcess);
		return;
	}
	ReadProcessMemory(hProcess, (LPCVOID)dAddress, &oldByte, 1, &dwSize);
	//结构体保存软件断点的地址和指令
	BREAK_POINT oldInfo;
	oldInfo.dwAddress = dAddress;
	oldInfo.bContent = oldByte;
	BYTE cc = '\xcc';
	WriteProcessMemory(hProcess, (LPVOID)dAddress, &cc, 1, &dwSize);
	//修改为原来的内存分页属性
	VirtualProtectEx(hProcess, (LPVOID)dAddress, sizeof(DWORD), dwOldProtect, &dwOldProtect);
	CloseHandle(hProcess);
	m_vecInt3Info.push_back(oldInfo);
}
//bh->硬件断点
BOOL CUserCommand::UserCommandBH(LPDEBUG_EVENT pDbgEvent,DWORD dAddress)
{
	if (m_vecHardExec.size() > 4)
	{
		return FALSE;
	}

	HANDLE hThread = OpenThread(PROCESS_ALL_ACCESS, 0, pDbgEvent->dwThreadId);
	CONTEXT ct = { CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(hThread, &ct);
	DBG_REG7* pDr7 = (DBG_REG7*)&ct.Dr7;
	if (ct.Dr0 == 0)
	{
		ct.Dr0 = dAddress;
		pDr7->RW0 = 0;
		pDr7->LEN0 = 0;
		pDr7->L0 = 1;
	}
	else if (ct.Dr1 == 0)
	{
		ct.Dr1 = dAddress;
		pDr7->RW1 = 0;
		pDr7->LEN1 = 0;
		pDr7->L1 = 1;
	}
	else if (ct.Dr2 == 0)
	{
		ct.Dr2 = dAddress;
		pDr7->RW2 = 0;
		pDr7->LEN2 = 0;
		pDr7->L2 = 1;
	}
	else if (ct.Dr3 == 0)
	{
		ct.Dr3 = dAddress;
		pDr7->RW3 = 0;
		pDr7->LEN3 = 0;
		pDr7->L3 = 1;
	}
	else
	{
		return FALSE;
	}
	m_vecHardExec.push_back(dAddress);
	SetThreadContext(hThread, &ct);
	CloseHandle(hThread);
	return TRUE;
}
//bm->内存断点
void CUserCommand::UserCommandBM(LPDEBUG_EVENT pDbgEvent, DWORD dAddress)
{
	//修改内存分页属性，改为没有任何访问权限
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pDbgEvent->dwProcessId);
	VirtualProtectEx(hProcess, (LPVOID)dAddress, sizeof(DWORD), PAGE_NOACCESS, &m_dwOldProtect);
}

//c->条件断点
void CUserCommand::UserCommandC(LPDEBUG_EVENT pDbgEvent)
{
	m_dwConditionNum[0] = m_cCondition[4];
	m_dwConditionNum[1] = '\0';
	m_nNum = atoi(m_dwConditionNum);
	m_bIsCondition = TRUE;

	// 设置单步
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, NULL, pDbgEvent->dwThreadId);
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;			// 指定要获取哪写寄存器的信息，很重要
	GetThreadContext(hThread, &ct);
	PEFLAGS pElg = (PEFLAGS)&ct.EFlags;
	pElg->TF = 1;
	SetThreadContext(hThread, &ct);		
	CloseHandle(hThread);
}

//反汇编函数
void CUserCommand::DisasmAtAddr(DWORD dwAddr, DWORD dwCount /*= 10*/)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, m_stcProcInfo.dwProcessId);

	WCHAR szOpCode[50] = {};
	WCHAR szAsm[50] = {};
	WCHAR szComment[50] = {};
	// 一次反汇编1条,默认反汇编10条，可以自定义反汇编指令数目，也可以由输入命令指定
	printf("%-10s %-20s    %-32s%s\n", "addr", "opcode", "asm", "comment");
	UINT uLen;
	for (DWORD i = 0; i < dwCount; i++) {
		// 反汇编
		uLen = DBG_Disasm(hProcess, (LPVOID)dwAddr, szOpCode, szAsm, szComment);
		wprintf_s(L"0x%08x   %-20s%-32s%s\n", dwAddr, szOpCode, szAsm, szComment);
		dwAddr += uLen;
	}
	CloseHandle(hProcess);
}

UINT CUserCommand::DBG_Disasm(HANDLE hProcess, LPVOID lpAddress, PWCHAR pOPCode, PWCHAR pASM, PWCHAR pComment)
{
	// 1. 将调试程序的内存复制到本地
	DWORD dwOldProc = 0;
	DWORD dwRetSize = 0;
	BYTE lpRemote_Buf[32] = {};
	VirtualProtectEx(hProcess, (LPVOID)lpAddress, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProc);
	ReadProcessMemory(hProcess, lpAddress, lpRemote_Buf, 32, &dwRetSize);
	VirtualProtectEx(hProcess, (LPVOID)lpAddress, sizeof(DWORD), dwOldProc, &dwOldProc);
	// 2. 初始化反汇编引擎
	DISASM objDiasm;
	objDiasm.EIP = (UIntPtr)lpRemote_Buf;		// 起始地址
	objDiasm.VirtualAddr = (UINT64)lpAddress;   // 虚拟内存地址（反汇编引擎用于计算地址）
	objDiasm.Archi = 0;							// AI-X86
	objDiasm.Options = 0x000;					// MASM
	// 3. 反汇编代码
	UINT unLen = Disasm(&objDiasm);
	if (-1 == unLen) return unLen;
	// 4. 将机器码转码为字符串
	LPWSTR lpOPCode = pOPCode;
	PBYTE  lpBuffer = lpRemote_Buf;
	for (UINT i = 0; i < unLen; i++) {
		StringCbPrintf(lpOPCode++, 50, L"%X", *lpBuffer & 0xF0);
		StringCbPrintf(lpOPCode++, 50, L"%X", *lpBuffer & 0x0F);
		lpBuffer++;
	}
	// 5. 保存反汇编出的指令
	WCHAR szASM[50] = { 0 };
	MultiByteToWideChar(CP_ACP, 0, objDiasm.CompleteInstr, -1, szASM, _countof(szASM));
	StringCchCopy(pASM, 50, szASM);
	return unLen;
}
//模块
void CUserCommand::UserCommandM(LPDEBUG_EVENT pDbgEvent)
{
	m_vecModuleInfo.clear();
	HANDLE        hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
	// 1. 创建一个模块相关的快照句柄
	hModuleSnap = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE,		// 指定快照的类型
		pDbgEvent->dwProcessId);		// 指定进程
	if (hModuleSnap == INVALID_HANDLE_VALUE)
		return;
	// 2. 通过模块快照句柄获取第一个模块信息
	if (!Module32First(hModuleSnap, &me32)) {
		CloseHandle(hModuleSnap);
		return;
	}
	char ch[512] = {};
	printf("加载基址\t名称\n");
	do
	{
		WCHAR_TO_CHAR(me32.szExePath, ch);
		printf("%08x\t", (UINT)me32.modBaseAddr);
		printf("%s\n", ch);
		m_vecModuleInfo.push_back(me32);
	} while (Module32Next(hModuleSnap, &me32));
	CloseHandle(hModuleSnap);
}
//栈
void CUserCommand::UserCommandK(LPDEBUG_EVENT pDbgEvent)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, NULL, pDbgEvent->dwThreadId);
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &ct);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pDbgEvent->dwProcessId);
	BYTE buff[512];
	DWORD dwRead = 0;
	ReadProcessMemory(hProcess, (LPCVOID)ct.Esp, buff, 512, &dwRead);
	for (int i = 0; i < 10; i++)
	{
		printf("%08X\n", ((DWORD*)buff)[i]);
	}
	CloseHandle(hThread);
	CloseHandle(hProcess);
}
//文件偏移
DWORD CUserCommand::RVAToOffset(IMAGE_DOS_HEADER* pDos, DWORD dwRva)
{
	IMAGE_SECTION_HEADER* pScnHdr;

	IMAGE_NT_HEADERS* pNtHdr =
		(IMAGE_NT_HEADERS*)(pDos->e_lfanew + (DWORD)pDos);

	pScnHdr = IMAGE_FIRST_SECTION(pNtHdr);
	DWORD dwNumberOfScn = pNtHdr->FileHeader.NumberOfSections;

	// 1. 遍历所有区段找到所在区段
	for (DWORD i = 0; i < dwNumberOfScn; ++i)
	{
		DWORD dwEndOfSection = pScnHdr[i].VirtualAddress + pScnHdr[i].SizeOfRawData;
		// 判断这个RVA是否在一个区段的范围内
		if (dwRva >= pScnHdr[i].VirtualAddress
			&& dwRva < dwEndOfSection)
		{
			// 2. 计算该RVA在区段内的偏移:rva 减去首地址
			DWORD dwOffset = dwRva - pScnHdr[i].VirtualAddress;
			// 3. 将区段内偏移加上区段的文件开始偏移
			return dwOffset + pScnHdr[i].PointerToRawData;
		}
	}
	return -1;
}
//读取文件
void CUserCommand::WirteUpdataFileValue(CString strPath, char* szContext)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = CreateFile(strPath,	/* 文件路径 */
		GENERIC_READ | GENERIC_WRITE,	/*访问方式*/
		0,								/*文件共享方式*/
		NULL,							/*安全描述符*/
		OPEN_EXISTING,					/*文件创建标志*/
		FILE_ATTRIBUTE_NORMAL,			/*文件标志和属性*/
		NULL							/*模板句柄,默认填NULL*/
		);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("打开文件失败,文件不存在\n");
		return;
	}
	int size = strlen(szContext);
	szContext[size] = '\r';
	szContext[size + 1] = '\n';
	szContext[size + 2] = '\0';
	// 设置文件读写位置
	SetFilePointer(hFile, 0, 0, FILE_END);
	// 写入文件.
	DWORD dwWrite = 0;
	WriteFile(hFile,
		szContext,					/*要写入的缓冲区的首地址*/
		strlen(szContext),			/*要写入到文件中的字节数*/
		&dwWrite,					/*实际写入的字节数*/
		NULL);

	CloseHandle(hFile);

}
//导出表
void CUserCommand::GetExportTableInfo()
{
	for (int i = 1; i < (int)m_vecModuleInfo.size(); ++i)
	{
		HANDLE hFile = INVALID_HANDLE_VALUE;
		hFile = CreateFile(m_vecModuleInfo[i].szExePath,
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			printf("文件不存在\n");
			return;
		}
		DWORD dwFileSize = 0;
		dwFileSize = GetFileSize(hFile, NULL);

		// 2. 申请内存空间
		BYTE* pBuf = new BYTE[dwFileSize];

		// 3. 将文件内容读取到内存中
		DWORD dwRead = 0;
		ReadFile(hFile, pBuf, dwFileSize, &dwRead, NULL);
		//1.找到Dos头
		IMAGE_DOS_HEADER* pDosHdr;// DOS头
		pDosHdr = (IMAGE_DOS_HEADER*)pBuf;

		// 2. 找到Nt头
		IMAGE_NT_HEADERS* pNtHdr = NULL;
		pNtHdr = (IMAGE_NT_HEADERS*)(pDosHdr->e_lfanew + (DWORD)pDosHdr);

		// 3. 找到扩展头
		IMAGE_OPTIONAL_HEADER* pOptHdr = NULL;
		pOptHdr = &pNtHdr->OptionalHeader;

		// 4. 找到数据目录表
		IMAGE_DATA_DIRECTORY* pDataDir = NULL;
		pDataDir = pOptHdr->DataDirectory;
		// 5. 找到导出表
		DWORD dwExpRva = pDataDir[0].VirtualAddress;
		// 5.1 得到RVA的文件偏移
		DWORD dwExpOfs = RVAToOffset(pDosHdr, dwExpRva);
		IMAGE_EXPORT_DIRECTORY* pExpTab = NULL;
		pExpTab = (IMAGE_EXPORT_DIRECTORY*)(dwExpOfs + (DWORD)pDosHdr);

		// 解析三张表
		DWORD dwExpAddrTabOfs = RVAToOffset(pDosHdr, pExpTab->AddressOfFunctions);
		DWORD dwExpNameTabOfs = RVAToOffset(pDosHdr, pExpTab->AddressOfNames);
		DWORD dwExpOrdTabOfs = RVAToOffset(pDosHdr, pExpTab->AddressOfNameOrdinals);
		// 三张中的地址表,名称都是一个DWORD类型数组
		DWORD* pExpAddr = (DWORD*)(dwExpAddrTabOfs + (DWORD)pDosHdr);
		DWORD* pExpName = (DWORD*)(dwExpNameTabOfs + (DWORD)pDosHdr);
		WORD* pExpOrd = (WORD*)(dwExpOrdTabOfs + (DWORD)pDosHdr);

		CString strFormat;
		CString strSerialNumber;
		CString strRVA;
		CString strOffset;
		CString strFunName;

		for (DWORD i = 0; i < pExpTab->NumberOfFunctions; ++i)
		{
			DWORD j = 0;
			for (; j < pExpTab->NumberOfNames; ++j)
			{
				if (pExpOrd[j] == i)
				{
					//序号	RVA		偏移		函数名
					strFormat.Format(L"%04X", ((DWORD)i + pExpTab->Base));

					strSerialNumber.Append(L"序号: ");
					strSerialNumber.Append(strFormat);

					strFormat.Format(L"%08X", pExpAddr[i]);
					strRVA.Append(L"    RVA: ");
					strRVA.Append(strFormat);

					DWORD dFileOffset = RVAToOffset(pDosHdr, pExpAddr[i]);
					strFormat.Format(L"%08X", dFileOffset);
					strOffset.Append(L"    偏移: ");
					strOffset.Append(strFormat);

					DWORD dwNameRva = pExpName[i];
					DWORD dwNameOfs = RVAToOffset(pDosHdr, dwNameRva);
					WCHAR* pFunctionName = nullptr;
					pFunctionName = (WCHAR*)(dwNameOfs + (DWORD)pDosHdr);
					strFormat.Format(L"%S", pFunctionName);
					strFunName.Append(L"    函数名: ");
					strFunName.Append(strFormat);

					strFormat = "";
					strFormat = strSerialNumber + strRVA + strOffset + strFunName;
					char ch[512] = {};
					WCHAR_TO_CHAR(strFormat, ch);
					WirteUpdataFileValue(L"tableExport.txt", ch);
					strFormat = "";
					strSerialNumber = "";
					strRVA = "";
					strOffset = "";
					strFunName = "";
				}
			}
		}
	}
}
//导入表
void CUserCommand::GetImportTableInfo()
{
	if (m_vecModuleInfo.size() == 0)
	{
		return;
	}

	//1.打开文件,将文件读取到内存.
	char path[MAX_PATH];
	WideCharToMultiByte(CP_ACP, 0,m_vecModuleInfo[0].szExePath, -1, path, MAX_PATH, NULL, NULL);
	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = CreateFileA(path,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("文件不存在\n");
		return;
	}

	DWORD dwFileSize = 0;
	dwFileSize = GetFileSize(hFile, NULL);
	// 2. 申请内存空间
	BYTE* pBuf = new BYTE[dwFileSize];
	// 3. 将文件内容读取到内存中
	DWORD dwRead = 0;
	ReadFile(hFile,
		pBuf,
		dwFileSize,
		&dwRead,
		NULL);
	IMAGE_DOS_HEADER* pDosHdr;// DOS头
	pDosHdr = (IMAGE_DOS_HEADER*)pBuf;

	// 2. 找到Nt头
	IMAGE_NT_HEADERS* pNtHdr = NULL;
	pNtHdr = (IMAGE_NT_HEADERS*)(pDosHdr->e_lfanew + (DWORD)pDosHdr);

	// 3. 找到扩展头
	IMAGE_OPTIONAL_HEADER* pOptHdr = NULL;
	pOptHdr = &pNtHdr->OptionalHeader;

	// 4. 找到数据目录表
	IMAGE_DATA_DIRECTORY* pDataDir = NULL;
	pDataDir = pOptHdr->DataDirectory;

	// 5. 得到导入表的RVA
	DWORD dwImpRva = pDataDir[1].VirtualAddress;

	IMAGE_IMPORT_DESCRIPTOR* pImpArray;

	pImpArray = (IMAGE_IMPORT_DESCRIPTOR*)(RVAToOffset(pDosHdr, dwImpRva) + (DWORD)pDosHdr);
	while (pImpArray->Name != 0)
	{
		// 导入的Dll的名字(Rva)
		DWORD dwNameOfs = RVAToOffset(pDosHdr, pImpArray->Name);
		char* pDllName = (char*)(dwNameOfs + (DWORD)pDosHdr);

		// 解析,在这个dll中,一共导入哪些函数
		//pImpArray->OriginalFirstThunk;
		// INT(导入名表)
		// 记录着一个从一个dll中导入了哪些函数
		// 这些函数要么是以名称导入,要么是以序号导入的
		// 到记录在一个数组中. 这个数组是IMAGE_THUNK_DATA
		// 类型的结构体数组.
		// FirstThunk保存着数组的RVA
		DWORD IATOfs = RVAToOffset(pDosHdr, pImpArray->FirstThunk);
		IMAGE_THUNK_DATA* pIat = NULL;
		pIat = (IMAGE_THUNK_DATA*)(IATOfs + (DWORD)pDosHdr);

		CString str;
		CString strDllName;
		CString strXuhao;
		CString strFunName;
		while (pIat->u1.Function != 0)
		{
			// 判断是否是以序号导入
			if (IMAGE_SNAP_BY_ORDINAL32(pIat->u1.Function))
			{
				// 以序号方式导入
				// 结构体保存的值低16位就是一个导入的序号
				//printf("\t导入序号[%d]\n", pInt->u1.Ordinal & 0xFFFF);
			}
			else
			{
				// 是以名称导入的]
				// 当函数是以名称导入的时候, 
				// pInt->u1.Function 保存的是一个
				// rva , 这个RVA指向一个保存函数名称
				// 信息的结构体
				IMAGE_IMPORT_BY_NAME* pImpName;
				DWORD dwImpNameOfs = RVAToOffset(pDosHdr, pIat->u1.Function);
				pImpName = (IMAGE_IMPORT_BY_NAME*)
					(dwImpNameOfs + (DWORD)pDosHdr);

				str.Append(L"DLL名称:");
				strDllName.Format(L"%S", pDllName);
				str.Append(strDllName);
				str.Append(L"  ");
				strXuhao.Format(L"%d", pImpName->Hint);
				str.Append(L"序号:");
				str.Append(strXuhao);
				str.Append(L"  ");
				str.Append(L"函数名:");
				strFunName.Format(L"%S", pImpName->Name);
				str.Append(strFunName);

				char ch[512] = {};
				WCHAR_TO_CHAR(str, ch);
				WirteUpdataFileValue(L"tableImport.txt", ch);
				str = "";
				strDllName = "";
				strXuhao = "";
				strFunName = "";
			}
			++pIat;
		}
		++pImpArray;
	}
}