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

//����Ĵ�����Ϣ
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
// 1.����Ĵ�����Ϣ
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, pDbgEvent->dwThreadId);
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// all register
	GetThreadContext(hThread, &ct);
	CloseHandle(hThread);
	ShowRegisterInfo(ct);
	// 2.����������Ϣ
	// ��!!!�쳣��ַ!!!��ʼ�����5����Ϣ����Ҫ��eip��ʼ
	DisasmAtAddr((DWORD)pDbgEvent->u.Exception.ExceptionRecord.ExceptionAddress, 5);
	// 3.�ȴ��û�����
	// �ȴ��û�����
	CHAR szCommand[MAX_INPUT] = {};
	while (1) {
		cout << "�������������:";
		gets_s(szCommand, MAX_INPUT);
		switch (szCommand[0]) {
		case 'u':							// ����� ���������û�����
			UserCommandU(pDbgEvent);
			break;
		case 't':							// ����F7
			UserCommandT(pDbgEvent);
			return DBG_CONTINUE;
		case 'g':							// go
			UserCommandT(pDbgEvent);
			m_bIsSingle = FALSE;
			m_bIsUserBrk = FALSE;
			return DBG_CONTINUE;
		case 'b':
			/*
			bp ����ϵ�
			bm �ڴ�ϵ�
			bh Ӳ���ϵ�
			bl ��ѯ�ϵ��б�
			*/
			UserCommandB(pDbgEvent,szCommand);
			break;
		case 'k':							// �鿴��������ջ֡
			UserCommandK(pDbgEvent);
			break;
		case 'm':							// �鿴ģ����Ϣ
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
			printf("����������:");
			scanf_s("%s", m_cCondition, _countof(m_cCondition));
			UserCommandC(pDbgEvent);
			scanf_s("%*[^\n]");
			scanf_s("%*c");
			break;
		default:
			printf("��������ȷ��ָ�\n");
			break;
		}
	}
	return DBG_CONTINUE;
}

//�û���������
void CUserCommand::UserCommandT(LPDEBUG_EVENT pDbgEvent)
{
	// ���õ���
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, NULL, pDbgEvent->dwThreadId);
	//��ȡ�̻߳�����
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;		// ָ��Ҫ��ȡ��д�Ĵ�������Ϣ������Ҫ
	GetThreadContext(hThread, &ct);
	PEFLAGS pElg = (PEFLAGS)&ct.EFlags;
	PDBG_REG6 pDr6 = (PDBG_REG6)&ct.Dr6;
	pElg->TF = 1;
	SetThreadContext(hThread, &ct);		//�����̻߳�����
	CloseHandle(hThread);
	m_bIsUserBrk = TRUE;
	m_bIsSingle = TRUE;
}

//b->���ֶϵ�����
void CUserCommand::UserCommandB(LPDEBUG_EVENT pDbgEvent,CHAR* pCommand)
{
	switch (pCommand[1])
	{
	case 'p':
	{
		printf("�������ַ:");
		scanf_s("%x", &m_dwBPAddress);
		UserCommandBP(pDbgEvent, m_dwBPAddress);
		scanf_s("%*[^\n]");
		scanf_s("%*c");
	}
	break;
	case'h':
	{
		printf("�������ַ:");
		scanf_s("%x", &m_dwBHAddress);
		if (!UserCommandBH(pDbgEvent, m_dwBHAddress))
		{
			printf("û�п��üĴ���\n");
		}
		scanf_s("%*[^\n]");
		scanf_s("%*c");
	}
	break;
	case'm':
	{
		printf("�������ַ:");
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

//u->�����
void CUserCommand::UserCommandU(LPDEBUG_EVENT pDbgEvt)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, NULL, pDbgEvt->dwThreadId);
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;// ָ��Ҫ��ȡ��д�Ĵ�������Ϣ������Ҫ
	GetThreadContext(hThread, &ct);
	DisasmAtAddr(ct.Eip, 10);
	SetThreadContext(hThread, &ct);
	CloseHandle(hThread);
}

//bp->��������ϵ�
void CUserCommand::UserCommandBP(LPDEBUG_EVENT pDbgEvent,DWORD dAddress)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pDbgEvent->dwProcessId);
	DWORD dwSize = 0;
	BYTE oldByte;
	DWORD dwOldProtect = 0;
	//�޸��ڴ��ҳ���ԣ���Ϊ�ɶ���д
	if (!VirtualProtectEx(hProcess, (LPVOID)dAddress, sizeof(DWORD), PAGE_READWRITE, &dwOldProtect)){
		CloseHandle(hProcess);
		return;
	}
	ReadProcessMemory(hProcess, (LPCVOID)dAddress, &oldByte, 1, &dwSize);
	//�ṹ�屣������ϵ�ĵ�ַ��ָ��
	BREAK_POINT oldInfo;
	oldInfo.dwAddress = dAddress;
	oldInfo.bContent = oldByte;
	BYTE cc = '\xcc';
	WriteProcessMemory(hProcess, (LPVOID)dAddress, &cc, 1, &dwSize);
	//�޸�Ϊԭ�����ڴ��ҳ����
	VirtualProtectEx(hProcess, (LPVOID)dAddress, sizeof(DWORD), dwOldProtect, &dwOldProtect);
	CloseHandle(hProcess);
	m_vecInt3Info.push_back(oldInfo);
}
//bh->Ӳ���ϵ�
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
//bm->�ڴ�ϵ�
void CUserCommand::UserCommandBM(LPDEBUG_EVENT pDbgEvent, DWORD dAddress)
{
	//�޸��ڴ��ҳ���ԣ���Ϊû���κη���Ȩ��
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pDbgEvent->dwProcessId);
	VirtualProtectEx(hProcess, (LPVOID)dAddress, sizeof(DWORD), PAGE_NOACCESS, &m_dwOldProtect);
}

//c->�����ϵ�
void CUserCommand::UserCommandC(LPDEBUG_EVENT pDbgEvent)
{
	m_dwConditionNum[0] = m_cCondition[4];
	m_dwConditionNum[1] = '\0';
	m_nNum = atoi(m_dwConditionNum);
	m_bIsCondition = TRUE;

	// ���õ���
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, NULL, pDbgEvent->dwThreadId);
	CONTEXT ct = {};
	ct.ContextFlags = CONTEXT_ALL;			// ָ��Ҫ��ȡ��д�Ĵ�������Ϣ������Ҫ
	GetThreadContext(hThread, &ct);
	PEFLAGS pElg = (PEFLAGS)&ct.EFlags;
	pElg->TF = 1;
	SetThreadContext(hThread, &ct);		
	CloseHandle(hThread);
}

//����ຯ��
void CUserCommand::DisasmAtAddr(DWORD dwAddr, DWORD dwCount /*= 10*/)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, m_stcProcInfo.dwProcessId);

	WCHAR szOpCode[50] = {};
	WCHAR szAsm[50] = {};
	WCHAR szComment[50] = {};
	// һ�η����1��,Ĭ�Ϸ����10���������Զ��巴���ָ����Ŀ��Ҳ��������������ָ��
	printf("%-10s %-20s    %-32s%s\n", "addr", "opcode", "asm", "comment");
	UINT uLen;
	for (DWORD i = 0; i < dwCount; i++) {
		// �����
		uLen = DBG_Disasm(hProcess, (LPVOID)dwAddr, szOpCode, szAsm, szComment);
		wprintf_s(L"0x%08x   %-20s%-32s%s\n", dwAddr, szOpCode, szAsm, szComment);
		dwAddr += uLen;
	}
	CloseHandle(hProcess);
}

UINT CUserCommand::DBG_Disasm(HANDLE hProcess, LPVOID lpAddress, PWCHAR pOPCode, PWCHAR pASM, PWCHAR pComment)
{
	// 1. �����Գ�����ڴ渴�Ƶ�����
	DWORD dwOldProc = 0;
	DWORD dwRetSize = 0;
	BYTE lpRemote_Buf[32] = {};
	VirtualProtectEx(hProcess, (LPVOID)lpAddress, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProc);
	ReadProcessMemory(hProcess, lpAddress, lpRemote_Buf, 32, &dwRetSize);
	VirtualProtectEx(hProcess, (LPVOID)lpAddress, sizeof(DWORD), dwOldProc, &dwOldProc);
	// 2. ��ʼ�����������
	DISASM objDiasm;
	objDiasm.EIP = (UIntPtr)lpRemote_Buf;		// ��ʼ��ַ
	objDiasm.VirtualAddr = (UINT64)lpAddress;   // �����ڴ��ַ��������������ڼ����ַ��
	objDiasm.Archi = 0;							// AI-X86
	objDiasm.Options = 0x000;					// MASM
	// 3. ��������
	UINT unLen = Disasm(&objDiasm);
	if (-1 == unLen) return unLen;
	// 4. ��������ת��Ϊ�ַ���
	LPWSTR lpOPCode = pOPCode;
	PBYTE  lpBuffer = lpRemote_Buf;
	for (UINT i = 0; i < unLen; i++) {
		StringCbPrintf(lpOPCode++, 50, L"%X", *lpBuffer & 0xF0);
		StringCbPrintf(lpOPCode++, 50, L"%X", *lpBuffer & 0x0F);
		lpBuffer++;
	}
	// 5. ���淴������ָ��
	WCHAR szASM[50] = { 0 };
	MultiByteToWideChar(CP_ACP, 0, objDiasm.CompleteInstr, -1, szASM, _countof(szASM));
	StringCchCopy(pASM, 50, szASM);
	return unLen;
}
//ģ��
void CUserCommand::UserCommandM(LPDEBUG_EVENT pDbgEvent)
{
	m_vecModuleInfo.clear();
	HANDLE        hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
	// 1. ����һ��ģ����صĿ��վ��
	hModuleSnap = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE,		// ָ�����յ�����
		pDbgEvent->dwProcessId);		// ָ������
	if (hModuleSnap == INVALID_HANDLE_VALUE)
		return;
	// 2. ͨ��ģ����վ����ȡ��һ��ģ����Ϣ
	if (!Module32First(hModuleSnap, &me32)) {
		CloseHandle(hModuleSnap);
		return;
	}
	char ch[512] = {};
	printf("���ػ�ַ\t����\n");
	do
	{
		WCHAR_TO_CHAR(me32.szExePath, ch);
		printf("%08x\t", (UINT)me32.modBaseAddr);
		printf("%s\n", ch);
		m_vecModuleInfo.push_back(me32);
	} while (Module32Next(hModuleSnap, &me32));
	CloseHandle(hModuleSnap);
}
//ջ
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
//�ļ�ƫ��
DWORD CUserCommand::RVAToOffset(IMAGE_DOS_HEADER* pDos, DWORD dwRva)
{
	IMAGE_SECTION_HEADER* pScnHdr;

	IMAGE_NT_HEADERS* pNtHdr =
		(IMAGE_NT_HEADERS*)(pDos->e_lfanew + (DWORD)pDos);

	pScnHdr = IMAGE_FIRST_SECTION(pNtHdr);
	DWORD dwNumberOfScn = pNtHdr->FileHeader.NumberOfSections;

	// 1. �������������ҵ���������
	for (DWORD i = 0; i < dwNumberOfScn; ++i)
	{
		DWORD dwEndOfSection = pScnHdr[i].VirtualAddress + pScnHdr[i].SizeOfRawData;
		// �ж����RVA�Ƿ���һ�����εķ�Χ��
		if (dwRva >= pScnHdr[i].VirtualAddress
			&& dwRva < dwEndOfSection)
		{
			// 2. �����RVA�������ڵ�ƫ��:rva ��ȥ�׵�ַ
			DWORD dwOffset = dwRva - pScnHdr[i].VirtualAddress;
			// 3. ��������ƫ�Ƽ������ε��ļ���ʼƫ��
			return dwOffset + pScnHdr[i].PointerToRawData;
		}
	}
	return -1;
}
//��ȡ�ļ�
void CUserCommand::WirteUpdataFileValue(CString strPath, char* szContext)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	hFile = CreateFile(strPath,	/* �ļ�·�� */
		GENERIC_READ | GENERIC_WRITE,	/*���ʷ�ʽ*/
		0,								/*�ļ�����ʽ*/
		NULL,							/*��ȫ������*/
		OPEN_EXISTING,					/*�ļ�������־*/
		FILE_ATTRIBUTE_NORMAL,			/*�ļ���־������*/
		NULL							/*ģ����,Ĭ����NULL*/
		);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("���ļ�ʧ��,�ļ�������\n");
		return;
	}
	int size = strlen(szContext);
	szContext[size] = '\r';
	szContext[size + 1] = '\n';
	szContext[size + 2] = '\0';
	// �����ļ���дλ��
	SetFilePointer(hFile, 0, 0, FILE_END);
	// д���ļ�.
	DWORD dwWrite = 0;
	WriteFile(hFile,
		szContext,					/*Ҫд��Ļ��������׵�ַ*/
		strlen(szContext),			/*Ҫд�뵽�ļ��е��ֽ���*/
		&dwWrite,					/*ʵ��д����ֽ���*/
		NULL);

	CloseHandle(hFile);

}
//������
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
			printf("�ļ�������\n");
			return;
		}
		DWORD dwFileSize = 0;
		dwFileSize = GetFileSize(hFile, NULL);

		// 2. �����ڴ�ռ�
		BYTE* pBuf = new BYTE[dwFileSize];

		// 3. ���ļ����ݶ�ȡ���ڴ���
		DWORD dwRead = 0;
		ReadFile(hFile, pBuf, dwFileSize, &dwRead, NULL);
		//1.�ҵ�Dosͷ
		IMAGE_DOS_HEADER* pDosHdr;// DOSͷ
		pDosHdr = (IMAGE_DOS_HEADER*)pBuf;

		// 2. �ҵ�Ntͷ
		IMAGE_NT_HEADERS* pNtHdr = NULL;
		pNtHdr = (IMAGE_NT_HEADERS*)(pDosHdr->e_lfanew + (DWORD)pDosHdr);

		// 3. �ҵ���չͷ
		IMAGE_OPTIONAL_HEADER* pOptHdr = NULL;
		pOptHdr = &pNtHdr->OptionalHeader;

		// 4. �ҵ�����Ŀ¼��
		IMAGE_DATA_DIRECTORY* pDataDir = NULL;
		pDataDir = pOptHdr->DataDirectory;
		// 5. �ҵ�������
		DWORD dwExpRva = pDataDir[0].VirtualAddress;
		// 5.1 �õ�RVA���ļ�ƫ��
		DWORD dwExpOfs = RVAToOffset(pDosHdr, dwExpRva);
		IMAGE_EXPORT_DIRECTORY* pExpTab = NULL;
		pExpTab = (IMAGE_EXPORT_DIRECTORY*)(dwExpOfs + (DWORD)pDosHdr);

		// �������ű�
		DWORD dwExpAddrTabOfs = RVAToOffset(pDosHdr, pExpTab->AddressOfFunctions);
		DWORD dwExpNameTabOfs = RVAToOffset(pDosHdr, pExpTab->AddressOfNames);
		DWORD dwExpOrdTabOfs = RVAToOffset(pDosHdr, pExpTab->AddressOfNameOrdinals);
		// �����еĵ�ַ��,���ƶ���һ��DWORD��������
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
					//���	RVA		ƫ��		������
					strFormat.Format(L"%04X", ((DWORD)i + pExpTab->Base));

					strSerialNumber.Append(L"���: ");
					strSerialNumber.Append(strFormat);

					strFormat.Format(L"%08X", pExpAddr[i]);
					strRVA.Append(L"    RVA: ");
					strRVA.Append(strFormat);

					DWORD dFileOffset = RVAToOffset(pDosHdr, pExpAddr[i]);
					strFormat.Format(L"%08X", dFileOffset);
					strOffset.Append(L"    ƫ��: ");
					strOffset.Append(strFormat);

					DWORD dwNameRva = pExpName[i];
					DWORD dwNameOfs = RVAToOffset(pDosHdr, dwNameRva);
					WCHAR* pFunctionName = nullptr;
					pFunctionName = (WCHAR*)(dwNameOfs + (DWORD)pDosHdr);
					strFormat.Format(L"%S", pFunctionName);
					strFunName.Append(L"    ������: ");
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
//�����
void CUserCommand::GetImportTableInfo()
{
	if (m_vecModuleInfo.size() == 0)
	{
		return;
	}

	//1.���ļ�,���ļ���ȡ���ڴ�.
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
		printf("�ļ�������\n");
		return;
	}

	DWORD dwFileSize = 0;
	dwFileSize = GetFileSize(hFile, NULL);
	// 2. �����ڴ�ռ�
	BYTE* pBuf = new BYTE[dwFileSize];
	// 3. ���ļ����ݶ�ȡ���ڴ���
	DWORD dwRead = 0;
	ReadFile(hFile,
		pBuf,
		dwFileSize,
		&dwRead,
		NULL);
	IMAGE_DOS_HEADER* pDosHdr;// DOSͷ
	pDosHdr = (IMAGE_DOS_HEADER*)pBuf;

	// 2. �ҵ�Ntͷ
	IMAGE_NT_HEADERS* pNtHdr = NULL;
	pNtHdr = (IMAGE_NT_HEADERS*)(pDosHdr->e_lfanew + (DWORD)pDosHdr);

	// 3. �ҵ���չͷ
	IMAGE_OPTIONAL_HEADER* pOptHdr = NULL;
	pOptHdr = &pNtHdr->OptionalHeader;

	// 4. �ҵ�����Ŀ¼��
	IMAGE_DATA_DIRECTORY* pDataDir = NULL;
	pDataDir = pOptHdr->DataDirectory;

	// 5. �õ�������RVA
	DWORD dwImpRva = pDataDir[1].VirtualAddress;

	IMAGE_IMPORT_DESCRIPTOR* pImpArray;

	pImpArray = (IMAGE_IMPORT_DESCRIPTOR*)(RVAToOffset(pDosHdr, dwImpRva) + (DWORD)pDosHdr);
	while (pImpArray->Name != 0)
	{
		// �����Dll������(Rva)
		DWORD dwNameOfs = RVAToOffset(pDosHdr, pImpArray->Name);
		char* pDllName = (char*)(dwNameOfs + (DWORD)pDosHdr);

		// ����,�����dll��,һ��������Щ����
		//pImpArray->OriginalFirstThunk;
		// INT(��������)
		// ��¼��һ����һ��dll�е�������Щ����
		// ��Щ����Ҫô�������Ƶ���,Ҫô������ŵ����
		// ����¼��һ��������. ���������IMAGE_THUNK_DATA
		// ���͵Ľṹ������.
		// FirstThunk�����������RVA
		DWORD IATOfs = RVAToOffset(pDosHdr, pImpArray->FirstThunk);
		IMAGE_THUNK_DATA* pIat = NULL;
		pIat = (IMAGE_THUNK_DATA*)(IATOfs + (DWORD)pDosHdr);

		CString str;
		CString strDllName;
		CString strXuhao;
		CString strFunName;
		while (pIat->u1.Function != 0)
		{
			// �ж��Ƿ�������ŵ���
			if (IMAGE_SNAP_BY_ORDINAL32(pIat->u1.Function))
			{
				// ����ŷ�ʽ����
				// �ṹ�屣���ֵ��16λ����һ����������
				//printf("\t�������[%d]\n", pInt->u1.Ordinal & 0xFFFF);
			}
			else
			{
				// �������Ƶ����]
				// �������������Ƶ����ʱ��, 
				// pInt->u1.Function �������һ��
				// rva , ���RVAָ��һ�����溯������
				// ��Ϣ�Ľṹ��
				IMAGE_IMPORT_BY_NAME* pImpName;
				DWORD dwImpNameOfs = RVAToOffset(pDosHdr, pIat->u1.Function);
				pImpName = (IMAGE_IMPORT_BY_NAME*)
					(dwImpNameOfs + (DWORD)pDosHdr);

				str.Append(L"DLL����:");
				strDllName.Format(L"%S", pDllName);
				str.Append(strDllName);
				str.Append(L"  ");
				strXuhao.Format(L"%d", pImpName->Hint);
				str.Append(L"���:");
				str.Append(strXuhao);
				str.Append(L"  ");
				str.Append(L"������:");
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