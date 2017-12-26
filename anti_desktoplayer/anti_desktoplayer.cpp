// anti_desktoplayer.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <atlstr.h>
#include <Windows.h>
#include <TlHelp32.h>

LPCTSTR		g_pMutexName = TEXT("KyUffThOkYwRRtgPP");
HANDLE		g_hMutex = NULL;
CString		g_DefaultBrowser = "iexplore.exe";
CString g_cstrSystemDir = "c:\\windows\\wystem32";
CString g_cstrWindowsDir = "";

char * DelFileSet[] = {
	"C:\\Program Files\\Microsoft\\DesktopLayer.exe",
	"C:\\Program Files\\Common Files\\Microsoft\\DesktopLayer.exe",
	"C:\\Documents and Settings\\Administrator\\Microsoft\\DesktopLayer.exe",
	"C:\\Documents and Settings\\Administrator\\Application Data\\Microsoft\\DesktopLayer.exe",
	"C:\\WINDOWS\\system32\\DesktopLayer.exe",
	"C:\\WINDOWS\\DesktopLayer.exe",
	"C:\\DOCUME~1\\ADMINI~1\\LOCALS~1\\Temp\\DesktopLayer.exe"
};

BOOL EunmRepair(CString strPath);

/*
*遍历系统所有进程，查找名称为"DesktopLayer "和"iexplore "的进程:
*对于"DesktopLayer "进程:直接结束；
*对于"iexplore "进程:直接结束进程，同时删除iexplore目录下的
*dmlconf.dat文件。
*/
BOOL TerminateMaliciousProcess();


BOOL DeleteMaliciousFile();
BOOL KillProcess(DWORD PID);
BOOL CleanReg();
BOOL RepaireFile();
DWORD ScanDirectory(const WCHAR *pwszPath);
DWORD ParseDiskName(TCHAR *pszDiskName);
BOOL SearchFile(TCHAR* szPath);
CString GetDefaultExplore();

int _tmain(int argc, _TCHAR* argv[])
{
	g_hMutex = CreateMutex(NULL, TRUE, g_pMutexName);
	g_DefaultBrowser = GetDefaultExplore();

	if (!g_hMutex){
		printf("未感染病毒\r\n");
	}

	char temp[MAX_PATH];
	GetSystemDirectoryA(temp, MAX_PATH);
	g_cstrSystemDir = temp;
	g_cstrSystemDir.MakeLower();
	GetWindowsDirectoryA(temp, MAX_PATH);
	g_cstrWindowsDir = temp;
	g_cstrWindowsDir.MakeLower();

	TerminateMaliciousProcess();
	DeleteMaliciousFile();
	CleanReg();
	RepaireFile();
	printf("病毒查杀完毕\r\n");
	return 0;
}

BOOL TerminateMaliciousProcess(){
	HANDLE hProcessSnap		= NULL;		// 进程快照句柄
	HANDLE hProcess			= NULL;		// 进程句柄
	PROCESSENTRY32 stcPe32	= { 0 };	// 进程快照信息
	stcPe32.dwSize			= sizeof(PROCESSENTRY32);

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return false;

	// 2. 通过进程快照句柄获取第一个进程信息
	if (!Process32First(hProcessSnap, &stcPe32))
	{
		CloseHandle(hProcessSnap);
		return false;
	}


	do{


		printf("进程路径：%s\r\n", stcPe32.szExeFile);
		CString str_ProcessName = stcPe32.szExeFile;
		str_ProcessName.MakeLower();

		if (str_ProcessName == g_DefaultBrowser || str_ProcessName == "DesktopLayer.exe"){
			printf("结束感染恶意进程%d\r\n", str_ProcessName.GetBuffer(0));
			KillProcess(stcPe32.th32ProcessID);
		}

	} while (Process32Next(hProcessSnap, &stcPe32));
	printf("恶意进程查杀完毕\r\n");
	CloseHandle(hProcessSnap);
	return 0;
}


BOOL KillProcess(DWORD PID){
	//HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE,PID);
	//if (hProcess == NULL){
		printf("结束进程%d\r\n", PID);
		char szCmd[256] = {0};
		sprintf(szCmd,"taskkill /F /PID %d\r\n", PID);
		system(szCmd);
		return 0;
	//}
	//system("pause");
	//return TerminateProcess(hProcess, 0);
}



BOOL DeleteMaliciousFile(){
	for (int i = 0; i < sizeof(DelFileSet)/sizeof(DelFileSet[0]); ++i){
		HANDLE hFile = CreateFile(DelFileSet[i],
			GENERIC_READ | GENERIC_WRITE,
			NULL,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
		CloseHandle(hFile);
		if (hFile != INVALID_HANDLE_VALUE){
			Sleep(100);
			DeleteFile(DelFileSet[i]);
		}
	}
	printf("病毒源程序清除完毕\r\n");
	return 0;
}

#define Size 1024
char g_Value[Size] = { 0 };
DWORD g_ValueSize = Size;
#define WIN_LOGON "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
BOOL CleanReg(){
	HKEY hKey ;
	LONG lRet = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		WIN_LOGON,
		0,
		KEY_ALL_ACCESS,
		&hKey
		);    //打开注册表

	DWORD dwType;
	lRet = RegQueryValueEx(hKey, "Userinit", NULL, &dwType, (LPBYTE)g_Value, &g_ValueSize);
	if (lRet != ERROR_SUCCESS){
		printf("注册表修复完成\r\n");
		return 0;
	}
	
	char * pCheckStr = g_Value + g_ValueSize - 17;
	
	CString cstrDesktoplayer = "desktoplayer.exe";

	if (cstrDesktoplayer == pCheckStr){
		int i;
		for (i = g_ValueSize; g_Value[i] != ','; --i);
		g_Value[i] = '\0';
		
		lRet = RegSetValueEx(hKey, "Userinit", NULL, dwType, (LPBYTE)g_Value, sizeof(g_Value));
		if (lRet == ERROR_SUCCESS){
			printf("%s\\%s注册表修复成功\r\n", WIN_LOGON, "Userinit");
		}
		else{
			printf("注册表修复失败\r\n");
		}
		Sleep(2000);
	}
	printf("注册表修复完成\r\n");
	RegCloseKey(hKey);
	printf("注册表修复关闭\r\n");
	return 0;
}


CString g_cstrScript = "</SCRIPT>";
BOOL RepaireHtml(char * FileName){
	FILE * pf = NULL;

	HANDLE hFile = CreateFile(FileName,
		GENERIC_READ|GENERIC_WRITE,
		NULL,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile <= 0){
		return -1;
	}

	char temp[32] = {0};
	DWORD dwByte = 32;
	SetFilePointer(hFile, -10, NULL, FILE_END);
	ReadFile(hFile, temp,  dwByte, &dwByte, NULL);
	temp[9] = '\0';

	if (temp == g_cstrScript){
		SetFilePointer(hFile, -173539, NULL, FILE_END);
		SetEndOfFile(hFile);
		printf("%s 被感染-修复完成\r\n", FileName);
	}

	CloseHandle(hFile);
	return 0;
}


CString g_cstrSectionName = ".rmnet";
BOOL RepairePe(char * FileName){
	FILE * pf = NULL;

	HANDLE hFile = CreateFile(FileName,
		GENERIC_READ | GENERIC_WRITE,
		NULL,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE){
		printf("%s文件被占用\r\n", FileName);
		//system("pause");
		return 0;
	}


	// 判断文件是否为空

	HANDLE hMap = CreateFileMapping(
		hFile,
		NULL,
		PAGE_READWRITE,
		0,
		0,
		NULL);

	if (hMap == NULL){
		printf("%s文件映射失败, 可能是文件收到系统保护\r\n", FileName);
		CloseHandle(hMap);
		CloseHandle(hFile);
		return 0;
	}

	void* pvFile = MapViewOfFile(
		hMap,
		FILE_MAP_READ | FILE_MAP_WRITE,
		0,
		0,
		0);
	unsigned char *p = (unsigned char*)pvFile;


	IMAGE_DOS_HEADER * pDosHeader = (IMAGE_DOS_HEADER *)p;
	if (pDosHeader->e_magic != 0x5a4d){
		UnmapViewOfFile(pvFile)jjujjj
		CloseHandle(hMap);
		CloseHandle(hFile);
		return 0;
	}

	if (pDosHeader->e_lfanew > GetFileSize(hFile, NULL)){
		UnmapViewOfFile(pvFile);
		CloseHandle(hMap);
		CloseHandle(hFile);
		return 0;
	}

	IMAGE_NT_HEADERS * pNtHeader = (IMAGE_NT_HEADERS *)(p + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != 0x4550 && pNtHeader->FileHeader.Machine != (unsigned short)0x014c){
		UnmapViewOfFile(pvFile);
		CloseHandle(hMap);
		CloseHandle(hFile);
		return 0;
	}


	IMAGE_SECTION_HEADER * pSection = (IMAGE_SECTION_HEADER *)(p + pDosHeader->e_lfanew + pNtHeader->FileHeader.SizeOfOptionalHeader + 0x18);
	for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i){
		if (pSection[i].Name == g_cstrSectionName){
			//int nRmnetoffset = pSection[i].PointerToRawData;
			//int a = pSection[i].VirtualAddress;
			//int b = *(DWORD *)(p + (pSection[i].PointerToRawData + 0x328));
			//pNtHeader->OptionalHeader.AddressOfEntryPoint = a - b;
			//pNtHeader->FileHeader.NumberOfSections--;
			//pNtHeader->OptionalHeader.SizeOfImage = (pNtHeader->OptionalHeader.SizeOfImage - pSection[i].SizeOfRawData);
			//pNtHeader->OptionalHeader.SizeOfImage &= 0xfffff000;
			//ZeroMemory(pSection + i, sizeof(IMAGE_SECTION_HEADER));
			//UnmapViewOfFile(pvFile);
			//CloseHandle(hMap);



			//SetFilePointer(hFile, nRmnetoffset, NULL, FILE_BEGIN);
			//SetEndOfFile(hFile);
			//CloseHandle(hFile);
			printf("%s 被感染-修复成功\r\n", FileName);
			return 0;
		}
	}

	UnmapViewOfFile(pvFile);
	CloseHandle(hMap);
	CloseHandle(hFile);
	return 0;
}



// 节首地址 -  [节偏移328]

BOOL RepaireFile(){
	char szbuf[MAX_PATH] = { 0 };

	GetLogicalDriveStringsA(MAX_PATH, szbuf);
	printf("获取盘符\r\n");
	int nCount = 0;
	char * pDrive = szbuf;
	for (int i = 0; szbuf[i] != 0; i+=4)
	{
		szbuf[i + 2] = '\0';
		printf("%s\r\n", szbuf + i);
		SearchFile(szbuf + i);
	}
	return nCount;

	//RepairePe("OllyMachine.dllv");
	return 0;
}


CString g_cstrHtml = ".html";
CString g_cstrPe = ".exe";
CString g_cstrDll = ".dll";

BOOL SearchFile(TCHAR* szPath)
{
	WIN32_FIND_DATA windata = { 0 };            //文件信息结构
	HANDLE hFile = NULL;
	TCHAR szPathNext[1024];                 //存放下一级目录路径
	ZeroMemory(szPathNext, sizeof(szPathNext));
	sprintf(szPathNext, "%s\\*.*", szPath);     //递归的时候继续深入下一级目录查找文件 
	hFile = FindFirstFile(szPathNext, &windata);//查找第一个文件（夹）
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;
	do
	{
		if (windata.cFileName[0] == '.')         //如果是当前目录或者上级目录，则进入下一次循环
			continue;
		if (windata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) //判断是否是文件夹
		{
			sprintf(szPathNext, "%s\\%s", szPath, windata.cFileName);
			CString strPathNext = szPathNext;
			strPathNext.MakeLower();
			if (strPathNext == g_cstrSystemDir){
				printf("忽略系统目录%s\r\n", szPathNext);
				continue;
			}
			SearchFile(szPathNext); //递归查找
		}
		else
		{
			//printf("扫描路径：%s\\%s\n", szPath, windata.cFileName);//如果是文件则输出文件路径
			TCHAR szFilePath[512] = {0};                 //存放下一级目录路径
			sprintf(szFilePath,"%s\\%s", szPath, windata.cFileName);     //递归的时候继续深入下一级目录查找文件 
			char * p = windata.cFileName;
			char * q = NULL;
			for (;*p;++p){
				if (*p == '.'){
					q = p;
				}
			}

			if (!q){
				continue;
			}

			if (*q){
				CString cstrSub = q;
				cstrSub.MakeLower();
				//printf("检查文件%s\r\n", windata.cFileName);
				if (cstrSub == g_cstrHtml){
					RepaireHtml(szFilePath);
				}
				else if (cstrSub == g_cstrPe){
					RepairePe(szFilePath);
				}
				else if (cstrSub == g_cstrDll){
					RepairePe(szFilePath);
				}
			}
		}
	} while (FindNextFile(hFile, &windata));     //如果深入到最后一层没有文件了则以次退出到上一层目录
	FindClose(hFile);
	return TRUE;
}


CString GetDefaultExplore()
{
	//1拿到默认浏览器名称
	//通过HKEY_CLASSES_ROOT\http\shell\open\command
	DWORD dwType = REG_SZ;
	DWORD dwSize = MAX_PATH;
	char szExplorePath[MAX_PATH] = { 0 };
	CString strRet = _TEXT("");
	TCHAR regname[] = _TEXT("http\\shell\\open\\command");
	HKEY hkResult;
	int nRet = RegOpenKey(HKEY_CLASSES_ROOT, regname, &hkResult);
	if (nRet != ERROR_SUCCESS)
	{
		printf("查询注册表项：http\\shell\\open\\command 失败\r\n");
		return strRet;
	}
	nRet = RegQueryValueEx(hkResult, TEXT(""), NULL, &dwType, (LPBYTE)szExplorePath, &dwSize);
	if (nRet != ERROR_SUCCESS)
	{
		printf("查询注册表项：http\\shell\\open\\command 失败\r\n");
		return strRet;
	}

	//截取第一个和第二个引号中间的内容
	int nFlag = 0;
	int nIndex = 0;
	char* szNew = NULL;
	while (nFlag <= 2)
	{
		if (szExplorePath[nIndex] == '"')
		{
			if (nFlag == 0)
			{
				szNew = szExplorePath + nIndex + 1;
			}
			if (nFlag == 1)
			{
				szNew[nIndex - 1] = '\0';
			}
			nFlag++;
		}
		nIndex++;
	}

	int i;
	for (i = strlen(szNew) - 1; szNew[i] != '\\'; --i);
	return szNew + i + 1;
}