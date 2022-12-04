#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <stdint.h>
#include <Memory.h>
#include <stdlib.h>
#include <stdio.h>


#pragma warning(disable:4996)

using namespace std;


// Obscure 2 Hook
// Copyright © 2022  Bart³omiej Duda
// License: GPL-3.0 License 


// Changelog:
// VERSION     DATE          AUTHOR             COMMENT
// v0.1        04.12.2022    Bartlomiej Duda    -


int stolen_bytes_len = 0;


bool Detour32(void* src, void* dst, int len)
{
	if (len < 5) return false;
	DWORD curProtection;
	VirtualProtect(src, len, PAGE_EXECUTE_READWRITE, &curProtection);
	memset(src, 0x90, len);
	uintptr_t relativeAddress = ((uintptr_t)dst - (uintptr_t)src) - 5;
	*(BYTE*)src = 0xE9;
	*(uintptr_t*)((uintptr_t)src + 1) = relativeAddress;
	DWORD temp;
	VirtualProtect(src, len, curProtection, &temp);
	return true;
}


char* TrampHook32(char* src, char* dst, const intptr_t len)
{
	if (len < 5) return 0;
	void* gateway = VirtualAlloc(0, len + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(gateway, src, len);
	intptr_t  gatewayRelativeAddr = ((intptr_t)src - (intptr_t)gateway) - 5;
	*(char*)((intptr_t)gateway + len) = 0xE9;
	*(intptr_t*)((intptr_t)gateway + len + 1) = gatewayRelativeAddr;
	Detour32(src, dst, len);
	return (char*)gateway;
}






DWORD AddressOfFunc = 0;
typedef unsigned int(*original_func)(char*, int);
original_func pMemberFunc;
unsigned int HookFunc(char* p1, int p2)
{
	unsigned int ret_hash = pMemberFunc(p1, p2);


	char hex_string[20];
	sprintf(hex_string, "%X", ret_hash);

	std::cout << "CRC_HASH=" << std::hex << hex_string << "\tSTR_LEN=" << std::dec << p2 << "\tSTR_OUT=" << p1 << endl;



	ofstream out_file("C:\\Users\\Arek\\Desktop\\obscure_2_hash_dump.txt", ios::out | ios::app);  // change this to your path!
	if (out_file.is_open())
	{
		out_file << "CRC_HASH=" << std::hex << hex_string << "\tSTR_LEN=" << std::dec << p2 << "\tSTR_OUT=" << p1 << endl;
		out_file.close();
	}
	else cout << "Unable to open file";



	return ret_hash;
}




DWORD WINAPI MainThread(LPVOID param)
{
	AllocConsole();
	freopen("CONOUT$", "w", stdout);
	cout << "HACK THREAD START" << endl;

	uintptr_t moduleBase = (uintptr_t)GetModuleHandle(NULL);
	cout << "Module Base_dec: " << std::dec << moduleBase << " Module base_hex: " << std::hex << moduleBase << endl;



	AddressOfFunc = moduleBase + 0x194510;
	stolen_bytes_len = 6;

	pMemberFunc = (original_func)AddressOfFunc;
	cout << "1) BEFORE TrampHook32 call..." << endl;
	pMemberFunc = (original_func)TrampHook32((char*)pMemberFunc, (char*)HookFunc, stolen_bytes_len);
	cout << "1) AFTER TrampHook32 call..." << endl;




	cout << "HACK THREAD END" << endl;
	return 0;
}



BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(0, 0, MainThread, hModule, 0, 0);
		break;
	default:
		break;
	}
	return TRUE;
}