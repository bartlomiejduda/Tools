#include <Windows.h>
#include <iostream>
#include <fstream>
// #include "sigscan.h"
#include <string>
#include <stdint.h>
#include <Memory.h>
#include <stdlib.h>


#pragma warning(disable:4996)

using namespace std;


// <GAME_NAME> Hook
// Copyright © 2021  Bartłomiej Duda
// License: GPL-3.0 License 


//Changelog:
// VERSION     DATE          AUTHOR             COMMENT
// v0.1        06.01.2021    Bartlomiej Duda    -


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






/*    THISCALL / FASTCALL  HOOK TEMPLATE
DWORD AddressOfFunc = 0;
typedef void(__thiscall* original_func)(void*, int);               // (1)
                                                                   //
original_func pMemberFunc;
void __fastcall HookFunc(void* pThis, void* edx, int p1)
{
	cout << "BD_HOOK1" <<
		    "pThis=" << pThis <<
		    "p1=" << p1 <<
		endl; 

	pMemberFunc(pThis, p1);
}
*/


/*    CDECL HOOK TEMPLATE
DWORD AddressOfFunc = 0;
typedef int(*original_func)(const char*, const char*);                   // (1)  
															    		 //       
original_func pMemberFunc;
int HookFunc(const char* dst, const char* src)
{
	
	cout << "BD_HOOK1" <<
		"dst=" << dst <<
		" src=" << src <<
		endl; 

	return pMemberFunc(dst, src);
}
*/


/*   WRITE TEXT DATA TO FILE TEMPLATE
	ofstream out_file("C:\\Users\\Arek\\Desktop\\star_stable_filenames.txt", ios::out | ios::app);
	if (out_file.is_open())
	{
		out_file << "PATH=" << ch_p1 << endl;
		out_file.close();
	}
	else cout << "Unable to open file";
*/



/*   WRITE BINARY DATA TO FILE TEMPLATE
ofstream out_file("C:\\Users\\Arek\\Desktop\\star_stable_data1.bin", ios::out | ios::app | ios::binary);
	if (out_file.is_open())
	{

		char* out_buffer;

		out_buffer = (char*)malloc(src_size_in_bytes);
		if (out_buffer == NULL)
		{
			cout << "Malloc error!" << endl;
			exit(1);
		}

		// write marker string to file
		file_count += 1;
		std::string marker_str("IKS" + std::to_string(file_count) + "  " + "SIZE: " + std::to_string(src_size_in_bytes) + "  END");
		//size_t size = marker_str.size();
		//out_file.write(&size, sizeof(size);
		out_file << marker_str;


		// write binary output to file
		memcpy(out_buffer, pSrc, src_size_in_bytes);
		for (int i = 0; i < src_size_in_bytes; i++)
		{
			out_file << out_buffer[i];
		}

		


		out_file.close();
	}
	else cout << "Unable to open file";
	*/





DWORD AddressOfFunc = 0;
typedef HANDLE(*original_func)(char*, int, DWORD); //            // (1)   
original_func pMemberFunc;
HANDLE HookFunc(char* p1, int p2, DWORD p3)
{
	/*cout << "BD_HOOK1" <<
			"p1=" << p1 <<
		endl;  */



	return pMemberFunc(p1, p2, p3);
}






DWORD AddressOfFunc2 = 0;
typedef unsigned int(*original_func2)(char*); //            // (2)    
original_func2 pMemberFunc2;
unsigned int HookFunc2(char* p1)
{
	unsigned int ret_hash = pMemberFunc2(p1);


	char hex_string[20];
	sprintf(hex_string, "%X", ret_hash);

	cout << "BD_HOOK2" <<
		"p1=" << p1 << "\tret_hash_DEC=" << ret_hash << "\tret_hash_HEX=" << hex_string << 
		endl;




	return ret_hash;
}






DWORD WINAPI MainThread(LPVOID param)
{
	AllocConsole();
	freopen("CONOUT$", "w", stdout);
	cout << "HACK THREAD START" << endl;
	//SigScan Scanner;

	uintptr_t moduleBase = (uintptr_t)GetModuleHandle(NULL);
	cout << "Module Base_dec: " << std::dec << moduleBase << " Module base_hex: " << std::hex << moduleBase << endl;








	// (1)
	AddressOfFunc = moduleBase + 0x683f0;
	stolen_bytes_len = 6;

	//cout << "Address_dec: " << std::dec << AddressOfFunc << " Address_hex: " << std::hex << AddressOfFunc << endl;
	pMemberFunc = (original_func)AddressOfFunc;
	cout << "1) BEFORE TrampHook32 call..." << endl;
	pMemberFunc = (original_func)TrampHook32((char*)pMemberFunc, (char*)HookFunc, stolen_bytes_len);
	cout << "1) AFTER TrampHook32 call..." << endl;





	// (2)
	AddressOfFunc2 = moduleBase + 0x80630;
	stolen_bytes_len = 6;

	pMemberFunc2 = (original_func2)AddressOfFunc2;
	cout << "2) BEFORE TrampHook32 call..." << endl;
	pMemberFunc2 = (original_func2)TrampHook32((char*)pMemberFunc2, (char*)HookFunc2, stolen_bytes_len);
	cout << "2) AFTER TrampHook32 call..." << endl;
	




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