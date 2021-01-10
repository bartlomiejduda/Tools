#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <stdint.h>
#include <Memory.h>
#include <stdlib.h>



#pragma warning(disable:4996)

using namespace std;


// Star Stable Online Hook
// Copyright © 2021  Bart³omiej Duda
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





/*DWORD AddressOfFunc = 0;
typedef int(__thiscall* original_func)(void*, const char*); //            // (1)  - CPXFileObject::Load ?
original_func pMemberFunc;
int __fastcall HookFunc(void* pThis, void* edx, const char* p1)
{

	char ch_p1[20];
	sprintf(ch_p1, "%s", p1);

	cout << "BD_HOOK1" <<
		"pThis=" << pThis <<
		" p1=" << ch_p1 <<
		endl;

	//Sleep(5000);

	return pMemberFunc(pThis, p1);
} */




/*DWORD AddressOfFunc = 0;
typedef int(__thiscall* original_func)(void*, const char*, unsigned int); //            // (1)  - CPXBitmap::OpenTarga
original_func pMemberFunc;
int __fastcall HookFunc(void* pThis, void* edx, const char* path, unsigned int dwOpenFlag)
{

	char ch_p1[20];
	sprintf(ch_p1, "%s", path);

	cout << "BD_HOOK1" <<
		"pThis=" << pThis <<
		" path=" << ch_p1 <<
		" open_flag=" << dwOpenFlag <<
		endl;

	//Sleep(5000);

	return pMemberFunc(pThis, path, dwOpenFlag);
}*/



/*DWORD AddressOfFunc = 0;
typedef int(__thiscall* original_func)(void*, const char*, unsigned int); //            // (1)  - CPXBitmap::OpenBitmap
original_func pMemberFunc;
int __fastcall HookFunc(void* pThis, void* edx, const char* path, unsigned int dwOpenFlag)
{

	char ch_p1[20];
	sprintf(ch_p1, "%s", path);

	cout << "BD_HOOK1" <<
		"pThis=" << pThis <<
		" path=" << ch_p1 <<
		" open_flag=" << dwOpenFlag <<
		endl;

	//Sleep(5000);

	return pMemberFunc(pThis, path, dwOpenFlag);
}*/




/*DWORD AddressOfFunc = 0;
typedef int(__thiscall* original_func)(void*, char*);            // (1)  - CPXFileObject::GetFileObjectPath
original_func pMemberFunc;
void __fastcall HookFunc(void* pThis, void* edx, char* path)
{
	char ch_p1[100];
	sprintf(ch_p1, "%s", path);

	cout << "BD_HOOK1" <<
		"pThis=" << pThis <<
		" path=" << ch_p1 <<
		endl;


	//Sleep(5000);

	pMemberFunc(pThis, path);
} */


/*DWORD AddressOfFunc = 0;
typedef void(__thiscall* original_func)(void*, const char*);            // (1)  - CPXPath::operator+=
                                                                        //        It will list all loaded scene files
original_func pMemberFunc;
void __fastcall HookFunc(void* pThis, void* edx, const char* szPath)
{
	char ch_p1[100];
	sprintf(ch_p1, "%s", szPath);

	cout << "BD_HOOK1" <<
		"pThis=" << pThis <<
		" path=" << ch_p1 <<
		endl;


	ofstream out_file("C:\\Users\\Arek\\Desktop\\star_stable_filenames.txt", ios::out | ios::app);
	if (out_file.is_open())
	{
		out_file << "PATH=" << ch_p1 << endl;
		out_file.close();
	}
	else cout << "Unable to open file";



	//Sleep(5000);

	pMemberFunc(pThis, szPath);
}*/



DWORD AddressOfFunc = 0;
int file_count = 0;
typedef char(__thiscall* original_func)(void*, const void*, unsigned int, void**, unsigned int, unsigned int, unsigned int);
                                                                        // (1)  - crnd::crn_unpacker::unpack_level
																		//        
original_func pMemberFunc;
char __fastcall HookFunc(void* pThis, void* edx, const void* pSrc, unsigned int src_size_in_bytes, void** pDst, unsigned int dst_size_in_bytes, unsigned int row_pitch_in_bytes, unsigned int level_index)
{
	//char ch_p1[100];
	//sprintf(ch_p1, "%s", szPath);


	char result = pMemberFunc(pThis, pSrc, src_size_in_bytes, pDst, dst_size_in_bytes, row_pitch_in_bytes, level_index);

	if (src_size_in_bytes > 1500 && src_size_in_bytes < 3000)
	{

		cout << "BD_HOOK1" <<
			"pThis=" << pThis <<
			" pSrc=" << pSrc <<
			" src_size=" << src_size_in_bytes <<
			" pDst=" << pDst <<
			" dst_size=" << dst_size_in_bytes <<
			" pitch=" << row_pitch_in_bytes <<
			" lev_index=" << level_index <<
			endl;


		file_count += 1;
		ofstream out_file("C:\\Users\\Arek\\Desktop\\star_out\\star_stable_data" + std::to_string(file_count) + ".bin", ios::out | ios::app | ios::binary);
	if (out_file.is_open())
	{

		char* out_buffer;

		out_buffer = (char*)malloc(dst_size_in_bytes);
		if (out_buffer == NULL)
		{
			cout << "Malloc error!" << endl;
			exit(1);
		}

		// write marker string to file
		//file_count += 1;
		//std::string marker_str("IKS" + std::to_string(file_count) + "  " + "SIZE: " + std::to_string(dst_size_in_bytes) + "  END");
		//size_t size = marker_str.size();
		//out_file.write(&size, sizeof(size);
		//out_file << marker_str;


		// write binary output to file
		memcpy(out_buffer, pDst, dst_size_in_bytes);
		for (int i = 0; i < dst_size_in_bytes; i++)
		{
			out_file << out_buffer[i];
		}




		out_file.close();
	}
	else cout << "Unable to open file";
	
	}

	
	return result;
}






/*
DWORD AddressOfFunc = 0;
typedef int(*original_func)(const char*, const char*);                   // (1)  - PXStriCmp
															    		 //        Lists strings filename comparsions
original_func pMemberFunc;
int HookFunc(const char* dst, const char* src)
{

	/*char ch_p1[100];
	sprintf(ch_p1, "%s", s1);

	char ch_p2[100];
	sprintf(ch_p2, "%s", s2);
	
	cout << "BD_HOOK1" <<
		"dst=" << dst <<
		" src=" << src <<
		endl; 


	/*ofstream out_file("C:\\Users\\Arek\\Desktop\\star_stable_filenames.txt", ios::out | ios::app);
	if (out_file.is_open())
	{
		out_file << "PATH=" << ch_p1 << endl;
		out_file.close();
	}
	else cout << "Unable to open file";
	


	//Sleep(5000);

	return pMemberFunc(dst, src);
}
*/




DWORD WINAPI MainThread(LPVOID param)
{
	AllocConsole();
	freopen("CONOUT$", "w", stdout);
	cout << "HACK THREAD START" << endl;
	//SigScan Scanner;

	uintptr_t moduleBase = (uintptr_t)GetModuleHandle(NULL);
	cout << "Module Base_dec: " << std::dec << moduleBase << " Module base_hex: " << std::hex << moduleBase << endl;


	// (1)
	//AddressOfFunc = moduleBase + 0x969A0;  //ObjectLoad
	//AddressOfFunc = moduleBase + 0x369280;  //OpenTarga
	//AddressOfFunc = moduleBase + 0x3685C0;  //OpenBitmap
	//AddressOfFunc = moduleBase + 0x96680;   //CPXFileObject::GetFileObjectPath
	//AddressOfFunc = moduleBase + 0x2DD70;   // CPXPath::operator+=
	AddressOfFunc = moduleBase + 0x330F70;    // crnd::crn_unpacker::unpack_level
	//AddressOfFunc = moduleBase + 0x4E4331;     // PXStriCmp
	stolen_bytes_len = 5;  // 5 or 6

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