#pragma once
#pragma warning(disable: 4267) //size_t to int conversion warning

#include <string>


//Disney's Hercules PC
inline unsigned long calculate_hercules_hash(char* s)
{
	unsigned long hash, i;
	hash = 0;
	for (i = 0; i < strlen(s); i++)
	{
		hash += toupper(s[i]) << ((i * 8) % 32);
	}
	hash += strlen(s);
	return(hash);
}


//Silent Hill Shattered Memories PSP ARC archive
inline unsigned long calculate_silent_hill_arc_hash(char* s)
{
	unsigned long hash, i;
	hash = 0;
	for (i = 0; i < strlen(s); i++)
	{
		hash *= 33;
		hash ^= s[i];
	}
	return(hash);
}

