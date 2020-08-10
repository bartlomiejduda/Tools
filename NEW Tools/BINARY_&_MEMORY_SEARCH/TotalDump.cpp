#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <windows.h>
#include <string> 
#include <sstream>
#include <iostream>




// Original author: Gynvael Coldwind (http://re.coldwind.pl/)
// Enhancements: Bartlomiej Duda


using namespace std;

int main(int argc, char **argv)
{
  if(argc != 2)
  {
    puts("usage: totaldump <pid>");
    return 1;
  }

  DWORD Pid;
  if(sscanf(argv[1], "%i", (unsigned int*)&Pid) != 1)
  {
    puts("Pid has to be in hex (0x1234) or dec (1234) form");
    return 2;
  }

  char DumpName[256];
  char DumpName2[256];
  sprintf(DumpName, "pdump_%u.bin", (unsigned int)Pid);
  sprintf(DumpName2, "pdump_%u.txt", (unsigned int)Pid);

  FILE *f;
  FILE *f2;

  f = fopen(DumpName, "wb");
  f2 = fopen(DumpName2, "wt");
  if(!f)
  {
    puts("Could not open dump file!");
    return 4;
  }

  HANDLE Proc = OpenProcess(PROCESS_VM_READ, FALSE, Pid);
  if(Proc == NULL)
  {
    puts("Opening process failed!");
    fclose(f);
    return 3;
  }
  puts("Opening successful!");

  DWORD i, Accessed = 0, Total = 0;
  SIZE_T DataRead;
  for(i = 0; i < 0x80000000; i+= 0x1000, Total++)
  {
    static unsigned char Data[0x1000];
    if(Total % 256 == 0)
      printf("Accessing page %.8x... (Accessed pages / Total Pages: %i / %i)\r", i, Accessed, Total);

    memset(Data, 0, sizeof(Data));
    DataRead = 0;
    if(ReadProcessMemory(Proc, (PVOID)i, Data, sizeof(Data), &DataRead) != 0 && DataRead > 0)
    {
      
      long int file_offset = ftell(f);
      fwrite(Data, 1, sizeof(Data), f);
      Accessed++;
      
      
      string log_text = "mem_address=" + to_string(i) + " file_offset=" + to_string(file_offset) + "\n";
      //cout << log_text;
      fwrite( log_text.c_str(), sizeof( char ), strlen( log_text.c_str() ), f2 );
      
    }
  }

  fclose(f);
  fclose(f2);
  CloseHandle(Proc);
  printf("\nDone!\n");
 

  return 0;
}

