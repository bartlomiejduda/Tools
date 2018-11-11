#include <iostream>
#include <fstream>
#include <windows.h>
#include <stdlib.h>

using namespace std;




inline uint16_t endian_swap_16(uint16_t x)
{
    x = (x>>8) | 
        (x<<8);
    return x;
}

inline uint32_t endian_swap_32(uint32_t x)
{
    x = (x>>24) | 
        ((x<<8) & 0x00FF0000) |
        ((x>>8) & 0x0000FF00) |
        (x<<24);
    return x;
}


void wait(int x)
{
	for (int i = x; i > 0; i--)
	{
		//cout << i << " seconds left..." << endl;
		Sleep(1000);
	}
}



int main()
{
	string filename;
	ifstream my_file; 
	uint64_t offset;
	
	
	while(true)
	{
		filename = "example_little_endian.bin";
		my_file.open(filename, ios::in | ios::out | ios::binary);
		
		if (my_file.is_open())
	  {
			uint8_t my_char;
			offset = my_file.tellg();
			cout << "Offset: " << offset << ", Reading CHAR from file " << filename << endl;
			my_file.read ((char*)&my_char, sizeof(my_char));
			cout << "My CHAR is: " << my_char << endl << endl;
			wait(3);
			
		
			uint16_t my_int16;
			offset = my_file.tellg();
			cout << "Offset: " << offset << ", Reading 2 BYTE INT from file " << filename << endl;
			my_file.read ((char*)&my_int16, sizeof(my_int16));
			cout << "My 2 BYTE INT is: " << my_int16 << endl << endl;
			wait(3);
			
			
			uint32_t my_int32;
			offset = my_file.tellg();
			cout << "Offset: " << offset << ", Reading 4 BYTE INT from file " << filename << endl;
			my_file.read ((char*)&my_int32, sizeof(my_int32));
			cout << "My 4 BYTE INT is: " << my_int32 << endl << endl;
			wait(3);
			system("cls");
			
			my_file.close();
	  }
	  
	  else
	  {
	  	cout << "File " << filename << " is not open!" << endl;
	  }
	  
	  
	  filename = "example_big_endian.bin";
	  my_file.open(filename, ios::in | ios::out | ios::binary);
	  
	  	if (my_file.is_open())
	  {
			uint8_t my_char;
			offset = my_file.tellg();
			cout << "Offset: " << offset << ", Reading CHAR from file " << filename << endl;
			my_file.read ((char*)&my_char, sizeof(my_char));
			cout << "My CHAR is: " << my_char << endl << endl;
			wait(3);
			
			
		
			uint16_t my_int16;
			offset = my_file.tellg();
			cout << "Offset: " << offset << ", Reading 2 BYTE INT from file " << filename << endl;
			my_file.read ((char*)&my_int16, sizeof(my_int16));
			cout << "My 2 BYTE INT is: " << endian_swap_16(my_int16) << endl << endl;
			wait(3);
			
			
			uint32_t my_int32;
			offset = my_file.tellg();
			cout << "Offset: " << offset << ", Reading 4 BYTE INT from file " << filename << endl;
			my_file.read ((char*)&my_int32, sizeof(my_int32));
			cout << "My 4 BYTE INT is: " << endian_swap_32(my_int32) << endl << endl;
			wait(3);
			system("cls");
			
			my_file.close();
	  }
	  
	  else
	  {
	  	cout << "File " << filename << " is not open!" << endl;
	  }
	  
	
	}
	

}
