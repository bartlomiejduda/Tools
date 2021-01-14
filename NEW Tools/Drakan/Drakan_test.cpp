#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <iostream>
using namespace std;


// Version   Date         Author               Comments
// v0.1      -            Zalasus, UCyborg     Original decode function from https://github.com/Zalasus/opendrakan
// v0.2      14.01.2021   Bartlomiej Duda      Some improvements


#pragma warning(disable:4996)
#pragma warning(disable:6387)


void decode(char* encoded_data, int data_size)
{
    cout << "DECODE START" << endl;


	uint32_t key = 0x5FDD390D;

	for(size_t i = 0; i < data_size; ++i)
	{
		encoded_data[i] ^= key & 0xFF;
		key = (key<<3) | (key>>(32-3));
	}
    
	
	cout << "DECODE END" << endl;

}


int main(int argc, char* argv[])
{
	cout << "MAIN START" << endl;
    char* p_encoded_data = (char*)malloc(0x1000000);

    
    FILE* input_file = fopen("C:\\Users\\Arek\\Desktop\\DRAKAN\\Dragon.rrc_OUT\\input_file.txt", "rb");
    FILE* output_file = fopen("C:\\Users\\Arek\\Desktop\\DRAKAN\\Dragon.rrc_OUT\\output_file.txt", "wb");
	
	
	//get file size
	fseek(input_file, 0L, SEEK_END);
	int p_data_size = ftell(input_file);
	fseek(input_file, 0L, SEEK_SET);
	

    // data decode
    memset(p_encoded_data, 0, 0x1000000);
    fread(p_encoded_data, 0x1000000, 1, input_file);
    decode(p_encoded_data, p_data_size);
    fwrite(p_encoded_data, p_data_size, 1, output_file);




    cout << "MAIN END" << endl;

    return 0;

}




