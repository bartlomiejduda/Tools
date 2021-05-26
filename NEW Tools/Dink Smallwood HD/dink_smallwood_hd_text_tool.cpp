#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>

// This product includes software developed by Seth A. Robinson ( www.rtsoft.com )

// Dink Smallwood Text Tool
// Copyright © 2021  Bart³omiej Duda
// License: GPL-3.0 License 


//Changelog:
// VERSION     DATE          AUTHOR             COMMENT
// v0.1        26.05.2021    Bartlomiej Duda    Initial version

#pragma warning(disable:4996)

using namespace std;


std::string ExtractFileName(const std::string& fullPath)
{
  const size_t lastSlashIndex = fullPath.find_last_of("/\\");
  return fullPath.substr(lastSlashIndex + 1);
}


void strchar(char *string, char ch)
/* This acts in the same way as strcat except it combines a string and
a single character, updating the null at the end. */
{
	int last;
	last=strlen(string);
	string[last]=ch;
	string[last+1]=0;
}

void dink_decompress( unsigned char *in, char * destBuf )
{

	const int stackSize = 2*1024;
	unsigned char stack[stackSize], pair[128][2];
	int c, top = 0;
	memset(stack, 0, stackSize);
	memset(pair, 0, 128*2);

	int outputSize = 0;

	c = *in; in++;

	if (c > 127)
	{
		//read optional pair count and pair table
		int readCount = (c-128)*2;
		memcpy(&pair,in, readCount );
		in += readCount;
	}
	else
	{
		if (c == '\r') c = '\n';
		if (c == 9) c = ' ';

		strchar(destBuf,c);
	}

	for (;;)
	{

		/* Pop byte from stack or read byte from file */
		if (top)
			c = stack[--top];
		else
		{
			if ((c = *in) == 0) break;
			in++;
		}
		
		/* Push pair on stack or output byte to file */
		if (c > 127)
		{
			if (top >= stackSize )
			{
				printf("Malformed .d file, can't read it.  Would overwrite random memory on the old Dink versions.");
				printf("Decompressed to %d bytes", outputSize);

				destBuf[outputSize] = 0;
				return;
			}
			stack[top++] = pair[c-128][1];
			stack[top++] = pair[c-128][0];
		}
		else
		{
			if (c == '\r') c = '\n';
			if (c == 9) c = ' ';

			strchar(destBuf,c);
			outputSize++;
			}
	}

	destBuf[outputSize] = 0;

}



int main( int argc, char * argv[] )
{
	if(argc <= 2)
	{
		cout << "Dink Smallwood HD Text Tool" << endl;
		cout << "Usage:" << endl;
		cout << "Decompress --> tool.exe input.d output.txt" << endl;
	}
	else
	{
		char* in_file_path = argv[1];
		char* out_file_path = argv[2];
		
		const char * in_filename = ExtractFileName( (string) in_file_path   ).c_str();
		
	
		unsigned char * inputBuffer;
		char * decompBuffer = new char[102400*128];
	
		ifstream in_file(in_file_path, ios::in | ios::binary);
		if (in_file.is_open())
		{
			in_file.seekg(0, std::ios::end);
			long f_size = in_file.tellg();
			in_file.seekg(0, std::ios::beg);
			
			
			//cout << "f_size: " << f_size << endl;
    		inputBuffer = new unsigned char [f_size];
    		in_file.seekg (0, ios::beg);
    		in_file.read ( (char*)inputBuffer, f_size);
			in_file.close();
		}
		else cout << "Unable to open input file..."; 
		
		
		
		
		dink_decompress(inputBuffer, decompBuffer);
		
		
		
		ofstream out_file(out_file_path, ios::out);
		if (out_file.is_open())
		{
			out_file << decompBuffer;
			out_file.close();
		}
		else cout << "Unable to open output file...";
		
	
		cout << "Finished decompressing " << in_filename << " file..." << endl;
	
	}
		
}




