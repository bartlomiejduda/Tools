#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <iostream>
using namespace std;


// Note: Original code comes from Xentax forum

// Version   Date         Author               Comments
// v0.1      -            Unknown              probably code decompiled directly from game?
// v0.2      14.11.2020   Bartlomiej Duda      Code rewritten to C++, also I did some refactoring and I have added comments


#pragma warning(disable:4996)
unsigned char stringDecode_buffer[0x100];
char* encryption_key = (char*)"6Ev2GlK1sWoCa5MfQ0pj43DH8Rzi9UnX"; // key_length=32
const unsigned long magichash = 0x0ceb538d;

void initStringDecode();
void decode(char* str, char* decodestr, int* num);
void decode2(char* buffer, char* decodestr, int size);




// INIT FUNCTION STEPS:
// 1. Set index value to 0
// 2. Assign current index value to string decode buffer + position set by encryption key value (for example 'E' = 69)
// 3. Increment index
// 4. Repeat previous steps until end of encryption key (length=32)
void initStringDecode()
{
    cout << "INIT_STRING START" << endl;

    int index = 0;
    memset(stringDecode_buffer, 0, sizeof(stringDecode_buffer));   // fills the buffer with zeroes
    do
    {
        *(stringDecode_buffer + encryption_key[index]) = index;  // assign index to specified position in decode buffer
        ++index;
    } while (index != 32);
}




void decode(char* encoded_data, char* decoded_data, int* decoded_data_size)
{
    cout << "DECODE1 START" << endl;

    int s = 0;
    unsigned char v1;
    unsigned char dectable;
    int index = 0;
    int counter = 0;
    int l = strlen(encoded_data) - 2;    // size of input file - 2
    int buffer_len = l;
    *decoded_data_size = (5 * l >> 3);  
    memset(decoded_data, 0, *decoded_data_size);


    do
    {
        if (l <= counter)
            buffer_len = 0;
        else
            buffer_len = encoded_data[counter + 2];

        dectable = stringDecode_buffer[buffer_len];


        switch (s)
        {
        case 3:
            v1 = 0;
            break;
        case 2:
            v1 = 0;
            dectable = 2 * dectable;
            break;
        case 1:
            v1 = 0;
            dectable = 4 * dectable;
            break;
        case 0:
            v1 = 0;
            dectable = 8 * dectable;
            break;
        case 7:
            v1 = 16 * dectable;
            dectable >>= 4;
            break;
        case 6:
            v1 = 32 * dectable;
            dectable >>= 3;
            break;
        case 5:
            v1 = dectable << 6;
            dectable >>= 2;
            break;
        case 4:
            v1 = dectable << 7;
            dectable >>= 1;
            break;
        default:
            v1 = 0;
            dectable = 0;
            break;
        }

        decoded_data[index] |= dectable;

        if (l - 1 != index)
            decoded_data[index + 1] |= v1;

        if ((unsigned int)(s + 5) <= 7)
            s += 5;
        else
        {
            index++;
            s -= 3;
            if (index == l)
                return;
        }

        counter++;
    } while (l > counter);

    decode2(decoded_data, decoded_data, *decoded_data_size);
}




void decode2(char* buffer, char* decodestr, int size)
{
    cout << "DECODE2 START" << endl;

    int i;
    char b;
    unsigned long m = magichash;
    unsigned int num = 0x12;
    for (i = 0; i < size; i++)
    {
        b = buffer[i];
        m = 0xab * (m % 0xb1) - 2 * (m / 0xb1);
        decodestr[i] = (b ^ num) + m;
        num += 6;
    }
}



void encode(char* decoded_data, char* encoded_data)
{
    cout << "ENCODE START" << endl;

    //TODO

    cout << "ENCODE END" << endl;
}



int main(int argc, char* argv[])
{
    cout << "MAIN START" << endl;

    FILE* input_file = fopen("C:\\Users\\Arek\\Desktop\\bully\\input.xml", "rb");
    FILE* output_file = fopen("C:\\Users\\Arek\\Desktop\\bully\\output.txt", "wb");
    char* p_encoded_data = (char*)malloc(0x1000000);
    char* p_decoded_data = (char*)malloc(0x1000000);
    int p_decoded_data_size = -1;


    // data decode
    initStringDecode();
    memset(p_encoded_data, 0, 0x1000000);
    fread(p_encoded_data, 0x1000000, 1, input_file);
    decode(p_encoded_data, p_decoded_data, &p_decoded_data_size);
    fwrite(p_decoded_data, p_decoded_data_size, 1, output_file);


    // data encode
    // TODO


    cout << "MAIN END" << endl;

    return 0;

}




