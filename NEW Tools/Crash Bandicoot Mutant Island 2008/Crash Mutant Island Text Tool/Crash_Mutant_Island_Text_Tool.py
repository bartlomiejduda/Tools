# -*- coding: utf-8 -*-

# Tested on Python 3.7.3
# This tool should be used with Crash Mutant Island 2008 Java game

# Ver    Date        Name
# v1.0   09.10.2019  Bartlomiej Duda
# v1.1   10.10.2019  Bartlomiej Duda


VERSION_NUM = "v1.1"


import os
import sys
import struct



def open_text():
    print ("Starting Crash Java text load...")
    
    strings_arr = []
    p_input_textfile_path = "C:\\Users\\Adam\\Desktop\\Txts_Pack_nb_0"
    text_file = open(p_input_textfile_path, 'rb')
    output_text_file = open("out.txt", 'wb+')
    
    num_of_bytes_to_skip = struct.unpack('>H', text_file.read(2))[0]
    text_file.read(num_of_bytes_to_skip)
    
    f_count = 0
    s_count = 0
    for j in range(6):
        f_count += 1
        short2_count_start = struct.unpack('>H', text_file.read(2))[0]
        short1_count_end = struct.unpack('>H', text_file.read(2))[0]        
        for i in range(short1_count_end):
            s_count += 1
            curr_offset = text_file.tell()
            string_size = struct.unpack('>H', text_file.read(2))[0]
            text_string = text_file.read(string_size)
            
            text_string = ( text_string
                            .replace(b"\xef\xbf\xbf\xc0\x80", b"<special_str_01>")
                            .replace(b"\xef\xbf\xbf\x03", b"<special_str_03>")
                            .replace(b"\xef\xbf\xbf\x04", b"<special_str_04>")
                            .replace(b"\xef\xbf\xbf\x05", b"<special_str_05>")
                            .replace(b"\xef\xbf\xbf\x06", b"<special_str_06>")
                            .replace(b"\xef\xbf\xbf\x08", b"<special_str_08>")
                            .replace(b"A\xc3\x86\xc3\x82\xc3\x80BC\xc3\x87DE\xc3\x89\xc3\x8a\xc3\x88\xc3\x8bFGHI\xc3\x8e\xc3\x8fJKLMNO\xc5\x92\xc3\x94PQRSTU\xc3\x9b\xc3\x99\xc3\x9c\xc2\xa9\xc2\xae\xe2\x84\xa2\xc3\x80BCDE\xc3\x89\xc3\x88FGHI\xc3\x8cJKLMNO\xc3\x92&lt;&gt;+-,.:()\xc2\xa9\xc2\xae\xe2\x84\xa2\xc3\x84\xc3\x96\xc3\x9c\xc3\x81\xc3\x89\xc3\x8d\xc3\x91\xc3\x93\xc3\x9a", b"<special_str_LONG>")
                            .replace(b"\xc2\xa9", b"<special_str_SHORT>")
                            .replace(b"\n", b"<special_str_new_line>")
                           )
            
            print("f=" + str(f_count) + " s=" + str(s_count) + " i=" + str(i+1) + " string_size = " + str(string_size) + " curr_offset = " + str(curr_offset)  )
            print(text_string)
            output_text_file.write(text_string)
            output_text_file.write(b"\x0D\x0A")
        
    text_file.close()
    output_text_file.close()
    
open_text()