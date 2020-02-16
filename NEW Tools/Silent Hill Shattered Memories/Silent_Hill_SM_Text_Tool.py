# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Silent Hill: Shattered Memories (PSP)

# Ver    Date        Author
# v0.1   16.02.2020  Bartlomiej Duda
# v0.2   16.02.2020  Bartlomiej Duda

VERSION_NUM = "v0.2"

import os
import sys
import struct

def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    
def decode_char(in_num):
    if int(in_num) < 5:        
        return "<TAG_" + str(in_num) + ">"
    else:
        #return "<UNKNOWN_TAG_" + str(in_num) + ">"
        return str(chr(in_num))
    

def read_SUB(in_sub_filepath):
    bd_logger("Starting read_SUB function...")
    sub_file = open(in_sub_filepath, 'rb') 
    
    ver_num = struct.unpack('<I', sub_file.read(4))[0]
    if ver_num != 2:
        bd_logger("Wrong version number!")
        return
    
    num_of_strings = struct.unpack('<I', sub_file.read(4))[0]
    hash_arr = []
    str_offset_arr = []
    tell_arr = []
    text_arr = []
    
    for i in range(num_of_strings):
        hash_i = struct.unpack('<I', sub_file.read(4))[0]
        offset_i = struct.unpack('<I', sub_file.read(4))[0] * 2
        tell_i = sub_file.tell()
        hash_arr.append(hash_i)
        str_offset_arr.append(offset_i)
        tell_arr.append(tell_i)
    
    
    base_offset = sub_file.tell()
    for i in range(num_of_strings):
        try:
            str1 = ""
            sub_file.seek(base_offset + str_offset_arr[i])
            offset_start = sub_file.tell()
            while(1):
                ch = struct.unpack('<H', sub_file.read(2))[0]
                if ch == 0:
                    break
                else:
                    str1 += decode_char(ch)
            print( str(i+1) + ") " + str1 )  
        except:
            offset_end = sub_file.tell()
            print("End of file! Offset: " + str(offset_end) )
                
        
    print("off_end: " + str( sub_file.tell() ) )
    
    
    sub_file.close()
    bd_logger("Ending read_SUB function...")



#  read SUB 
#p_in_sub_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM\\out_s2\\DATA_47.sub"
p_in_sub_filepath = "C:\\Users\\Arek\\Desktop\\Silent_Hill_SM\\out_s2\\DATA_1323.sub"
read_SUB(p_in_sub_filepath)