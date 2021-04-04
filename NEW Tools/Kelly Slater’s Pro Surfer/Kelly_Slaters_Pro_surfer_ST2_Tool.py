# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Kelly Slater’s Pro Surfer (PS2)

# Ver    Date        Author               Comment
# v0.1   03.04.2021  Bartlomiej Duda      -
# v0.2   04.04.2021  Bartlomiej Duda      -

import os
import sys
import struct
import datetime


def bd_logger(in_str):
    '''
    Function for logging debug messages
    '''   
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    


pc_to_ascii = ( 
       '\0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', ' ', '_', ':', '"', '\'',
       'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',  'P',
       'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '(', ')', '[', ']', '<',  '>',
       '=', '+', '-', '*', '/', '%', '&', '|', '!', '#', '$', '?', '.', ',', ';', '\\'
    )

PSTRING_PCHUNK_NUMBER = 4
PSTRING_SHIFT_START = 58
STRING_PCHUNK_LENGTH_BITS = 4
PSTRING_PCHAR_MASK = 0x3f
PSTRING_CACHE_SIZE = 12
PSTRING_PCHUNK_LENGTH = 10
PSTRING_MAX_LENGTH = (PSTRING_PCHUNK_LENGTH * PSTRING_PCHUNK_NUMBER)
PSTRING_MAX_LENGTH_PLUS_ONE = (PSTRING_MAX_LENGTH + 1)
PSTRING_SHIFT_BY = 6

def unpack_pstring(in_packed_str):
    shift = 0
    i = 0
    temp_chr = 0
    output_index = 0
    ret_val = []
    output_cache = [[0 for x in range(PSTRING_MAX_LENGTH_PLUS_ONE)] for y in range(PSTRING_CACHE_SIZE)]
    
    for j in range(PSTRING_PCHUNK_NUMBER):
        shift = PSTRING_SHIFT_START
        b_start = j * 8
        b_end = j * 8 + 8
        
        while shift >= STRING_PCHUNK_LENGTH_BITS:
            temp_chr = ((    int.from_bytes(in_packed_str[b_start:b_end], "little") >> shift) & 0xFF) & (PSTRING_PCHAR_MASK)
            output_cache[output_index][i] = pc_to_ascii[temp_chr]
            if output_cache[output_index][i] == '\0':
                break
            shift -= PSTRING_SHIFT_BY
            i += 1   
                
    output_cache[output_index][i] = '\0'
    ret_val = output_cache[output_index]
  
    output_index += 1
    if output_index >= PSTRING_CACHE_SIZE:
        output_index = 0         
    
    out_str = ""
    for char in ret_val:
        out_str += str(char)
    out_str = out_str.replace("0", "").rstrip("\x00")
    return out_str

def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from ST2 files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(os.path.dirname(out_folder_path)):  
        os.makedirs(os.path.dirname(out_folder_path))     
    
    st2_file = open(in_file_path, 'rb')
    
    index_offset = struct.unpack("<L", st2_file.read(4))[0]
    HEADER_SIZE = 64
    
    sign = 0
    try:
        sign = struct.unpack("<H", st2_file.read(2))[0]
    except:
        pass
    
    if sign != 23294:
        raise Exception("This is not valid ST2 file! Exiting!")
    
    st2_file.read(2) # version 
    num_of_entries = struct.unpack("<L", st2_file.read(4))[0]
    
    st2_file.seek(32)
    temp_data_offset = struct.unpack("<L", st2_file.read(4))[0]
    print(temp_data_offset)
    
    st2_file.seek(index_offset)

    for i in range(num_of_entries):
        encrypted_str = st2_file.read(32)
        file_offset = struct.unpack("<L", st2_file.read(4))[0]
        file_size = struct.unpack("<L", st2_file.read(4))[0]
        file_type = struct.unpack("<B", st2_file.read(1))[0]
        file_flags = struct.unpack("<B", st2_file.read(1))[0]
        st2_file.read(10) # skip some fields
        st2_file.read(12) # skip padding
            
        file_name = unpack_pstring(encrypted_str)
        
        if file_type == 1:
            file_offset = temp_data_offset + file_offset
        else:
            file_offset = file_offset + HEADER_SIZE
        
        back_offset = st2_file.tell()
        
        st2_file.seek(file_offset)
        file_data = st2_file.read(file_size)
        
        file_path = out_folder_path + file_name
        
        print(file_name.ljust(20) + " " + str(file_type) + " " + str(file_flags) + " " + str(file_offset).ljust(7) + " " + str(file_size) )
        
        out_file = open(file_path, "wb+")
        out_file.write(file_data)
        out_file.close()
    
        st2_file.seek(back_offset)
   
    
    st2_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\ANTARCTI.ST2"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\ANTARCTI.ST2_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()