# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Harry Potter and the Sorcerer's Stone (PS1)

# Ver    Date        Author
# v0.1   08.06.2020  Bartlomiej Duda



import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    

def decode_char(in_str):
    out_str = ""
    for ch in in_str:
        o_ch = ord(ch)
        if o_ch > 95 and o_ch < 123:
            ch = chr(ord(ch)+1)
            
        out_str += ch
    return out_str


def decode_text(in_FILE_path, out_FILE_path):
    '''
    Function for decoding text
    '''    
    bd_logger("Starting decode_text...")    
    
    in_file = open(in_FILE_path, 'rb')
    out_file = open(out_FILE_path, 'wt+')
    
    
    in_file.seek(160996) #TODO    go to XSPL chunk 
    
    magic = in_file.read(4)
    chunk_size = struct.unpack('<l', in_file.read(4))[0]
    
    unknowns = in_file.read(12) #TODO 
    
    offset_arr = []
    for i in range(184):
        offset = struct.unpack('<l', in_file.read(4))[0]
        offset_arr.append(offset)
        
    offset_arr.append(chunk_size)
    
    
    for i in range(184):
        str_size = offset_arr[i+1] - offset_arr[i]
        s_str = "BD_TRANSLATE_TEXT=" +       decode_char(    in_file.read(str_size).decode("utf16", errors='replace')   )
        print(s_str)
        #out_file.write(temp_s_str) #TODO
    
    
    
    
    in_file.close()
    out_file.close()
    bd_logger("Ending decode_text...")    
    
    
    
    
    
def main():
    
    main_switch = 1
    # 1 - text decode

    if main_switch == 1:
        in_filepath = "C:\\Users\\Arek\\Desktop\\T1L1M007.WAD"
        out_ini_path = "C:\\Users\\Arek\\Desktop\\T1L1M007.WAD_OUT.ini"
        decode_text(in_filepath, out_ini_path)

    else:
        print("Wrong option selected!")

    bd_logger("End of main...")    
    
    
    
main()