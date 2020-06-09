# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Harry Potter and the Sorcerer's Stone (PS1)

# Ver    Date        Author
# v0.1   08.06.2020  Bartlomiej Duda
# v0.2   09.06.2020  Bartlomiej Duda



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
        
        #exceptions?
        elif o_ch == 167 or o_ch == 169:
            ch = chr(ord(ch)+74)
        elif o_ch == 132:
            ch = chr(ord(ch)+59)
        elif o_ch == 126:
            ch = chr(ord(ch)+35)
        
        
        #special chars    
        elif o_ch > 128:
            ch = chr(ord(ch)+73)
            
        out_str += ch
    return out_str


def decode_text(in_FILE_path, out_FILE_path):
    '''
    Function for decoding text
    '''    
    bd_logger("Starting decode_text...")    
    
    in_file = open(in_FILE_path, 'rb')
    out_file = open(out_FILE_path, 'wt+', encoding="utf16")
    
    XSPL_begin_offset = 160996
    in_file.seek(XSPL_begin_offset) #TODO    go to XSPL chunk 
    
    
    #header reading
    magic = in_file.read(4)
    chunk_size = struct.unpack('<l', in_file.read(4))[0]
    supp_langs = in_file.read(4)
    num_of_strings = struct.unpack('<l', in_file.read(4))[0] * 4
    unknown = in_file.read(4)
    print("num_of_strings: " + str(num_of_strings) )
    
    
    #setting base offset
    str_base_offset = XSPL_begin_offset + 20 + (num_of_strings * 4)
    real_offset_arr = []
    
    
    #offset table reading
    offset_arr = []
    for i in range(num_of_strings):
        offset = struct.unpack('<l', in_file.read(4))[0]
        offset_arr.append(offset)
        real_offset_arr.append(str_base_offset + offset)
        
    offset_arr.append(offset_arr[-1] + 2)
    
    
    #text reading
    for i in range(num_of_strings):
        str_size = offset_arr[i+1] - offset_arr[i]
        s_str = "BD_TRANSLATE_TEXT=" +       decode_char(    in_file.read(str_size).decode("utf16", errors='replace').replace("\x00", "<NULL>").rstrip("<NULL>")   )
        print( "real_offset: " + str(real_offset_arr[i]) +  " len: " + str(str_size).ljust(3) + " " + str(i+1) + ")" + s_str)
        out_file.write(s_str + "\n") #TODO
    
    
    
    
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