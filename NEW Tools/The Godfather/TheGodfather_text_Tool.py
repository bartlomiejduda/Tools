# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with The Godfather NAM_1.DAT

# Ver    Date        Author               Comment
# v0.1   27.01.2021  Bartlomiej Duda      -

import os
import sys
import struct
import datetime
import binascii


def bd_logger(in_str):
    '''
    Function for logging debug messages
    '''   
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    


def get_string2(in_file):
    out_name = ""
    while 1:
        ch = struct.unpack("c", in_file.read(1))[0]
        
        if ord(ch) != 0:
            try:
                out_name += ch.decode("utf8")
            except:
                temp_hex = hex(ord(ch))  # workaround for invalid characters...
                temp_str = "<" + str(temp_hex) + ">"
                out_name += temp_str
                
        else:
            break
    return out_name


def get_string(in_file):
    out_name = ""
    b_out_name = b''
    file_size = os.path.getsize(in_file.name)
    while 1:  
        curr_offset = in_file.tell() 
        if curr_offset == file_size:  # EOF reached, aborting
            break
        
        ch = struct.unpack("c", in_file.read(1))[0]
        
        if ord(ch) != 0:
            b_out_name += ch  
        else:
            break
        
    out_name = b_out_name.decode("utf8")
    return out_name        
    

def export_text(in_file_path, out_folder_path):
    '''
    Function for exporting text from DAT files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    dat_file = open(in_file_path, 'rb')
    out_file = open(out_folder_path + "text_output.txt", "wt+", encoding="utf8")
    
    
    pointer_arr_offset = 36308  # These values are hardcoded 
    num_of_entries = 6324       # for decompressed NAM_1.DAT from The Godfather
    
    dat_file.seek(pointer_arr_offset)
    
    sep = "|"
    
    out_file.write("ID" + sep + "POINTER OFFSET" + sep + "TEXT OFFSET" + sep + "TEXT\n")
    
    for i in range(num_of_entries):
        
        pointer_offset = dat_file.tell()
        text_offset = struct.unpack("<L", dat_file.read(4))[0]
        back_offset = dat_file.tell()
        dat_file.seek(text_offset)
        
        out_text = get_string(dat_file)
        out_line = str(i+1) + sep + str(pointer_offset) + sep + str(text_offset) + sep + out_text
        print(out_line)
        out_file.write(out_line + "\n")
        dat_file.seek(back_offset)
   
    out_file.close()
    dat_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - text export 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\NAM\\NAM_1.decompressed"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\NAM\\NAM_1.decompressed_OUT\\"
        export_text(p_in_file_path, p_out_folder_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()