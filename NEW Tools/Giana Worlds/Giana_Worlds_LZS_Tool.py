# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Giana Worlds

# Ver    Date        Author              Comment
# v0.1   30.11.2020  Bartlomiej Duda     Initial Version
# v0.2   30.11.2020  Bartlomiej Duda     Fixed unpacking + added decompression

import os
import sys
import struct
import lzss # pip install lzss


def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    


def get_name(in_file):
    out_name = ""
    while 1:
        ch = struct.unpack("c", in_file.read(1))[0]
        
        if ord(ch) != 0:
            out_name += ch.decode("utf8")
        else:
            break
    return out_name


def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from LZS files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    lzs_file = open(in_file_path, 'rb')
    lzs_file_size = os.path.getsize(in_file_path) 
    
    lzs_file.seek(lzs_file_size-4)
    tail_start_offset = struct.unpack("<L", lzs_file.read(4))[0]
    lzs_file.seek(tail_start_offset)
    
    
    curr_offset = lzs_file.tell()
    file_count = 0
    path_arr = []
    name_arr = []
    offset_arr = []
    comp_size_arr = []
    while curr_offset < lzs_file_size-4:
        file_count += 1
        file_name = get_name(lzs_file)
        file_offset = struct.unpack("<L", lzs_file.read(4))[0]
        file_comp_size = struct.unpack("<L", lzs_file.read(4))[0]
        file_uncomp_size = struct.unpack("<L", lzs_file.read(4))[0]
        lzs_file.read(4)
        file_path = out_folder_path + file_name
        
        curr_offset = lzs_file.tell()
        
        name_arr.append(file_name)
        path_arr.append(file_path)
        offset_arr.append(file_offset)
        comp_size_arr.append(file_comp_size)
        
    
    for i in range(file_count):
        f_path = path_arr[i]
        f_name = name_arr[i]
        
        print(f_path)
        
        lzs_file.seek(offset_arr[i])
        file_data = lzs_file.read(comp_size_arr[i])
        file_data = lzss.decompress(file_data)
        
        out_file = open(f_path, "wb+")
        out_file.write(file_data)
        out_file.close()
   
    
    lzs_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "C:\\INNE_GRY\\Giana Worlds\\data.lzs"
        p_out_folder_path = "C:\\INNE_GRY\\Giana Worlds\\data.lzs_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()