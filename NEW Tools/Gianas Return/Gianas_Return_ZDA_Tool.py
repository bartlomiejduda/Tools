# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Giana's Return 

# Ver    Date        Author             Comment
# v0.1   26.11.2020  Bartlomiej Duda    Initial version
# v0.2   28.11.2020  Bartlomiej Duda    Added decryption method

import os
import sys
import struct
import zlib

from itertools import cycle
def xore(data, key):
    return bytes(a ^ b for a, b in zip(data, cycle(key)))

def decrypt_data(in_data):
    xor_res = b'\xBB'
    data_size = len(in_data)
    out_data = bytearray()
    
    for curr_offset in range(data_size):
        data_byte = struct.pack("B", in_data[curr_offset])
        xor_res = xore(xor_res, data_byte)
        out_data.extend(xor_res)
    
    return out_data
    

def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
  

def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from ZDA files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    zda_file = open(in_file_path, 'rb')
    
    zda_file.read(4)
    num_of_files = struct.unpack("<L", zda_file.read(4))[0]
    zda_file.read(4)
    
    name_arr = []
    size_arr = []
    for i in range(num_of_files):
        f_name = zda_file.read(40).decode("utf-8").rstrip("\x00")
        f_uncomp_size = zda_file.read(4)
        f_comp_size = struct.unpack("<L", zda_file.read(4))[0]
        f_offset = zda_file.read(4)
        
        name_arr.append(f_name)
        size_arr.append(f_comp_size)
        
    for i in range(num_of_files):
        f_data = zlib.decompress(zda_file.read(size_arr[i])) # data decompression
        f_data = decrypt_data(f_data) # data decryption
        f_name = name_arr[i]
        
        f_path = out_folder_path + f_name
        print(f_path)
        
        out_file = open(f_path, "wb+")
        out_file.write(f_data)
        out_file.close()
        
   
    
    zda_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    
    main_switch = 2
    # 1 - data export 
    # 2 - data export (all archives)
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\Gianas Return\\data\\sprites.zda"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\Gianas Return\\data\\sprites.zda_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    elif main_switch == 2:
        p_data_dir_path = "C:\\Users\\Arek\\Desktop\\Gianas Return\\data\\"
        
        for root, dirs, files in os.walk(p_data_dir_path):
            for file in files:
                if file.endswith(".zda"):
                    in_archive = os.path.join(root, file)
                    out_folder = in_archive + "_OUT\\"
                    export_data(in_archive, out_folder)
        
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()