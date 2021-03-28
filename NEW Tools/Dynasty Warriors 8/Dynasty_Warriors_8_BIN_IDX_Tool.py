# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Dynasty Warriors 8

# Ver    Date        Author               Comment
# v0.1   28.03.2021  Bartlomiej Duda      -

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
   

def export_data(bin_in_file_path, idx_in_file_path, out_folder_path):
    '''
    Function for exporting data from BIN files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    bin_file = open(bin_in_file_path, "rb")
    
    idx_file = open(idx_in_file_path, "rb")
    
    idx_size = os.path.getsize(idx_in_file_path)
    num_of_idx_entries = int(idx_size / 32)
    
    f_count = 0
    for i in range(num_of_idx_entries):
        section_start = struct.unpack("<Q", idx_file.read(8))[0]
        uncomp_size = struct.unpack("<Q", idx_file.read(8))[0]
        comp_size = struct.unpack("<Q", idx_file.read(8))[0]
        comp_flag = struct.unpack("<Q", idx_file.read(8))[0]
        
        if comp_size != 0:
            f_count += 1
            bin_file.seek(section_start)
            f_data = bin_file.read(comp_size)
            
            ext = ""
            if comp_flag == 1:
                ext = ".comp"
            else:
                ext = ".dat"
                
            f_path = out_folder_path + "file" + str(f_count) + ext 
            print(f_path)
            out_file = open(f_path, "wb+")
            out_file.write(f_data)
            out_file.close()
   
    idx_file.close()
    bin_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_bin_in_file_path = "C:\\Users\\Arek\\Desktop\\DW8E idx&bin\\LINKDATA0.BIN"
        p_idx_in_file_path = "C:\\Users\\Arek\\Desktop\\DW8E idx&bin\\LINKDATA.IDX"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\DW8E idx&bin\\LINKDATA0.BIN_OUT\\"
        export_data(p_bin_in_file_path, p_idx_in_file_path, p_out_folder_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()