# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Hokuto No Ken (PS2)

# Ver    Date        Author               Comment
# v0.1   11.03.2021  Bartlomiej Duda      -

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


class DIR_ENTRY:
    def __init__(self, in_name, in_offset, in_size):
        self.dir_name = in_name 
        self.dir_offset = in_offset 
        self.dir_size = in_size 
        
    

def export_data(in_idx_file_path, in_bin_file_path, out_folder_path):
    '''
    Function for exporting data from BIN files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    idx_file = open(in_idx_file_path, "rb")
    bin_file = open(in_bin_file_path, "rb")
    
    magic = idx_file.read(4).decode("utf8")
    if magic != "FARC":
        log_msg = "It is not valid FARC archive! Aborting!"
        bd_logger(log_msg)
        raise Exception(log_msg)
    
    idx_file.read(4) # version 
    num_of_dir_entries = struct.unpack("<L", idx_file.read(4))[0]
    idx_file.read(4) # num of file entries?
    
    for i in range(num_of_dir_entries):
        idx_file.read(4) # dir entry offset 
        
    
    idx_file.read(24) # bin archive name 
    
    dir_list = []
    for i in range(num_of_dir_entries):
        dir_name = idx_file.read(4).decode("utf8")
        dir_offset = struct.unpack("<L", idx_file.read(4))[0]
        dir_size = struct.unpack("<L", idx_file.read(4))[0]
        idx_file.read(4) # nulls
        dir_object = DIR_ENTRY(dir_name, dir_offset, dir_size)
        dir_list.append(dir_object)
        
        
    for dir_item in dir_list:
        dir_path = out_folder_path + dir_item.dir_name + "\\"
        
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)         
        
        idx_file.seek(dir_item.dir_offset)
        
        idx_file.read(4) # dir name 
        num_of_file_entries = struct.unpack("<L", idx_file.read(4))[0]
        
        dir_start_offset = struct.unpack("<L", idx_file.read(4))[0]
        idx_file.read(4) # dir size 
        
        for i in range(num_of_file_entries):
            file_path = dir_path + "file" + str(i+1)

            file_offset = struct.unpack("<L", idx_file.read(4))[0]
            file_size = struct.unpack("<L", idx_file.read(4))[0]
            
            bin_file.seek(file_offset)
            
            file_magic = ""
            ext = ".dat"
            try:
                file_magic = bin_file.read(4).decode("utf8")
            except:
                pass
            
            if file_magic == "VAGp":
                ext = ".vag"
            elif file_magic == "FARC":
                ext = ".idx"
            elif file_magic == "PALH":
                ext = ".bin"            
            elif file_magic == "SDRV":
                ext = ".sdrv"                 
                

            bin_file.seek(file_offset)
            file_path += ext
            print(file_path)   
            
            file_data = bin_file.read(file_size)
            
            
            out_file = open(file_path, "wb+")
            out_file.write(file_data)
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
        p_idx_in_file_path = "C:\\Users\\Arek\\Desktop\\HK\\HK_I.IDX"
        p_bin_in_file_path = "C:\\Users\\Arek\\Desktop\\HK\\HK_B.BIN"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\HK\\HK_OUT\\"
        
        export_data(p_idx_in_file_path, p_bin_in_file_path, p_out_folder_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()