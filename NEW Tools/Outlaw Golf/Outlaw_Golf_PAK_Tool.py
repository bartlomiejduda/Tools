# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Outlaw Golf (PC)

# Ver    Date        Author               Comment
# v0.1   02.02.2021  Bartlomiej Duda      -
# v0.2   21.02.2021  Bartlomiej Duda      Finished export function

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
    

def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from PAK files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    pak_file = open(in_file_path, 'rb')
    
    magic = struct.unpack("8s", pak_file.read(8))[0]
    
    if magic != b'PAXFILE\xff':
        bd_logger("It is not valid PAK file from Outlaw Golf! Aborting!")
        return
    
    pak_file.read(20) # unknown 
    
    pak_file.read(4) # data offset
    num_of_directories = struct.unpack("<L", pak_file.read(4))[0]
    num_of_files = struct.unpack("<L", pak_file.read(4))[0]
    align_value = struct.unpack("<L", pak_file.read(4))[0]
    
    pak_file.read(52) # unknown 
    
    
    # read directories info
    dir_name_arr = []
    dir_filenum_arr = []
    for i in range(num_of_directories - 1):
        dir_name = struct.unpack("32s", pak_file.read(32))[0].decode("utf8").rstrip("\x00")
        pak_file.read(8) # unknown 
        
        first_file_num = struct.unpack("<L", pak_file.read(4))[0]
        print(dir_name + " " + str(first_file_num))
        dir_name_arr.append(dir_name)
        dir_filenum_arr.append(first_file_num)
        
        num_of_files_in_directory = struct.unpack("<L", pak_file.read(4))[0]

    
    
    dir_name_arr.reverse()
    dir_filenum_arr.reverse()
    
        
    # read files info loop
    for i in range(num_of_files):
        file_name = struct.unpack("32s", pak_file.read(32))[0].decode("utf8").rstrip("\x00")
        file_offset = struct.unpack("<L", pak_file.read(4))[0]
        file_size = struct.unpack("<L", pak_file.read(4))[0]
        
        back_offset = pak_file.tell()
        
        pak_file.seek(file_offset)
        file_data = pak_file.read(file_size)
        
        
        # find directory for current file
        file_num = i + 1
        dir_count = -1
        file_dir = ""
        for f_file_num in dir_filenum_arr:
            dir_count += 1
            
            if file_num > f_file_num:
                file_dir = dir_name_arr[dir_count] + "\\"
                break
        

        # crete output directories
        out_file_folder = out_folder_path + file_dir
        if not os.path.exists(out_file_folder):
            os.makedirs(out_file_folder)         
        
        
        # write out data
        out_file_path = out_file_folder + file_name
        out_file = open(out_file_path, "wb+")
        out_file.write(file_data)
        out_file.close()
        print(out_file_path)
        
        
        pak_file.seek(back_offset)
        
    
    
    pak_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "E:\\INNE_GRY_TEMP\\OutlawGolf\\golf.PAK"
        p_out_folder_path = "E:\\INNE_GRY_TEMP\\OutlawGolf\\golf.PAK_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()