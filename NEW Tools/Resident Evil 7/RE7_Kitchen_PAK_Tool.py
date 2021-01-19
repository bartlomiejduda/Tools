# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Resident Evil 7 KITCHEN demo

# Ver    Date        Author               Comment
# v0.1   19.01.2021  Bartlomiej Duda      -

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
    
    
    magic = struct.unpack("4s", pak_file.read(4))[0].decode("utf8")
    print(magic)
    
    if magic != "KPKA":
        bd_logger("This is not a valid RE 7 KITCHEN demo file!")
        return
    
    pak_file.read(4) # version
    num_of_files = struct.unpack("<L", pak_file.read(4))[0]
    pak_file.read(4) # nulls
    
    
    offset_arr = []
    size_arr = []
    path_arr = []
    for i in range(num_of_files):
        file_offset = struct.unpack("<L", pak_file.read(4))[0]
        pak_file.read(4) # nulls
        file_size = struct.unpack("<L", pak_file.read(4))[0]
        pak_file.read(4) # nulls
        pak_file.read(4) # hash1
        pak_file.read(4) # hash2
        
        offset_arr.append(file_offset)
        size_arr.append(file_size)

        out_file_path = out_folder_path + "file" + str(i+1) + ".bin"
        #bd_logger(out_file_path)
        path_arr.append(out_file_path)
        
        
    for i in range(num_of_files):
        f_offset = offset_arr[i]
        f_size = size_arr[i]
        f_path = path_arr[i]
        
        pak_file.seek(f_offset)
        file_data = pak_file.read(f_size)
        
        bd_logger(f_path)
        
        out_file = open(f_path, "wb+")
        out_file.write(file_data)
        out_file.close()
        

   
    
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
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\re.pak"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\re.pak_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()