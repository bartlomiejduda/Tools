# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Giana Sisters : Twisted Dreams - Owltimate Edition

# Ver    Date        Author
# v0.1   21.11.2020  Bartlomiej Duda

import os
import sys
import struct
import gzip



def bd_logger(in_str):
    import datetime
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
    pak_file.read(16)
    num_of_files = struct.unpack("<L", pak_file.read(4))[0]
    
    # getting offsets
    offset_arr = []
    for i in range(num_of_files):
        offset = struct.unpack("<L", pak_file.read(4))[0]
        offset_arr.append(offset)
        pak_file.read(4)
        
    pak_size = os.path.getsize(in_file_path)
    offset_arr.append(pak_size)
    

    # getting sizes
    size_arr = []
    size_count = 0
    for i in range(num_of_files):
        file_size = offset_arr[i+1] - offset_arr[i]
        size_arr.append(file_size)
        size_count += file_size
        
        
        
    #removing out file if it exists
    out_file_path = out_folder_path + "sbpack1.bin"
    print(out_file_path)
    if os.path.exists(out_file_path):
        os.remove(out_file_path)    
        
    for i in range(num_of_files):
        out_file_data = pak_file.read(size_arr[i])
        
        #decompress data 
        out_data_decompressed = gzip.decompress(out_file_data)
        
        # writing output file 
        out_file = open(out_file_path, "ab+")
        out_file.write(out_data_decompressed)
        out_file.close()
        

    pak_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\PAK\\animations.pak"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\PAK\\animations.pak_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()