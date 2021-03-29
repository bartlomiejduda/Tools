# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with My Riding Stables 2

# Ver    Date        Author               Comment
# v0.1   29.03.2021  Bartlomiej Duda      -

import os
import sys
import struct
import datetime
import zlib


def bd_logger(in_str):
    '''
    Function for logging debug messages
    '''   
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    

def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from DAT files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(os.path.dirname(out_folder_path)):  
        os.makedirs(os.path.dirname(out_folder_path))         
    
    dat_file = open(in_file_path, 'rb')
    
    dat_file.seek(32) # skip magic 
    num_of_entries = struct.unpack("<L", dat_file.read(4))[0]
    dat_file.seek(64) # go to entries
    
    for i in range(num_of_entries):
        file_path = dat_file.read(104).decode("utf8").rstrip("\x00")
        
        file_offset = struct.unpack("<L", dat_file.read(4))[0]
        comp_file_size = struct.unpack("<L", dat_file.read(4))[0]
        comp_flag = struct.unpack("<L", dat_file.read(4))[0]
        dat_file.read(4) # nulls 
        uncomp_file_size = struct.unpack("<L", dat_file.read(4))[0]
        dat_file.read(4) # nulls 
        print(file_path + " " + str(comp_file_size) + " " + str(uncomp_file_size) + " " + str(comp_flag))
        
        back_offset = dat_file.tell()
        
        
        dat_file.seek(file_offset)
        file_data = dat_file.read(comp_file_size)
        
        if comp_flag == 1:
            file_data = zlib.decompress(file_data)
        
        out_path = out_folder_path + file_path
        #print(out_path)
        
        if not os.path.exists(os.path.dirname(out_path)):  
            os.makedirs(os.path.dirname(out_path)) 
            
        out_file = open(out_path, "wb+")
        out_file.write(file_data)
        out_file.close()
        
        
        
        dat_file.seek(back_offset)
        
   
    
    dat_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\horse.dat"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\horse.dat_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()