# -*- coding: utf-8 -*-

'''
Copyright © 2021  Bartłomiej Duda
License: GPL-3.0 License 
'''


# Program tested on Python 3.7.0
# It should be used with Yulgang 2

# Ver    Date        Author               Comment
# v0.1   28.01.2021  Bartlomiej Duda      -

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
    

def export_data(thd_in_file_path, tdt_in_file_path, out_folder_path):
    '''
    Function for exporting data from THD/TDT files
    '''    
    bd_logger("Starting export_data...")  
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    thd_file = open(thd_in_file_path, 'rb')
    tdt_file = open(tdt_in_file_path, 'rb')
    
    magic = struct.unpack("4s", thd_file.read(4))[0].decode("utf8")
    if magic != "YG2!":
        bd_logger("This is not valid THD file!")
        return
    
    
    thd_file.read(28) # skip header 
    
    num_of_entries = struct.unpack("<L", thd_file.read(4))[0]
    
    for i in range(num_of_entries):
        thd_file.read(4) # skip entries
        
    num_of_entries = struct.unpack("<L", thd_file.read(4))[0]
    
    file_offset_arr = []
    for i in range(num_of_entries):
        entry_ID = struct.unpack("<L", thd_file.read(4))[0]
        file_offset = struct.unpack("<L", thd_file.read(4))[0]
        file_offset_arr.append(file_offset)
        

    tdt_file_size = os.path.getsize(tdt_in_file_path)
    file_offset_arr.append(tdt_file_size)
    
    for i in range(num_of_entries):
        f_size = file_offset_arr[i+1] - file_offset_arr[i]
        f_offset = file_offset_arr[i]
        
        tdt_file.seek(f_offset)
        f_data = tdt_file.read(f_size)
        
        out_file_name = out_folder_path + "file" + str(i+1) + ".bin"
        print(out_file_name)
        
        out_file = open(out_file_name, "wb+")
        out_file.write(f_data)
        out_file.close()
    
   
    
    thd_file.close()
    tdt_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    '''
    Main function of this program. If you are planning to use it,
    you should adjust paths first.
    '''   
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_thd_in_file_path = "C:\\Users\\Arek\\Desktop\\THD\\tb_item.thd"
        p_tdt_in_file_path = "C:\\Users\\Arek\\Desktop\\THD\\tb_item.tdt"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\THD\\tb_item_OUT\\"
        export_data(p_thd_in_file_path, p_tdt_in_file_path, p_out_folder_path)
        
    else:
        bd_logger("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()