# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Minority Report - Everybody Runs (Xbox) *.XSD/*.XSH

# Ver    Date        Author
# v0.1   22.10.2020  Bartlomiej Duda

import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    
def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from *.XSD/*.XSH files
    '''    
    bd_logger("Starting export_data...")    
    
    head_file = open(in_file_path, 'rb')
    
    data_file_path = in_file_path[0:-3] + "XSD"
    data_file = open(data_file_path, 'rb')
    
    head_file.seek(8)
    num_of_files = struct.unpack("<L", head_file.read(4))[0]
    
    if not os.path.exists(out_folder_path):
        os.makedirs(out_folder_path)      
    
    total_size = 0
    for i in range(num_of_files):
        file_name = head_file.read(32).decode("utf8").split("\x00")[0]
        head_file.read(4)
        file_offset = struct.unpack("<L", head_file.read(4))[0]
        file_size = struct.unpack("<H", head_file.read(2))[0]
        head_file.read(2)
        head_file.read(56)
        total_size += file_size
        
        data_file.seek(file_offset)
        data = data_file.read(file_size)
        
        out_path = out_folder_path + file_name + ".bin"
        bd_logger(out_path)
        out_file = open(out_path, "wb+")
        out_file.write(data)
        out_file.close()
        
        #print("file_name: " + file_name + "\t file_off: " + str(file_offset) + "\t file_size: " + str(file_size) + "\tsummm: " + str(total_size))
        
    
    data_file.close()
    head_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    
    main_switch = 1

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\xbox archives\\L07_SR.XSH"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\xbox archives\\L07_SR.XSH_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
  
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()