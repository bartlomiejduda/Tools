# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Catwoman (PC)

# Ver    Date        Author
# v0.1   11.10.2020  Bartlomiej Duda


import os
import sys
import struct



def bd_logger(in_str):
    import datetime
    now = datetime.datetime.now()
    print(now.strftime("%d-%m-%Y %H:%M:%S") + " " + in_str)    
    


def export_data(in_file_path, out_folder_path):
    '''
    Function for exporting data from AVL / VOL files
    '''    
    bd_logger("Starting export_data...")    
    
    data_file = open(in_file_path, 'rb')
    
    data_file.read(8)
    
    num_of_files = struct.unpack("<L", data_file.read(4) )[0]
    print("num_of_files: " + str(num_of_files) )
    
    data_file.read(4) #directory size
    
    for i in range(num_of_files):
        data_file.read(12) #entry
        
        
    for i in range(num_of_files):
        #read data
        file_offset = struct.unpack("<L", data_file.read(4) )[0]
        data_file.read(4) #nulls 
        file_size = struct.unpack("<L", data_file.read(4) )[0]
        data_file.read(4) #nulls 
        file_name = data_file.read(8).decode("utf8")
        data_file.read(1) #null
        
        #print("file_off: " + str(file_offset) + " file_size: " + str(file_size) + " file_name: " + str(file_name) )
        
        back_offset = data_file.tell()
        
        #write out files
        data_file.seek(file_offset)
        out_data = data_file.read(file_size)
        out_file_path = out_folder_path + file_name 
        bd_logger(out_file_path)
        out_file = open(out_file_path, 'wb+')
        out_file.write(out_data)
        out_file.close()
        
        
        data_file.seek(back_offset)
  
    
    data_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    
    main_switch = 1
    # 1 - data export 

    if main_switch == 1:
        #p_in_file_path = "C:\\Users\\Arek\\Desktop\\Data\\01.avl"
        #p_out_folder_path = "C:\\Users\\Arek\\Desktop\\Data\\01_avl_out\\"
        
        p_in_file_path = "C:\\Users\\Arek\\Desktop\\Data\\01.vol"
        p_out_folder_path = "C:\\Users\\Arek\\Desktop\\Data\\01_vol_out\\"        
        
        export_data(p_in_file_path, p_out_folder_path)
        
  
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()