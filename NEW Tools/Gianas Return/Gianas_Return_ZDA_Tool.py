# -*- coding: utf-8 -*-

# Tested on Python 3.8.0
# This tool should be used with Giana's Return 

# Ver    Date        Author
# v0.1   26.11.2020  Bartlomiej Duda

import os
import sys
import struct
import zlib



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
        f_data = zlib.decompress(zda_file.read(size_arr[i]))
        f_name = name_arr[i]
        
        f_path = out_folder_path + f_name
        print(f_path)
        
        out_file = open(f_path, "wb+")
        out_file.write(f_data)
        out_file.close()
        
   
    
    zda_file.close()
    bd_logger("Ending export_data...")    
    
    
    
    
def main():
    
    main_switch = 1
    # 1 - data export 
    

    if main_switch == 1:
        p_in_file_path = "C:\\Users\\Adam\\Desktop\\Gianas Return\\data\\music0.zda"
        p_out_folder_path = "C:\\Users\\Adam\\Desktop\\Gianas Return\\data\\music0.zda_OUT\\"
        export_data(p_in_file_path, p_out_folder_path)
        
    else:
        print("Wrong option selected!")
        
        
    
    bd_logger("End of main...")    
    
    
    
main()